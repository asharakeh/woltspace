#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
exec 3>&1 >/dev/null 2>&1
root=$(mktemp -d)
run_id=${root##*.}
name=telegram-broker-${run_id,,}
base=$name:base
image=$name:fixture
route_off=$name:route-off
committed=$name:committed
net=$name-net
provider=$name-provider
source_volume=$name-source
volumes=("$source_volume" "$name-post" "$name-pre")
policy=/var/lib/woltspace-secrets
export HOME="$root/home" WOLTSPACE_WOLTS_DIR="$root/lodge" WOLTSPACE_LOCAL=true WOLTSPACE_NODE_SUDO=false
pid= container= owned= phase=setup line=1
trap 'line=$LINENO' ERR
cleanup() {
    local status=$? failed=0 volume
    trap - EXIT
    trap '' INT TERM
    if [[ $owned ]]; then
        for target in "$name" "$provider"; do
            if docker container inspect "$target"; then docker rm -f "$target" || failed=1; fi
        done
        for volume in "${volumes[@]}"; do
            if docker volume inspect "$volume"; then docker volume rm "$volume" || failed=1; fi
        done
        if docker network inspect "$net"; then docker network rm "$net" || failed=1; fi
        for target in "$committed" "$route_off" "$image" "$base"; do
            if docker image inspect "$target"; then docker image rm "$target" || failed=1; fi
        done
    fi
    if [[ $pid ]]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" || :
    fi
    rm -rf -- "$root" || failed=1
    if (( failed )); then phase=cleanup; status=1; fi
    if (( status )); then printf '::error::broker-smoke phase=%s line=%s\n' "$phase" "$line" >&3
    else printf 'PASS cleanup\n' >&3; fi
    exit "$status"
}
trap cleanup EXIT
trap 'line=$LINENO; exit 1' INT TERM
for target in "$name" "$provider"; do
    if docker container inspect "$target"; then exit 1; fi
done
for target in "$committed" "$route_off" "$image" "$base"; do
    if docker image inspect "$target"; then exit 1; fi
done
for volume in "${volumes[@]}"; do
    if docker volume inspect "$volume"; then exit 1; fi
done
if docker network inspect "$net"; then exit 1; fi
owned=1
mkdir -p "$HOME" "$WOLTSPACE_WOLTS_DIR/.claude" "$root/build" "$root/ledger" "$root/certs"
printf 'WOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
# Synthetic only: a fresh random bot token that lives in this shell and on stdin, never in argv or a file.
secret=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
token="123456:$secret"
digest=$(printf '123456:42' | sha256sum | cut -c1-32)
printf '%s 42\n' "$(printf '%s' "$token" | sha256sum | cut -d' ' -f1)" >"$root/ledger/expect"
chmod 755 "$root/ledger"
phase=image
WOLTSPACE_IMAGE="$base" ./woltspace build --local
bash test/telegram-broker-fixture/certs.sh "$root/certs"
chmod 755 "$root/certs"
chmod 644 "$root/certs/"*
cp test/telegram-broker-fixture/{provider,worker}.py "$root/certs/ca.pem" "$root/build/"
chmod 0644 "$root/build/worker.py"  # the shared-node probe must be able to start
printf 'FROM %s\n' "$base" >"$root/build/Dockerfile"
cat >>"$root/build/Dockerfile" <<'DOCKER'
COPY provider.py worker.py ca.pem /opt/fixture/
RUN set -e; cat /opt/fixture/ca.pem >>/etc/ssl/certs/ca-certificates.crt; \
    printf 'dummy\ntelegram\n' >/etc/woltspace/broker-dummy
DOCKER
docker build --network none --tag "$image" "$root/build"
printf 'FROM %s\nRUN printf "dummy\\n" >/etc/woltspace/broker-dummy\n' "$image" >"$root/build/Dockerfile"
docker build --network none --tag "$route_off" "$root/build"
docker network create --internal "$net"
docker run -d --name "$provider" --network "$net" --network-alias api.telegram.org -u 0 \
    -v "$root/ledger:/fixture" -v "$root/certs:/certs:ro" --entrypoint /opt/woltspace/tools/woltspace/bin/python \
    "$image" -I /opt/fixture/provider.py
inside() { docker exec -u 0 "$container" "$@"; }
py() { inside /opt/woltspace/tools/woltspace/bin/python -I "$@"; }
probe() { py /opt/fixture/worker.py "$@"; }
audit_result() {
    python3 -c 'import json,sys; [state] = [row[-1] for row in json.load(sys.stdin) if row[2]==sys.argv[1]]; print(state)' "$1"
}
admin() { py -m woltspace.dummy_broker admin "$@"; }
json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
ok() { [[ $(admin "$@" | json_field result) == ok ]]; }
provision() {  # through the shipping host wrapper, which keeps stdin open only for provision
    printf '42\n%s\n' "$token" | WOLTSPACE_CONTAINER="$name" ./woltspace secrets provision telegram.notice | json_field result
}
ready() { [[ $(provision) == ok ]]; ok grant alpha dummy.ping; ok grant alpha telegram.notice; }
wait_until() {
    local limit=$((SECONDS + 30))
    until "$@"; do (( SECONDS < limit )) || return 1; sleep .15; done
}
health() { docker exec -u node "$container" curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:7777/health; }
boot() {
    local isolation=$1 volume=${2:-} startup_image=${3:-$image}
    local -a mounts=()
    if [[ $volume ]]; then mounts=(-v "$volume:$policy"); fi
    container=$(docker create --name "$name" --network "$net" --security-opt no-new-privileges \
        -e WOLTSPACE_FEATURE_ISOLATION="$isolation" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "${mounts[@]}" -v "$WOLTSPACE_WOLTS_DIR:/workspace/wolts" "$startup_image")
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container") == "$net" ]]
    docker start "$container"
    wait_until health
}
retire() {
    local expected=$1
    [[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$container") == "exited $expected" ]]
    docker rm "$container"
    [[ -z $(docker ps -aq --no-trunc --filter "id=$container") ]]
    container=
}
stop() { docker stop --time 15 "$container"; retire 0; }
archive() {
    [[ -z $container ]]
    volume_tar "$1:$policy:ro" --numeric-owner -C "$policy" -cpf - . >"$2"
    [[ -s $2 && $(stat -c %a "$2") == 600 ]]
}
restore() {
    [[ -z $container && $(docker volume create "$1") == "$1" ]]
    volume_tar "$1:$policy" --numeric-owner --same-owner --same-permissions -C "$policy" -xpf - <"$2"
}
volume_tar() {
    local mount=$1
    shift
    docker run --rm -i --name "$name" --network none -v "$mount" --entrypoint tar "$image" "$@"
}
# Members holding the control, then members holding any slice of the secret: "N 0" with N > 0.
clean_of_token() { [[ $(python3 test/telegram-broker-fixture/scan.py "$1" "$2" <<<"$secret") =~ ^[1-9][0-9]*\ 0$ ]]; }
ledger() { [[ $(paste -sd, "$root/ledger/accepts") == "$1" ]]; }
mode() { printf '%s\n' "$1" >"$root/ledger/mode"; }

phase=flag-off
boot false
inside test ! -e /run/woltspace-broker/effect.sock
[[ $(provision) != ok ]]
stop
phase=send
docker volume create "$source_volume"
boot true "$source_volume"
inside test ! -e /run/woltspace-broker/effect.sock
ok enroll alpha
ok register dummy.ping
[[ $(admin arm telegram.notice | json_field result) == not-provisioned ]]
[[ $(admin grant alpha telegram.notice | json_field result) == not-provisioned ]]
ready
probe unavailable
mode ok
arm=$(admin arm telegram.notice | json_field id)
probe ok
probe audit >"$root/before-node.json"
[[ $(audit_result "$arm" <"$root/before-node.json") == ok ]]
if ! node_probe=$(docker exec -u node "$container" /opt/woltspace/tools/woltspace/bin/python -I /opt/fixture/worker.py node) ||
    [[ ${node_probe##*$'\n'} != node-fenced ]]; then
    case ${node_probe##*$'\n'} in
        node-discovery|node-process|node-files|node-directory|node-sockets) phase=${node_probe##*$'\n'} ;;
        *) phase=node-start ;;
    esac
    line=$LINENO
    exit 1
fi
probe audit >"$root/after-node.json"
python3 - "$root/before-node.json" "$root/after-node.json" <<'PY'
import json, sys
before, after = (json.load(open(path)) for path in sys.argv[1:])
assert after[:len(before)] == before  # every prior row, the accepted send included, is intact
assert [row[1:] for row in after[len(before):]] == [  # only the node's two refused provision attempts
    ["worker", "other", None, "other", "denied"], ["node", "launch-control", None, "other", "invalid"]]
PY
mode mismatch
mismatch=$(admin arm telegram.notice | json_field id)
probe mismatch
[[ $(probe audit | audit_result "$mismatch") == mismatch ]]
ledger ok,mismatch
probe audit >"$root/pre.json"
phase=custody
control="control-$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
inside sh -c 'printf "%s\n" "$1" >/root/fixture-control' sh "$control"
docker commit "$container" "$committed"
docker save -o "$root/committed.tar" "$committed"
clean_of_token "$root/committed.tar" "$control"
rm -f -- "$root/committed.tar"
docker image rm "$committed"
stop
archive "$source_volume" "$root/pre.tar"
clean_of_token "$root/pre.tar" "telegram-$digest"

phase=crash-after-accept
boot true "$source_volume"
[[ $(admin arm telegram.notice | json_field result) == not-provisioned ]]
ready
mode crash
arm=$(admin arm telegram.notice | json_field id)
probe crash &
pid=$!
wait_until ledger ok,mismatch,crash
[[ $(admin arm telegram.notice | json_field result) == busy ]]
[[ $(probe audit | audit_result "$arm") == pending ]]
docker kill --signal KILL "$container"
retire 137
if wait "$pid"; then exit 1; fi
pid=
mode replay
boot true "$source_volume"
ready
probe unavailable
probe audit >"$root/post.json"
[[ $(audit_result "$arm" <"$root/post.json") == unknown ]]
stop
archive "$source_volume" "$root/post.tar"
clean_of_token "$root/post.tar" "telegram-$digest"

sends=ok,mismatch,crash
for snapshot in post pre; do
    phase="$snapshot-restore"
    volume="$name-$snapshot"
    restore "$volume" "$root/$snapshot.tar"
    boot true "$volume"
    probe audit >"$root/restored.json"
    cmp "$root/$snapshot.json" "$root/restored.json"  # the included audit comes back whole
    [[ $(grep -Fc "$arm" "$root/restored.json" || :) == "$([[ $snapshot == post ]] && echo 1 || echo 0)" ]]
    [[ $(admin arm telegram.notice | json_field result) == not-provisioned ]]
    [[ $(provision) == ok ]]
    ok grant alpha dummy.ping
    mode ok
    admin arm telegram.notice | json_field id >/dev/null
    probe denied  # provisioned and armed, but the restored grant row stays inactive
    ledger "$sends"
    ok grant alpha telegram.notice
    probe ok  # positive control: fresh provision, grant and arm send exactly once
    sends+=,ok
    ledger "$sends"
    stop
done
phase=rollback
boot true "$source_volume" "$route_off"
inside test ! -e /run/woltspace-broker/effect.sock
probe audit >"$root/rollback-before.json"
cmp "$root/post.json" "$root/rollback-before.json"
[[ $(provision) == disabled ]]
ok grant alpha dummy.ping
probe denied
probe audit >"$root/rollback-after.json"
[[ $(audit_result "$arm" <"$root/rollback-after.json") == unknown ]]
ledger "$sends"
[[ $sends == ok,mismatch,crash,ok,ok && ! -e "$root/ledger/errors" ]]
stop
printf 'PASS one acceptance per arm; verified result; mismatch; custody scans; crash, restores, rollback without replay\n' >&3
