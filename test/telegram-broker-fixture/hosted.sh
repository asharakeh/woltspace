#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
exec 3>&1 >/dev/null 2>&1
root=$(mktemp -d)
run_id=${root##*.}
name=telegram-broker-${run_id,,}  # Docker names are lowercase
base=$name:base
image=$name:fixture
route_off=$name:route-off
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
        if docker container inspect "$name"; then docker rm -f "$name" || failed=1; fi
        for volume in "${volumes[@]}"; do
            if docker volume inspect "$volume"; then docker volume rm "$volume" || failed=1; fi
        done
        for target in "$route_off" "$image" "$base"; do
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
if docker container inspect "$name"; then exit 1; fi
for target in "$route_off" "$image" "$base"; do
    if docker image inspect "$target"; then exit 1; fi
done
for volume in "${volumes[@]}"; do
    if docker volume inspect "$volume"; then exit 1; fi
done
owned=1
mkdir -p "$HOME" "$WOLTSPACE_WOLTS_DIR/.claude" "$root/build" "$root/ledger"
printf 'WOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
phase=image
WOLTSPACE_IMAGE="$base" ./woltspace build --local
cp test/telegram-broker-fixture/{telegram,worker}.py "$root/build/"
chmod 0644 "$root/build/telegram.py"  # the node-run connector loads it; root runs worker.py
printf 'FROM %s\n' "$base" >"$root/build/Dockerfile"
cat >>"$root/build/Dockerfile" <<'DOCKER'
COPY telegram.py worker.py /opt/fixture/
RUN set -e; p=/workspace/woltspace/container/connectors/telegram; \
    mv "$p/telegram_connector.py" "$p/telegram_real.py"; \
    cp /opt/fixture/telegram.py "$p/telegram_connector.py"; \
    test "$(stat -c %a "$p/telegram_connector.py")" = 644; \
    printf 'dummy\ntelegram\n' >/etc/woltspace/broker-dummy
DOCKER
docker build --network none --tag "$image" "$root/build"
printf 'FROM %s\nRUN printf "dummy\\n" >/etc/woltspace/broker-dummy\n' "$image" >"$root/build/Dockerfile"
docker build --network none --tag "$route_off" "$root/build"
inside() { docker exec -u 0 "$container" "$@"; }
py() { inside /opt/woltspace/tools/woltspace/bin/python -I "$@"; }
probe() { py /opt/fixture/worker.py "$@"; }
audit_result() {
    python3 -c 'import json,sys; [state] = [row[-1] for row in json.load(sys.stdin) if row[2]==sys.argv[1]]; print(state)' "$1"
}
admin() { py -m woltspace.dummy_broker admin "$@"; }
json_field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
ok() { [[ $(admin "$@" | json_field result) == ok ]]; }
regrant() { ok grant alpha dummy.ping; ok grant alpha telegram.notice; }
wait_until() {
    local limit=$((SECONDS + 30))
    until "$@"; do (( SECONDS < limit )) || return 1; sleep .15; done
}
health() { docker exec -u node "$container" curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:7777/health; }
handoff() {
    inside awk '$6=="03" && $8=="/run/woltspace-broker/effect.sock" {found=1} END {exit !found}' /proc/net/unix
}
boot() {
    local isolation=$1 volume=${2:-} startup_image=${3:-$image}
    local -a mounts=()
    if [[ $volume ]]; then mounts=(-v "$volume:$policy"); fi
    container=$(docker create --name "$name" --network none --security-opt no-new-privileges \
        -e WOLTSPACE_FEATURE_ISOLATION="$isolation" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        -e ENABLE_TELEGRAM_BOT=true -e TELEGRAM_ALLOWED_USERS=42 -e TELEGRAM_BOT_TOKEN=fixture-only \
        "${mounts[@]}" -v "$WOLTSPACE_WOLTS_DIR:/workspace/wolts" -v "$root/ledger:/fixture" "$startup_image")
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container") == none ]]
    docker start "$container"
    wait_until health
    if [[ $isolation == true && $startup_image == "$image" ]]; then wait_until handoff; fi
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
one_accept() { [[ $(cat "$root/ledger/accepts") == accepted && $(wc -l <"$root/ledger/accepts") == 1 ]]; }

phase=flag-off
boot false
inside test ! -e /run/woltspace-broker/effect.sock
stop
phase=pre-send
docker volume create "$source_volume"
boot true "$source_volume"
ok enroll alpha
ok register dummy.ping
ok grant alpha dummy.ping
ok register telegram.notice
ok grant alpha telegram.notice
probe unavailable
[[ ! -e "$root/ledger/accepts" ]]
stop
archive "$source_volume" "$root/pre.tar"

phase=crash-after-accept
boot true "$source_volume"
regrant
arm=$(admin arm telegram.notice | json_field id)
probe crash &
pid=$!
wait_until one_accept
[[ $(admin arm telegram.notice | json_field result) == busy ]]
[[ $(probe audit | audit_result "$arm") == pending ]]
docker kill --signal KILL "$container"
retire 137
if wait "$pid"; then exit 1; fi
pid=
boot true "$source_volume"
regrant
probe unavailable
probe audit >"$root/post.json"
[[ $(audit_result "$arm" <"$root/post.json") == unknown ]]
stop
archive "$source_volume" "$root/post.tar"

for snapshot in post pre; do
    phase="$snapshot-restore"
    volume="$name-$snapshot"
    restore "$volume" "$root/$snapshot.tar"
    boot true "$volume"
    probe audit >"$root/restored.json"
    if [[ $snapshot == post ]]; then
        cmp "$root/post.json" "$root/restored.json"
    else
        [[ $(grep -Fc "$arm" "$root/restored.json" || :) == 0 ]]
    fi
    regrant
    probe unavailable
    if [[ $snapshot == pre ]]; then
        ok revoke alpha telegram.notice
        probe denied
    fi
    one_accept
    stop
done
phase=rollback
boot true "$source_volume" "$route_off"
inside test ! -e /run/woltspace-broker/effect.sock
probe audit >"$root/rollback-before.json"
cmp "$root/post.json" "$root/rollback-before.json"
regrant
probe unavailable
ok revoke alpha telegram.notice
probe denied
probe audit >"$root/rollback-after.json"
[[ $(audit_result "$arm" <"$root/rollback-after.json") == unknown ]]
one_accept
stop
printf 'PASS one acceptance; crash recovery; post/pre restore; protected rollback\n' >&3
