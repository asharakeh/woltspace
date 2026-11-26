#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
export PATH="$(pwd -P):$PATH"
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|admin|forced-stop-resume|recreate|clean-stop|backup-restore|crash-reconcile|cleanup) ;;
        *) failed_phase=setup ;;
    esac
    [[ $source_line =~ ^[1-9][0-9]{0,5}$ ]] || source_line=1
    printf '::error::broker-smoke phase=%s line=%s\n' "$failed_phase" "$source_line" >&3
}
trap 'failure_line=$LINENO' ERR
root=$(mktemp -d) || { annotate_failure setup "$LINENO"; echo 'FAIL setup' >&3; exit 1; }
export WOLTSPACE_CONTAINER="broker-smoke-${root##*.}"
export WOLTSPACE_IMAGE="broker-smoke:${root##*.}"
export HOME="$root/home" XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data"
export WOLTSPACE_WOLTS_DIR="$root/wolts"
export WOLTSPACE_NODE_SUDO=false WOLTSPACE_LOCAL=true WOLTSPACE_PUBLISH_HOST=127.0.0.1
export WOLTSPACE_PORT=17777 WOLTSPACE_FEATURE_ISOLATION=false
name=$WOLTSPACE_CONTAINER
store=/var/lib/woltspace-broker/store
volume="$name-secrets" policy=/var/lib/woltspace-secrets
helper="$name-recovery"
venv_python=/opt/woltspace/tools/woltspace/bin/python
phase=setup

cleanup() {
    local status=$? cleaned=0
    trap - EXIT
    # Only remove the container and image that this run attempted to create.
    if [[ ${owned:-false} == true ]]; then
        if docker container inspect "$helper" >/dev/null; then
            docker rm -f "$helper" || cleaned=1
        fi
        if docker container inspect "$name" >/dev/null; then
            docker rm -f "$name" || cleaned=1
        fi
        if docker volume inspect "$volume" >/dev/null; then
            docker volume rm "$volume" || cleaned=1
        fi
        if docker image inspect "$WOLTSPACE_IMAGE" >/dev/null; then
            docker image rm "$WOLTSPACE_IMAGE" || cleaned=1
        fi
    fi
    rm -rf -- "$root" || cleaned=1
    if (( status != 0 )); then
        annotate_failure "$phase" "$failure_line"
        printf 'FAIL %s\n' "$phase" >&3
    fi
    if (( cleaned != 0 )); then
        if (( status == 0 )); then annotate_failure cleanup "$LINENO"; fi
        echo 'FAIL cleanup' >&3; exit 1
    fi
    echo 'PASS cleanup' >&3
    exit "$status"
}
trap cleanup EXIT
trap 'failure_line=$LINENO; exit 1' INT TERM

mkdir -p "$HOME" "$WOLTSPACE_WOLTS_DIR"
docker info
if docker container inspect "$name" || docker container inspect "$helper" || docker image inspect "$WOLTSPACE_IMAGE" || docker volume inspect "$volume"; then failure_line=$LINENO; exit 1; fi
owned=true
phase=image-build
./woltspace build --local
echo 'PASS image-build' >&3

health() {
    # The API starts asynchronously after broker readiness. Wait at most 30 s.
    local response deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        if response=$(curl --noproxy '*' -fsS --max-time 1 http://127.0.0.1:17777/health); then
            python3 -c 'import json,sys; h=json.load(sys.stdin); assert h["ok"] is True; print(int(h["pid"]))' <<<"$response"
            return
        fi
        [[ $(docker inspect -f '{{.State.Running}}' "$name") == true ]] || return 1
        sleep 1
    done
    return 1
}

broker_uids() {
    docker exec "$name" ps -eo uid=,args= |
        awk '$3 == "-I" && $4 == "-S" && $5 ~ /\/dummy_broker\.py$/ { print $1 }'
}

phase=flag-off
printf 'DEV_MODE=false\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
./woltspace start
health
uids=$(broker_uids)
[[ -z $uids ]]
docker exec "$name" test ! -e "${store%/*}"
[[ -z $(docker volume ls -q --filter "name=^${volume}$") ]]  # flag off creates no policy volume
./woltspace stop
[[ -z $(docker ps -aq --filter "name=^/${name}$") ]]
echo 'PASS flag-off' >&3

check_isolation() {
    local pid worker_uid uids
    pid=$(health)
    uids=$(broker_uids)
    [[ $uids == 990 ]] # Exactly one broker, including after resume.
    worker_uid=$(docker exec "$name" ps -o uid= -p "$pid" | awk '{print $1}')
    [[ $worker_uid == "$(id -u)" && $worker_uid != 0 && $worker_uid != "$uids" ]]
    docker exec -i --user node "$name" python3 - "$store" <<'PY'
import sys

try:
    with open(sys.argv[1], "rb"):
        pass
except PermissionError:
    sys.exit(0)
sys.exit(1)
PY
}

phase=flag-on
export WOLTSPACE_FEATURE_ISOLATION=true
# Quoting exercises dotenv parsing. The setup marker predates the supervisor.
printf 'DEV_MODE="true"\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
./woltspace start
check_isolation
docker logs "$name" 2>&1 | grep -E '^setup complete: .* dev=True$' >/dev/null
before=$(docker exec --user 990:990 "$name" sha256sum "$store")
echo 'PASS flag-on' >&3

phase=admin
admin() { ./woltspace secrets "$@" 3>&-; }  # host Docker authority -> uid 0 in the container
[[ $(admin enroll wolt-a) == '{"result": "ok"}' ]]
[[ $(admin enroll wolt-b) == '{"result": "ok"}' ]]
[[ $(admin grant wolt-a dummy.ping) == '{"result": "not-registered"}' ]]
[[ $(admin register dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin grant wolt-a dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin run wolt-a dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin run wolt-b dummy.ping) == '{"result": "not-granted"}' ]]
[[ $(admin run wolt-c dummy.ping) == '{"result": "unknown-wolt"}' ]]
[[ $(admin run wolt-a other.send) == '{"result": "unknown-action"}' ]]
# The ordinary worker: same admin client, no socket access, no store access.
out=$(docker exec --user node "$name" /opt/woltspace/tools/woltspace/bin/python -I -m woltspace.dummy_broker admin grant wolt-b dummy.ping) && exit 1
[[ $out == '{"result": "unavailable"}' ]]
docker exec --user node "$name" test ! -r "$policy/policy.json"
docker exec --user node "$name" sh -c "ls $policy" && exit 1
[[ $(docker exec -u 0 "$name" stat -c '%u:%g %a' "$policy") == '990:990 700' ]]
[[ $(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'"$policy"'"}}{{.Type}} {{.Name}}{{end}}{{end}}' "$name") == "volume $volume" ]]
[[ $(admin run wolt-b dummy.ping) == '{"result": "not-granted"}' ]]  # the worker's grant never landed
key=$(docker exec -u 0 "$name" cat "$policy/action.key")
[[ ${#key} == 64 ]]
leak() {
    # The key exists only in this disposable test. Inspect the declared Docker
    # environment and a fresh worker exec. The broker launch env is covered in unit tests.
    local hay i
    hay=$(docker logs "$name" 2>&1 &&
          docker exec -u 0 "$name" sh -c "cat $policy/audit.log && ps -eo args" &&
          docker inspect -f '{{json .Config.Env}}' "$name" &&
          docker exec --user node "$name" env) || return 1
    for ((i = 0; i + 16 <= 64; i += 16)); do [[ $hay != *"${key:i:16}"* ]] || return 1; done
}
leak
docker exec -u 0 "$name" python3 -c 'import json,sys
rows=[json.loads(l) for l in open(sys.argv[1])]
assert rows and all(set(r)=={"caller","op","action","result"} for r in rows), rows' "$policy/audit.log"
echo 'PASS admin' >&3

phase=forced-stop-resume
container_id=$(docker inspect -f '{{.Id}}' "$name")
docker kill --signal KILL "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 137' ]]
docker diff "$name" | grep -Fx "A $store" >/dev/null
docker start "$container_id"
[[ $(docker inspect -f '{{.Id}}' "$name") == "$container_id" ]]
check_isolation
after=$(docker exec --user 990:990 "$name" sha256sum "$store")
[[ -n $after && $after != "$before" ]]
[[ $(admin run wolt-a dummy.ping) == '{"result": "ok"}' ]]  # policy and key survived the kill
[[ $(docker exec -u 0 "$name" cat "$policy/action.key") == "$key" ]]
echo 'PASS forced-stop-resume' >&3

phase=recreate
./woltspace stop  # force-removes the container; the named volume stays
[[ -z $(docker ps -aq --filter "name=^/${name}$") && -n $(docker volume ls -q --filter "name=^${volume}$") ]]
./woltspace start
check_isolation
[[ $(admin run wolt-a dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin revoke wolt-a dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin run wolt-a dummy.ping) == '{"result": "not-granted"}' ]]
leak
echo 'PASS recreate' >&3

phase=clean-stop
# The host stop command force-removes the container. Observe SIGTERM first.
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
changes=$(docker diff "$name")
[[ $changes != *"${store%/*}"* && $changes != *"/run/woltspace-broker"* ]]
./woltspace stop
[[ -z $(docker ps -aq --filter "name=^/${name}$") ]]
echo 'PASS clean-stop' >&3

# The helper is offline and auto-removed; its archive stream is not logged.
offline() {
    docker run --rm --name "$helper" --network none --log-driver none "$@"
}

phase=backup-restore
mkdir -m 700 "$root/recovery"
fixture="$root/recovery"
probe() {
    offline -i --user "$(id -u):$(id -g)" -v "$fixture:/fixture" \
        --entrypoint "$venv_python" "$WOLTSPACE_IMAGE" -I - "$@" <test/test_broker_recovery_probe.py
}
archive_tool() {
    offline --user "$(id -u):$(id -g)" -e HOME=/fixture -v "$fixture:/fixture" \
        --entrypoint /usr/local/bin/woltspace "$WOLTSPACE_IMAGE" "$@"
}
probe fixture /fixture
archive_tool backup --wolts-dir /fixture/old --out /fixture --tag before-cutover
archive_tool restore /fixture/woltspace-backup-before-cutover.tar.gz --to /fixture/restored
probe quarantine /fixture
restored="$fixture/restored/wolts"
printf 'WOLTSPACE_CONFIG=/workspace/wolts/.space/legacy.json\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$restored/.env"

# Lodge archives exclude this separate trusted volume. Snapshot it with the broker stopped.
./woltspace start
check_isolation
[[ $(admin grant wolt-b dummy.ping) == '{"result": "ok"}' ]]
trusted_policy=$(docker exec -u 0 "$name" sha256sum "$policy/policy.json")
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
./woltspace stop
[[ -z $(docker ps -aq --filter "name=^/${name}$") ]]
[[ $(docker volume inspect -f '{{.Name}}' "$volume") == "$volume" ]]
snapshot="$fixture/broker-volume.tar"
(
    umask 077
    offline --user 0:0 -v "$volume:$policy:ro" --entrypoint tar "$WOLTSPACE_IMAGE" \
        --numeric-owner -C "$policy" -cpf - . >"$snapshot"
)
[[ -s $snapshot && $(stat -c %a "$snapshot") == 600 ]]
docker volume rm "$volume"
[[ -z $(docker volume ls -q --filter "name=^${volume}$") ]]
[[ $(docker volume create "$volume") == "$volume" ]]
offline -i --user 0:0 -v "$volume:$policy" --entrypoint tar "$WOLTSPACE_IMAGE" \
    --numeric-owner --same-owner --same-permissions -C "$policy" -xpf - <"$snapshot"
offline --user 0:0 -v "$volume:$policy:ro" --entrypoint sh "$WOLTSPACE_IMAGE" -ec '
    dir=$1
    [ "$(stat -c "%u:%g %a" "$dir")" = "990:990 700" ]
    [ "$(stat -c "%u:%g %a" "$dir/policy.json")" = "990:990 600" ]
    [ "$(stat -c "%u:%g %a" "$dir/action.key")" = "990:990 400" ]
    [ "$(stat -c "%u:%g %a" "$dir/audit.log")" = "990:990 600" ]
' sh "$policy"
export WOLTSPACE_WOLTS_DIR="$restored"
./woltspace start
check_isolation
cmp "$fixture/old/.space/marker.txt" "$restored/.space/marker.txt"
python3 - "$restored/.space/platform/connectors.json" <<'PYTHON'
import json
import sys
from pathlib import Path

report = json.loads(Path(sys.argv[1]).read_text())
legacy, = (entry for entry in report["connectors"] if entry["name"] == "legacy")
assert legacy["state"] == "disabled" and legacy["pid"] is None
PYTHON
[[ $(docker exec -u 0 "$name" sha256sum "$policy/policy.json") == "$trusted_policy" ]]
[[ $(docker exec -u 0 "$name" cat "$policy/action.key") == "$key" ]]
[[ $(admin run wolt-b dummy.ping) == '{"result": "ok"}' ]]
[[ $(admin run wolt-a dummy.ping) == '{"result": "not-granted"}' ]]
leak
echo 'PASS backup-restore' >&3

phase=crash-reconcile
audit_before=$(docker exec -u 0 "$name" sha256sum "$policy/audit.log")
docker stop --time 15 "$name"
offline -i -v "$volume:$policy" --entrypoint "$venv_python" "$WOLTSPACE_IMAGE" \
    -I - crash "$policy" <test/test_broker_recovery_probe.py
docker start "$name"
check_isolation
[[ $(docker exec -u 0 "$name" sha256sum "$policy/audit.log") == "$audit_before" ]]
reconciled_policy=$(docker exec -u 0 "$name" sha256sum "$policy/policy.json")
[[ $reconciled_policy != "$trusted_policy" ]]
# Read-only owner action confirms the authoritative policy after restart.
[[ $(admin run wolt-a dummy.ping) == '{"result": "ok"}' ]]
[[ $(docker exec -u 0 "$name" sha256sum "$policy/policy.json") == "$reconciled_policy" ]]
docker exec -u 0 "$name" "$venv_python" -I -c '
import json, sys
rows = [json.loads(row) for row in open(sys.argv[1])]
assert all(set(row) == {"caller", "op", "action", "result"} for row in rows)
assert rows[-1] == {"caller": "host-admin", "op": "run", "action": "dummy.ping", "result": "ok"}
assert sum(row["op"] == "grant" and row["result"] == "ok" for row in rows) == 2
' "$policy/audit.log"
leak
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
echo 'PASS crash-reconcile' >&3
