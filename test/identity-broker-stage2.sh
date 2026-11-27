#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
export PATH="$(pwd -P):$PATH"
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|admin|dispatch|crash-restart|clean-stop|cleanup) ;;
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
venv_python=/opt/woltspace/tools/woltspace/bin/python
phase=setup

cleanup() {
    local status=$? cleaned=0
    trap - EXIT
    # Only remove the container and image that this run attempted to create.
    if [[ ${owned:-false} == true ]]; then
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
if docker container inspect "$name" || docker image inspect "$WOLTSPACE_IMAGE" || docker volume inspect "$volume"; then failure_line=$LINENO; exit 1; fi
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
echo 'PASS flag-on' >&3

phase=admin
admin() { ./woltspace secrets "$@" 3>&-; }  # host Docker authority -> uid 0 in the container
# Every reply is checked with the client's exit status: 0 only for ok, 1 for any refusal.
id_of() { python3 -c 'import json,re,sys; r=json.load(sys.stdin); assert set(r) == {"result", "id"} and r["result"] == "ok" and re.fullmatch("p-[0-9a-f]{32}", r["id"]); print(r["id"])'; }
result_of() {
    local out status=0
    out=$(admin "${@:2}") || status=$?
    [[ $out == "{\"result\": \"$1\"}" && $status == "$([[ $1 == ok ]] && echo 0 || echo 1)" ]]
}
id_a=$(admin enroll wolt-a | id_of)
id_b=$(admin enroll wolt-b | id_of)
[[ $id_a != "$id_b" && $(admin enroll wolt-a | id_of) == "$id_a" ]]  # stable, opaque, replay-safe
result_of not-registered grant wolt-a dummy.ping
result_of ok register dummy.ping
result_of ok grant wolt-a dummy.ping
result_of ok run wolt-a dummy.ping
result_of not-granted run wolt-b dummy.ping
result_of unknown-wolt run wolt-c dummy.ping
result_of unknown-action run wolt-a other.send
# The ordinary worker: same admin client, no socket access, no registry access.
out=$(docker exec --user node "$name" "$venv_python" -I -m woltspace.dummy_broker admin grant wolt-b dummy.ping) && exit 1
[[ $out == '{"result": "unavailable"}' ]]
docker exec --user node "$name" test ! -r "$policy/registry.db"
docker exec --user node "$name" sh -c "ls $policy" && exit 1
result_of not-granted run wolt-b dummy.ping  # the worker's grant never landed
[[ $(docker inspect -f '{{range .Mounts}}{{if eq .Destination "'"$policy"'"}}{{.Type}} {{.Name}}{{end}}{{end}}' "$name") == "volume $volume" ]]
modes() {
    docker exec -u 0 "$name" sh -ec '
        cd "$1"; [ "$(ls -A | tr "\n" " ")" = "action.key registry.db " ]
        [ "$(stat -c "%u:%g %a" . registry.db action.key | tr "\n" " ")" = "990:990 700 990:990 600 990:990 400 " ]
    ' sh "$policy"
}
modes
# One uid-0 process in the container reads the dummy key and checks every 16-char slice
# against the logs, declared env, process args, the registry file and its own exec env.
# The key never enters this shell; only a fixed label comes back.
leak() {
    { docker logs "$name" 2>&1; docker inspect -f '{{json .Config.Env}}' "$name"; } |
        docker exec -i -u 0 "$name" "$venv_python" -I -c '
import os, sys
key = open(sys.argv[1] + "/action.key", "rb").read()
hay = sys.stdin.buffer.read() + open(sys.argv[1] + "/registry.db", "rb").read()
hay += str(os.environ).encode()
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        hay += open(f"/proc/{pid}/cmdline", "rb").read()
    except OSError:
        pass
assert len(key) == 64 and all(key[i:i + 16] not in hay for i in range(0, 64, 16))
print("no-leak")
' "$policy" | grep -Fx no-leak >/dev/null
}
leak
audit_ok() {
    docker exec -u 0 "$name" "$venv_python" -I -c '
import sqlite3, sys
db = sqlite3.connect(f"file:{sys.argv[1]}/registry.db?mode=ro", uri=True)
rows = db.execute("SELECT caller, op, principal, action, result FROM audit").fetchall()
assert rows and all(p is None or p.startswith("p-") for _, _, p, _, _ in rows)
assert not any("wolt-" in str(row) for row in rows)  # ids, never names
print(sum(row[1:2] == ("grant",) and row[4] == "ok" for row in rows))
' "$policy"
}
[[ $(audit_ok) == 1 ]]
echo 'PASS admin' >&3

phase=dispatch
# Install a root-owned synthetic launcher; workers receive only their own FD.
fixture=$(docker exec -i -u 0 "$name" sh -ec '
    dir=$(mktemp -d /tmp/identity-dispatch.XXXXXX)
    cat >"$dir/probe.py"
    chmod 0444 "$dir/probe.py"
    chmod 0755 "$dir"
    printf "%s\n" "$dir/probe.py"
' <test/identity_broker_stage2_fixture.py)
[[ $fixture =~ ^/tmp/identity-dispatch\.[[:alnum:]]{6}/probe\.py$ ]]
probe() { docker exec -u 0 "$name" env -i PATH=/usr/bin:/bin /usr/bin/python3 -I -S "$fixture" "$@"; }
metrics=$(probe exercise)
[[ $metrics =~ ^dispatch\ submissions=12\ ok=6\ denied=3\ busy=3\ requests_per_second=[0-9.]+\ p50_ms=[0-9.]+\ p95_ms=[0-9.]+\ p99_ms=[0-9.]+\ revoke_ms=[0-9.]+$ ]]
printf '%s\n' "$metrics" >&3
echo 'PASS dispatch' >&3

phase=crash-restart
container_id=$(docker inspect -f '{{.Id}}' "$name")
broker_pid=$(docker exec "$name" ps -eo pid=,uid=,args= |
    awk '$2 == 990 && $4 == "-I" && $5 == "-S" && $6 ~ /\/dummy_broker\.py$/ { print $1 }')
[[ $broker_pid =~ ^[1-9][0-9]*$ ]]
# The supervisor can exit and reap the attached docker exec after the signal.
# The stopped status plus the unknown audit row after restart is the proof.
crash_status=0
probe crash "$broker_pid" || crash_status=$?
case "$crash_status" in 0|1|137|143) ;; *) failure_line=$LINENO; exit 1 ;; esac
[[ $(timeout 20 docker wait "$container_id") == 1 ]]
docker start "$container_id"
check_isolation
out=$(probe recover)
[[ $out == 'PASS unknown-no-replay' ]]
echo 'PASS crash-restart' >&3

phase=clean-stop
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
echo 'PASS clean-stop' >&3
