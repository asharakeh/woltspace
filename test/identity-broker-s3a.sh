#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
export PATH="$(pwd -P):$PATH"
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|admin|create|recover|restart|lifecycle|clean-stop|cleanup) ;;
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

dummy_engine() {
    [[ $(docker exec --user node "$name" sh -c 'command -v claude') == /home/node/.local/bin/claude ]]
    # The image's engine binary, replaced in this disposable container by an offline stand-in:
    # no provider, credentials or network. Without a terminal (boot's `claude plugin`) it exits at once;
    # in a session's tmux pane it records one start in its working folder and stays up.
    docker exec -i -u 0 "$name" sh -ec '
        engine=/home/node/.local/bin/claude
        [ -e "$engine" ] || [ -L "$engine" ]
        rm -f "$engine"
        cat >"$engine"
        chmod 0755 "$engine"
    ' <<'ENGINE'
#!/bin/sh
[ -t 0 ] || exit 0
printf 'start\n' >>.dummy-engine
while :; do sleep 60; done
ENGINE
}
starts_of() { wc -l <"$WOLTSPACE_WOLTS_DIR/$1/.dummy-engine"; }

phase=flag-off
printf 'DEV_MODE=false\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
./woltspace start
health
dummy_engine
uids=$(broker_uids)
[[ -z $uids ]]
docker exec "$name" test ! -e "${store%/*}"
[[ -z $(docker volume ls -q --filter "name=^${volume}$") ]]  # flag off creates no policy volume
flag_off=$(curl --noproxy '*' -sS --max-time 30 -o /dev/null -w '%{http_code}' -H 'content-type: application/json' \
    -d '{"name": "wolt-o", "type": "beaver"}' http://127.0.0.1:17777/sessions/new/create)
[[ $flag_off == 200 && -f $WOLTSPACE_WOLTS_DIR/wolt-o/wolt/wolt.json && ! -e $WOLTSPACE_WOLTS_DIR/wolt-o/.state/create-request ]]
deadline=$((SECONDS + 30))
until [[ -s $WOLTSPACE_WOLTS_DIR/wolt-o/.dummy-engine ]]; do (( SECONDS < deadline )); sleep 1; done
[[ $(starts_of wolt-o) == 1 ]]  # the ordinary create really started its first session, once
[[ $(curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:17777/sessions |
    python3 -c 'import json,sys; print(sum(s.get("wolt") == "wolt-o" for s in json.load(sys.stdin)))') == 1 ]]
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
dummy_engine
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

phase=create
# The ordinary create API on the published port, with the request ID the lodge page and the tui send.
# Codes, IDs and session names stay in this shell; only fixed labels are printed.
api() {
    curl --noproxy '*' -sS --max-time 30 -o "$root/reply.json" -w '%{http_code}' \
        -H 'content-type: application/json' -d "$1" http://127.0.0.1:17777/sessions/new/create
}
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$root/reply.json" "$1"; }
from_json() { python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], ""))' "$1" "$2"; }
ordinary() {  # the create socket as the ordinary node uid
    docker exec --user node "$name" "$venv_python" -I -c 'import json,sys
from woltspace import dummy_broker as b
print(json.dumps(b.call(json.loads(sys.argv[1]), b.SOCKET.with_name(b.CREATE))))' "$1"
}
approve() {  # the host owner reviews the exact terms, then approves that fingerprint
    local review
    review=$(admin review "$1")
    [[ $(from_json "$review" status) == pending ]]
    admin approve "$1" "$(from_json "$review" fingerprint)" >"$root/approved.json"
    python3 -c 'import json,re,sys; r=json.load(open(sys.argv[1])); assert r["status"] == "approved"
print(re.fullmatch("p-[0-9a-f]{32}", r["id"])[0])' "$root/approved.json"
}
token() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
sessions_of() {  # the lodge's own session registry: how many sessions this wolt has
    curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:17777/sessions |
        python3 -c 'import json,sys; print(sum(s.get("wolt") == sys.argv[1] for s in json.load(sys.stdin)))' "$1"
}
first_session() {  # the reply names the real first session; it reaches running with its tmux and agent alive
    local session deadline=$((SECONDS + 30))
    session=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["session"]["name"])' "$root/reply.json")
    until curl --noproxy '*' -fsS --max-time 5 "http://127.0.0.1:17777/sessions/$session" | python3 -c 'import json,sys
s = json.load(sys.stdin); sys.exit(0 if (s["status"], s.get("tmux_alive"), s.get("agent_alive")) == ("running", True, True) else 1)'; do
        (( SECONDS < deadline )) || return 1
        sleep 1
    done
    until [[ -s $WOLTSPACE_WOLTS_DIR/$1/.dummy-engine ]]; do (( SECONDS < deadline )) || return 1; sleep 1; done
    [[ $(sessions_of "$1") == 1 && $(starts_of "$1") == 1 ]]  # one registry session, one engine start
}
rid_a=$(token)
body=$(printf '{"name": "wolt-p", "type": "beaver", "request_id": "%s"}' "$rid_a")
[[ $(api "$body") == 202 && $(field status) == pending ]]
code=$(field code)
[[ $(api "$body") == 202 && $(field code) == "$code" && ! -e $WOLTSPACE_WOLTS_DIR/wolt-p ]]  # replay, nothing written
[[ $(api "${body/beaver/otter}") == 409 && $(field result) == conflict ]]
out=$(docker exec --user node "$name" "$venv_python" -I -m woltspace.dummy_broker admin approve "$code" 000000000000) && exit 1
[[ $out == '{"result": "unavailable"}' ]]  # node cannot reach the admin socket
[[ $(ordinary "{\"op\": \"approve\", \"code\": \"$code\", \"terms\": \"000000000000\"}") == '{"result": "denied"}' ]]
pid=$(approve "$code")
result_of creating rename wolt-p wolt-q  # an unfinished create keeps its name
[[ $(api "$body") == 200 && $(field status) == launched && $(field id) == "$pid" ]]
first_session wolt-p
[[ $(cat "$WOLTSPACE_WOLTS_DIR/wolt-p/.state/create-request") == "$rid_a $pid" ]]
[[ $(api "$body") == 200 && $(field status) == launched && $(sessions_of wolt-p) == 1 && $(starts_of wolt-p) == 1 ]]  # a replay starts nothing
echo 'PASS create' >&3

phase=recover
# The CLI entry point; a folder this request did not start is left for the owner.
# As a lodge session runs it: every lodge child gets WOLTSPACE_PYTHON = the venv interpreter
# (container_entrypoint). A bare exec would reach the image's woltspace-python symlink, which starts the
# base python without the woltspace package.
cli() { docker exec --user node -e "WOLTSPACE_PYTHON=$venv_python" "$name" create-creature-wolt "$@"; }
rid_x=$(token)
mkdir "$WOLTSPACE_WOLTS_DIR/wolt-x"
printf 'owner data\n' >"$WOLTSPACE_WOLTS_DIR/wolt-x/notes.md"
out=$(cli wolt-x beaver --request "$rid_x")  # exit 0: a pending request
[[ $(from_json "$out" status) == pending ]]
code_x=$(from_json "$out" code)
[[ $code_x =~ ^c-[0-9a-f]{8}$ ]]
approve "$code_x" >/dev/null
out=$(cli wolt-x beaver --request "$rid_x") && exit 1
[[ $(from_json "$out" status) == ambiguous && $(cat "$WOLTSPACE_WOLTS_DIR/wolt-x/notes.md") == 'owner data' ]]
[[ $(from_json "$(admin reconcile "$code_x")" status) == approved ]]
mv "$WOLTSPACE_WOLTS_DIR/wolt-x" "$root/owner-kept"
out=$(cli wolt-x beaver --request "$rid_x")
[[ $(from_json "$out" status) == scaffolded ]]  # first launch stays separate
[[ -f $WOLTSPACE_WOLTS_DIR/wolt-x/wolt/wolt.json ]]
echo 'PASS recover' >&3

phase=restart
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
docker start "$name"
check_isolation
status=$(ordinary "{\"op\": \"create-status\", \"request\": \"$rid_a\"}")
[[ $(from_json "$status" status) == launched && $(from_json "$status" id) == "$pid" ]]  # durable across restart
echo 'PASS restart' >&3

phase=lifecycle
result_of ok rename wolt-p wolt-r
[[ $(admin enroll wolt-r | id_of) == "$pid" ]]  # rename keeps the stable ID and the name stays held
[[ $(api "$(printf '{"name": "wolt-r", "type": "beaver", "request_id": "%s"}' "$(token)")") == 409 ]]
result_of ok retire wolt-r
[[ $(from_json "$(ordinary "{\"op\": \"create-status\", \"request\": \"$rid_a\"}")" status) == retired ]]
body=$(printf '{"name": "wolt-r", "type": "beaver", "request_id": "%s"}' "$(token)")
[[ $(api "$body") == 202 ]]
new_pid=$(approve "$(field code)")
[[ $new_pid != "$pid" && $(api "$body") == 200 && $(field id) == "$new_pid" ]]
first_session wolt-r
result_of not-granted run wolt-r dummy.ping  # a recreated name inherits no grant
modes
leak
[[ $(audit_ok) == 1 ]]
echo 'PASS lifecycle' >&3

phase=clean-stop
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
echo 'PASS clean-stop' >&3
