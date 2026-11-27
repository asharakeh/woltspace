#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
export PATH="$(pwd -P):$PATH"
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|lifecycle-start|lifecycle-resume|lifecycle-stop|clean-stop|cleanup) ;;
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

docker logs "$name" 2>&1 |
    grep -Fx 'automatic wolt launch refused: protected session launch required' >/dev/null
[[ $(starts_of wolt-o) == 1 ]]
phase=lifecycle-start
unregistered=$(curl --noproxy '*' -sS --max-time 10 -o /dev/null -w '%{http_code}' \
    -H 'content-type: application/json' -d '{"wolt":"wolt-o"}' http://127.0.0.1:17777/sessions/new/lodge)
[[ $unregistered == 500 ]]
admin() { ./woltspace secrets "$@" 3>&-; }
admin enroll wolt-o
admin register dummy.ping
admin grant wolt-o dummy.ping
node_uid=$(docker exec --user node "$name" id -u)
terminal() {
    docker exec --user node "$name" env -i PATH=/usr/bin:/bin         tmux -S "/tmp/tmux-$node_uid/default" "$@"
}
api() {
    local route=$1
    shift
    curl --noproxy '*' -fsS --max-time 35 "$@" "http://127.0.0.1:17777$route"
}
post() { api "$1" -H 'content-type: application/json' -d "$2"; }
field() {
    python3 -c 'import json,sys
data=json.load(sys.stdin)
for key in sys.argv[1:]:
    data=data[key]
print(data)' "$@"
}
start() { post /sessions/new/lodge '{"wolt":"wolt-o"}' | field name; }
count() {
    docker exec -u 0 "$name" /usr/bin/python3 -I -c '
import sqlite3,sys
with sqlite3.connect("file:/var/lib/woltspace-secrets/registry.db?mode=ro", uri=True) as db:
    print(db.execute("SELECT count(*) FROM audit WHERE op=? AND result=?", sys.argv[1:]).fetchone()[0])
' "$1" "$2"
}
workers() {
    docker exec "$name" ps -eo uid=,args= |
        awk '$1 == 991 && $0 ~ /woltspace[.]protected_launcher worker/ { print $1 }' | wc -l
}
wait_workers() {
    local deadline=$((SECONDS + 12))
    until [[ $(workers) == "$1" ]]; do (( SECONDS < deadline )) || return 1; sleep 1; done
}
a=$(start) b=$(start)
[[ $a != "$b" && $(count attach ok) == 2 ]]
wait_workers 2
a_record=$(api "/sessions/$a")
orig=$(field harness_session_id <<<"$a_record")
pane=$(field runtime pane_id <<<"$a_record")
before=$(field attempt <<<"$a_record")
sibling=$(api "/sessions/$b" | field attempt)
[[ -n $orig && $pane == %* && -n $before && -n $sibling ]]
docker exec -i --user node "$name" env -i PATH=/usr/bin:/bin \
    /usr/bin/python3 -I -S - <<'PYTEST'
import json, socket
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(3)
    control.connect("/run/woltspace-broker/launch.sock")
    control.sendall(json.dumps(dict(op="launch-open", wolt="wolt-o",
                                   session="wolt-o-peer-check", attempt="111111111111")).encode() + b"\n")
    assert json.loads(control.makefile("rb").readline()) == {"result": "ok"}
PYTEST
docker exec -i --user 991:991 "$name" env -i PATH=/usr/bin:/bin \
    /usr/bin/python3 -I -S - wolt-o-peer-check 111111111111 <<'PYTEST'
import json, socket, sys

selector = dict(session=sys.argv[1], attempt=sys.argv[2])
with socket.socket(socket.AF_UNIX) as control:
    control.settimeout(3)
    control.connect("/run/woltspace-broker/launch.sock")
    control.sendall(json.dumps(dict(selector, op="launch-open", wolt="wolt-o")).encode() + b"\n")
    assert json.loads(control.makefile("rb").readline()) == {"result": "denied"}
with socket.socket(socket.AF_UNIX) as launcher:
    launcher.settimeout(3)
    launcher.connect("/run/woltspace-launch.sock")
    try:
        launcher.sendall(json.dumps(dict(selector, op="launch-redeem")).encode() + b"\n")
        assert launcher.recv(128) == b""
    except (BrokenPipeError, ConnectionResetError):
        pass
PYTEST
docker exec -i --user node "$name" env -i PATH=/usr/bin:/bin \
    /usr/bin/python3 -I -S - <<'PYTEST'
import json, socket
with socket.socket(socket.AF_UNIX) as launcher:
    launcher.settimeout(5)
    launcher.connect("/run/woltspace-launch.sock")
    launcher.sendall(json.dumps(dict(op="launch-redeem", session="wolt-o-peer-check",
                                     attempt="111111111111")).encode() + b"\n")
    assert launcher.makefile("rb").readline() == b"protected dummy ready\n"
    launcher.sendall(b"exit\n")
    assert launcher.recv(1) == b""
PYTEST
wait_workers 2
docker exec -i -u 0 "$name" /usr/bin/python3 -I -S - <<'PYTEST'
from pathlib import Path

def read_status(proc):
    return dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines())

proc_root = Path("/proc")
workers = []
for proc in proc_root.iterdir():
    if not proc.name.isdecimal():
        continue
    try:
        args = (proc / "cmdline").read_bytes().split(b"\0")
        if [b"woltspace.protected_launcher", b"worker"] != args[args.index(b"-m") + 1:][:2]:
            continue
        status = read_status(proc)
    except (OSError, ValueError):
        continue
    workers.append(status)
assert len(workers) == 2
for status in workers:
    assert status["Uid"].split() == status["Gid"].split() == ["991"] * 4
    assert status["Groups"].strip() == ""
    assert status["NoNewPrivs"].strip() == "1"
    assert status["Seccomp"].strip() == "2"
    # Compare with the actual launcher so Docker's inherited filters alone cannot pass.
    parent = read_status(proc_root / status["PPid"].strip())
    assert parent["Uid"].split() == ["0"] * 4
    assert int(status["Seccomp_filters"]) > int(parent["Seccomp_filters"])
PYTEST
[[ $(count attach ok) == 3 ]]
echo 'PASS lifecycle-start' >&3

phase=lifecycle-resume
wait_ping() {
    local pane_id=$1 deadline=$((SECONDS + 12))
    until terminal capture-pane -p -t "$pane_id" | grep -Fx 'dummy ok' >/dev/null; do
        (( SECONDS < deadline )) || return 1
        sleep 1
    done
}
post "/sessions/$a/resume" '{"prompt":"ping"}'
wait_ping "$pane"
[[ $(count attach ok) == 3 && $(count dispatch ok) == 1 ]]
[[ $(api "/sessions/$a" | field attempt) == "$before" ]]

# Recreate the supported saved-pane condition: the trusted shell remains in
# the exact pane, while the previous worker has exited and lost its channel.
terminal respawn-pane -k -t "$pane" /bin/bash --noprofile --norc
wait_workers 1
post "/sessions/$a/resume" '{"prompt":"ping"}' | field status | grep -Fx revived
wait_ping "$pane"
after=$(api "/sessions/$a")
[[ $(field runtime pane_id <<<"$after") == "$pane" ]]
[[ $(field harness_session_id <<<"$after") == "$orig" && $(field attempt <<<"$after") != "$before" ]]
[[ $(count attach ok) == 4 && $(count dispatch ok) == 2 ]]

# Leave an unrelated window alive, then remove just the dedicated pane.
terminal new-window -d -t "=$a" /bin/bash --noprofile --norc
terminal kill-pane -t "$pane"
wait_workers 1
post "/sessions/$a/resume" '{"prompt":"ping"}' | field status | grep -Fx revived
after=$(api "/sessions/$a")
new_pane=$(field runtime pane_id <<<"$after")
[[ $new_pane != "$pane" && $(field harness_session_id <<<"$after") == "$orig" ]]
wait_ping "$new_pane"
[[ $(count attach ok) == 5 && $(count dispatch ok) == 3 ]]
echo 'PASS lifecycle-resume' >&3

phase=lifecycle-stop
post "/sessions/$a/stop" '{}'
wait_workers 1
[[ $(api "/sessions/$b" | field attempt) == "$sibling" ]]
post "/sessions/$a/resume" '{"prompt":"ping"}' | field status | grep -Fx respawned
after=$(api "/sessions/$a")
[[ $(field harness_session_id <<<"$after") == "$orig" ]]
wait_ping "$(field runtime pane_id <<<"$after")"
[[ $(count attach ok) == 6 && $(count dispatch ok) == 4 ]]
[[ $(api "/sessions/$b" | field attempt) == "$sibling" ]]
post "/sessions/$a/stop" '{}'
post "/sessions/$b/stop" '{}'
wait_workers 0
echo 'PASS lifecycle-stop' >&3

phase=clean-stop
docker stop --time 15 "$name"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$name") == 'exited 0' ]]
echo 'PASS clean-stop' >&3
