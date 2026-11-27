#!/usr/bin/env bash
set -Eeuo pipefail
exec 3>&1 >/dev/null 2>&1
phase=setup
line=1
root=
owned=0
container=
trap 'line=$LINENO' ERR
cleanup() {
    local status=$? failed=0
    trap - EXIT
    trap '' INT TERM
    if (( owned )); then
        if [[ -n $container ]]; then docker rm -f "$container" || failed=1; fi
        if docker volume inspect "$volume"; then docker volume rm "$volume" || failed=1; fi
        for tag in "$image" "$base"; do
            if docker image inspect "$tag"; then docker image rm "$tag" || failed=1; fi
        done
        local remaining
        remaining=$(docker ps -aq --filter "name=^/${name}$") || failed=1
        [[ -z $remaining ]] || failed=1
        remaining=$(docker volume ls -q --filter "name=^${volume}$") || failed=1
        [[ -z $remaining ]] || failed=1
    fi
    if [[ -n $root ]]; then
        rm -rf -- "$root" || failed=1
        [[ ! -e $root ]] || failed=1
    fi
    if (( failed )); then
        printf '::error::broker-smoke phase=cleanup line=%s\n' "$LINENO" >&3
        exit 1
    fi
    if (( status )); then
        printf '::error::broker-smoke phase=%s line=%s\n' "$phase" "$line" >&3
    else
        printf 'PASS cleanup\n' >&3
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'line=$LINENO; exit 1' INT TERM
root=$(mktemp -d)
suffix=${root##*.}
name="ordinary-stock-$suffix"
volume="$name-secrets"
base="ordinary-stock-base:$suffix"
image="ordinary-stock:$suffix"
if docker container inspect "$name" || docker volume inspect "$volume" ||
   docker image inspect "$base" || docker image inspect "$image"; then exit 1; fi
owned=1
export HOME="$root/home" WOLTSPACE_WOLTS_DIR="$root/wolts" WOLTSPACE_LOCAL=true
export WOLTSPACE_NODE_SUDO=false WOLTSPACE_CONTAINER="$name"
mkdir -p "$HOME" "$root/install/files" "$WOLTSPACE_WOLTS_DIR/.claude"
for wolt in alpha beta; do
    mkdir -p "$WOLTSPACE_WOLTS_DIR/$wolt/wolt"
    printf '{"name":"%s","type":"beaver","harness":"codex"}\n' "$wolt" >"$WOLTSPACE_WOLTS_DIR/$wolt/wolt/wolt.json"
done
printf 'DEV_MODE="true"\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"

phase=image-build
WOLTSPACE_IMAGE="$base" ./woltspace build --local
curl -fsS --max-time 120 --proto '=https' \
    https://registry.npmjs.org/@openai/codex/-/codex-0.172.0-linux-x64.tgz -o "$root/release.tgz"
for file in codex codex-code-mode-host; do
    tar -xOzf "$root/release.tgz" "package/vendor/x86_64-unknown-linux-musl/bin/$file" >"$root/install/files/$file"
    chmod 0555 "$root/install/files/$file"
done
(cd "$root/install/files" && sha256sum -c <<'HASHES'
ad83b94c093f0cdd8176a6bc8005a461bdf23a759863e157d40f562b8a9d664d  codex
1800682c85429ff546b23a1aa96b5c1405fe74ac6743690d89d6dc5cfaf3b4f1  codex-code-mode-host
HASHES
)
cp test/ordinary-stock-fixture/{fence,lane,worker}.py "$root/install/files/"
printf 'stock-fixture\n' >"$root/install/stock-fixture"
printf 'FROM %s\nCOPY --chown=0:0 files/ /usr/local/lib/woltspace-stock-fixture/\nCOPY --chown=0:0 stock-fixture /etc/woltspace/stock-fixture\n' "$base" >"$root/install/Dockerfile"
docker build --network none --tag "$image" "$root/install"

api() {
    local route=$1
    shift
    docker exec --user node "$container" curl --noproxy '*' -fsS --max-time 25 "$@" "http://127.0.0.1:7777$route"
}
post() { api "$1" -H 'content-type: application/json' -d "$2"; }
field() {
    python3 -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v)' "$@"
}
wait_for() {
    local deadline=$((SECONDS + 24))
    until "$@"; do (( SECONDS < deadline )) || return 1; sleep .2; done
}
screen_has() {
    docker exec --user node "$container" env -i PATH=/usr/bin:/bin tmux \
        -S "/tmp/tmux-$(id -u)/default" capture-pane -p -t "$1" | grep -Fx "$2"
}
admin() { WOLTSPACE_IMAGE="$image" WOLTSPACE_FEATURE_ISOLATION=true ./woltspace secrets "$@" 3>&-; }

boot() {
    local isolation=$1 wolts=$2
    local -a mounts=()
    if [[ $isolation == true ]]; then
        docker volume create "$volume"
        mounts+=(-v "$volume:/var/lib/woltspace-secrets")
    fi
    container=$(docker create --name "$name" --network none --security-opt no-new-privileges \
        -e WOLTSPACE_FEATURE_ISOLATION="$isolation" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
        "${mounts[@]}" -v "$wolts:/workspace/wolts:rw" \
        -v "$wolts/.claude:/home/node/.claude:rw" "$image")
    [[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container") == none ]]
    docker start "$container"
    wait_for api /health
}
finish_container() {
    docker stop --time 15 "$container"
    [[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$container") == 'exited 0' ]]
    docker rm "$container"
    local remaining
    remaining=$(docker ps -aq --no-trunc --filter "id=$container")
    [[ -z $remaining ]]
    container=
}
terminal() {
    docker exec --user node "$container" env -i PATH=/usr/bin:/bin tmux \
        -S "/tmp/tmux-$(id -u)/default" "$@"
}

phase=flag-off
mkdir -p "$root/flag-off/.claude"
cp "$WOLTSPACE_WOLTS_DIR/.env" "$root/flag-off/.env"
boot false "$root/flag-off"
docker exec -i -u 0 "$container" sh -ec '
    engine=/home/node/.local/bin/claude
    [ -e "$engine" ] || [ -L "$engine" ]
    rm -f "$engine"
    cat >"$engine"
    chmod 0755 "$engine"
' <<'ENGINE'
#!/bin/sh
[ -t 0 ] || exit 0
printf 'started\n' >.ordinary-engine
while :; do sleep 60; done
ENGINE
post /sessions/new/create '{"name":"control","type":"beaver"}'
wait_for test -s "$root/flag-off/control/.ordinary-engine"
docker exec -u 0 "$container" sh -ec '
    test -f /etc/woltspace/stock-fixture
    test ! -e /run/woltspace-launch.sock
    test ! -e /run/woltspace-engine
    test ! -e /var/lib/woltspace-broker
'
[[ -z $(docker volume ls -q --filter "name=^${volume}$") ]]
finish_container
echo 'PASS flag-off' >&3

phase=flag-on
boot true "$WOLTSPACE_WOLTS_DIR"
if post /sessions/new/lodge '{"wolt":"alpha"}'; then exit 1; fi
admin enroll alpha
admin enroll beta
admin register dummy.ping
admin grant alpha dummy.ping
echo 'PASS flag-on' >&3

# Inventory only the in-container broker's actual socket handles, once it has
# processed the admin request. No descriptor duplication or broker state mutation.
broker_pid=$(docker exec "$container" ps -eo pid=,uid= | awk '$2 == 990 {print $1}')
[[ $broker_pid =~ ^[1-9][0-9]*$ ]]
broker_sockets() {
    docker exec --user 990:990 "$container" sh -ec '
        test -r "/proc/$1/fd"
        test -x "/proc/$1/fd"
        for fd in /proc/"$1"/fd/*; do
            target=$(readlink "$fd") || continue
            case "$target" in socket:\[*\]) printf "%s\n" "$target";; esac
        done
    ' sh "$broker_pid" | sort -u
}
phase=lifecycle-start
broker_sockets >"$root/broker-before"
[[ $(wc -l <"$root/broker-before") -ge 3 ]]
a=$(post /sessions/new/lodge '{"wolt":"alpha","prompt":"fixture-overlap"}' | field name)
broker_sockets >"$root/broker-alpha"
old_socket=$(comm -13 "$root/broker-before" "$root/broker-alpha")
[[ $old_socket =~ ^socket:\[[0-9]+\]$ ]]
b=$(post /sessions/new/lodge '{"wolt":"beta","prompt":"fixture-overlap"}' | field name)
[[ $a != "$b" ]]
broker_sockets >"$root/broker-both"
sibling_socket=$(comm -13 "$root/broker-alpha" "$root/broker-both")
[[ $sibling_socket =~ ^socket:\[[0-9]+\]$ && $sibling_socket != "$old_socket" ]]
a_row=$(api "/sessions/$a")
original=$(field harness_session_id <<<"$a_row")
attempt=$(field attempt <<<"$a_row")
a_pane=$(field runtime pane_id <<<"$a_row")
b_row=$(api "/sessions/$b")
b_pane=$(field runtime pane_id <<<"$b_row")
b_attempt=$(field attempt <<<"$b_row")
arrived() {
    [[ $(docker exec -u 0 "$container" find /run/woltspace-engine -name arrived -type f | wc -l) == 2 ]]
}
wait_for arrived
docker exec -u 0 "$container" find /run/woltspace-engine -name arrived -type f \
    -execdir touch release ';'
wait_for screen_has "$a_pane" 'fixture complete'
wait_for screen_has "$b_pane" 'fixture complete'
post "/sessions/$a/resume" '{"prompt":"ping"}'
post "/sessions/$b/resume" '{"prompt":"ping"}'
wait_for screen_has "$a_pane" 'dummy ok'
wait_for screen_has "$b_pane" 'dummy refused'
[[ $(api "/sessions/$a" | field attempt) == "$attempt" ]]
echo 'PASS lifecycle-start' >&3

phase=lifecycle-stop
post "/sessions/$a/stop" '{}' | field status | grep -Fx stopped
old_channel_retired() {
    local current
    current=$(broker_sockets) || return
    grep -Fxq "$sibling_socket" <<<"$current" && ! grep -Fxq "$old_socket" <<<"$current"
}
wait_for old_channel_retired
echo 'PASS broker retirement' >&3
post "/sessions/$b/resume" '{"prompt":"fixture-survive"}'
sibling_replied() {
    local lines
    lines=$(screen_has "$b_pane" 'fixture complete') || return
    [[ $(wc -l <<<"$lines") == 2 ]]
}
wait_for sibling_replied
[[ $(api "/sessions/$b" | field attempt) == "$b_attempt" ]]
echo 'PASS lifecycle-stop' >&3

phase=lifecycle-resume
post "/sessions/$a/resume" '{"prompt":"fixture-resume"}'
a_row=$(api "/sessions/$a")
[[ $(field harness_session_id <<<"$a_row") == "$original" && $(field attempt <<<"$a_row") != "$attempt" ]]
wait_for screen_has "$(field runtime pane_id <<<"$a_row")" 'fixture complete'
docker exec --user node "$container" /opt/woltspace/tools/woltspace/bin/python -I -c '
import sys
from woltspace.protected_launcher import reap_status
assert reap_status(sys.argv[1], sys.argv[2], 1) == "unavailable"
' "$a" "$attempt"
post "/sessions/$a/stop" '{}' | field status | grep -Fx stopped
post "/sessions/$b/stop" '{}' | field status | grep -Fx stopped
echo 'PASS lifecycle-resume' >&3

phase=lifecycle-stop
# Start a fresh turn whose fixed endpoint waits for release, then drop its
# dedicated bridge while the request is pending. Let the ordinary stop API
# observe the exact receipt after the pane no longer exists.
c=$(post /sessions/new/lodge '{"wolt":"alpha","prompt":"fixture-overlap"}' | field name)
c_row=$(api "/sessions/$c")
c_uuid=$(field harness_session_id <<<"$c_row")
c_pane=$(field runtime pane_id <<<"$c_row")
turn_pending() {
    local matches
    matches=$(docker exec -u 0 "$container" find /run/woltspace-engine \
        -path "*/$c_uuid/control/arrived" -type f) || return
    [[ -n $matches ]]
}
wait_for turn_pending
terminal kill-pane -t "$c_pane"
post "/sessions/$c/stop" '{}' | field status | grep -Fx stopped
no_broker_workers() {
    local current
    current=$(broker_sockets) || return
    [[ $current == "$(cat "$root/broker-before")" ]]
}
wait_for no_broker_workers
finish_container
echo 'PASS controlled interruption' >&3
