#!/usr/bin/env bash
# Disposable proof of the fixed notice entry: a protected stock Codex Wolt's own shell tool runs the packaged
# telegram-notice helper; the broker and the ordinary connector (a file-backed Telegram stand-in) do the rest.
set -Eeuo pipefail
umask 077
exec 3>&1 >/dev/null 2>&1
root=$(mktemp -d)
run_id=${root##*.}
name=telegram-notice-${run_id,,}
base=$name:base
image=$name:fixture
volume=$name-secrets
pid= container= owned= phase=setup line=1
trap 'line=$LINENO' ERR
cleanup() {
    local status=$? failed=0
    trap - EXIT
    trap '' INT TERM
    if [[ $pid ]]; then kill "$pid" 2>/dev/null || :; wait "$pid" || :; fi
    if [[ $owned ]]; then
        if docker container inspect "$name"; then docker rm -f "$name" || failed=1; fi
        if docker volume inspect "$volume"; then docker volume rm "$volume" || failed=1; fi
        for target in "$image" "$base"; do
            if docker image inspect "$target"; then docker image rm "$target" || failed=1; fi
        done
    fi
    rm -rf -- "$root" || failed=1
    if (( failed )); then phase=cleanup; status=1; fi
    if (( status )); then printf '::error::broker-smoke phase=%s line=%s\n' "$phase" "$line" >&3
    else printf 'PASS cleanup\n' >&3; fi
    exit "$status"
}
trap cleanup EXIT
trap 'line=$LINENO; exit 1' INT TERM
if docker container inspect "$name" || docker volume inspect "$volume" ||
   docker image inspect "$base" || docker image inspect "$image"; then exit 1; fi
owned=1
export HOME="$root/home" WOLTSPACE_WOLTS_DIR="$root/wolts" WOLTSPACE_LOCAL=true
export WOLTSPACE_NODE_SUDO=false WOLTSPACE_CONTAINER="$name"
mkdir -p "$HOME" "$root/install/files" "$root/ledger" "$WOLTSPACE_WOLTS_DIR/.claude"
chmod 755 "$root/ledger"
for wolt in alpha:codex beta:codex gamma:claude delta:codex; do
    mkdir -p "$WOLTSPACE_WOLTS_DIR/${wolt%:*}/wolt"
    printf '{"name":"%s","type":"beaver","harness":"%s"}\n' "${wolt%:*}" "${wolt#*:}" \
        >"$WOLTSPACE_WOLTS_DIR/${wolt%:*}/wolt/wolt.json"
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
cp test/ordinary-stock-fixture/{fence,lane,worker,probe}.py "$root/install/files/"
cp test/telegram-broker-fixture/telegram.py "$root/install/"
chmod 0755 "$root/install/files"  # worker 991 traverses it to run the engine
chmod 0644 "$root/install/files/probe.py" "$root/install/telegram.py"  # the unprivileged entries: worker, node
printf 'stock-fixture\n' >"$root/install/stock-fixture"
cat >"$root/install/Dockerfile" <<DOCKER
FROM $base
COPY --chown=0:0 files/ /usr/local/lib/woltspace-stock-fixture/
COPY --chown=0:0 stock-fixture /etc/woltspace/stock-fixture
COPY --chown=0:0 telegram.py /opt/fixture/telegram.py
RUN set -e; test -x /usr/bin/telegram-notice; p=/workspace/woltspace/container/connectors/telegram; \\
    mv "\$p/telegram_connector.py" "\$p/telegram_real.py"; cp /opt/fixture/telegram.py "\$p/telegram_connector.py"; \\
    for f in "\$p/telegram_connector.py" /usr/local/lib/woltspace-stock-fixture/probe.py; do \\
        test "\$(stat -c %a "\$f")" = 644; done; \\
    printf 'dummy\\ntelegram\\n' >/etc/woltspace/broker-dummy
DOCKER
docker build --network none --tag "$image" "$root/install"

inside() { docker exec -u 0 "$container" "$@"; }
api() { docker exec --user node "$container" curl --noproxy '*' -fsS --max-time 25 "http://127.0.0.1:7777$1"; }
post() { docker exec --user node "$container" curl --noproxy '*' -fsS --max-time 25 \
    -H 'content-type: application/json' -d "$2" "http://127.0.0.1:7777$1"; }
field() {
    python3 -c 'import json,sys; v=json.load(sys.stdin)
for k in sys.argv[1:]: v=v[k]
print(v)' "$@"
}
wait_for() {
    local deadline=$((SECONDS + 40))
    until "$@"; do (( SECONDS < deadline )) || return 1; sleep .2; done
}
pane_count() {  # how many times the pane shows exactly this line
    docker exec --user node "$container" env -i PATH=/usr/bin:/bin tmux -S "/tmp/tmux-$(id -u)/default" \
        capture-pane -p -t "$1" | grep -Fxc "$2" || :
}
shows() { [[ $(pane_count "$1" "$2") == "$3" ]]; }
admin() { WOLTSPACE_IMAGE="$image" WOLTSPACE_FEATURE_ISOLATION=true ./woltspace secrets "$@" 3>&-; }
ok() { [[ $(admin "$@" | field result) == ok ]]; }
accepts() { [[ $(cat "$root/ledger/accepts" 2>/dev/null | wc -l) == "$1" ]]; }
arm_state() {
    inside /opt/woltspace/tools/woltspace/bin/python -I -c '
import sqlite3, sys
db = sqlite3.connect("file:/var/lib/woltspace-secrets/registry.db?mode=ro", uri=True)
print(db.execute("SELECT result FROM audit WHERE op = ?", (sys.argv[1],)).fetchone()[0])' "$1"
}
handoff() {
    inside awk '$6=="03" && $8=="/run/woltspace-broker/effect.sock" {found=1} END {exit !found}' /proc/net/unix
}
state_of() {  # the protected state dir of a session's current launch
    local row principal conversation
    row=$(api "/sessions/$1")
    conversation=$(field harness_session_id <<<"$row")
    principal=$(inside sh -c 'ls -d /run/woltspace-engine/*/"$1"' sh "$conversation")
    [[ $principal == /run/woltspace-engine/p-*/"$conversation" ]]
    printf '%s\n' "$principal"
}
engine_of() {  # the stock engine whose cwd is that launch's home
    inside sh -c 'for p in $(pgrep -f "codex app-server"); do
        [ "$(readlink /proc/$p/cwd)" = "$1/home" ] && echo "$p"; done' sh "$1"
}

phase=boot
docker volume create "$volume"
container=$(docker create --name "$name" --network none --security-opt no-new-privileges \
    -e WOLTSPACE_FEATURE_ISOLATION=true -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -e ENABLE_TELEGRAM_BOT=true -e TELEGRAM_ALLOWED_USERS=42 -e TELEGRAM_BOT_TOKEN=fixture-only \
    -v "$volume:/var/lib/woltspace-secrets" -v "$WOLTSPACE_WOLTS_DIR:/workspace/wolts:rw" \
    -v "$WOLTSPACE_WOLTS_DIR/.claude:/home/node/.claude:rw" -v "$root/ledger:/fixture" "$image")
[[ $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container") == none ]]
docker start "$container"
wait_for api /health
wait_for handoff
[[ $(inside stat -c '%U:%G %a' /usr/bin/telegram-notice) == 'root:root 755' ]]  # the shipped helper
docker exec -i -u 0 "$container" sh -ec '  # ordinary (unfenced) engines leave a marker if they ever start
    stand_in=$(cat)
    for engine in /home/node/.local/bin/claude /usr/local/bin/codex; do
        rm -f "$engine"; printf "%s\n" "$stand_in" >"$engine"; chmod 0755 "$engine"
    done
' <<'ENGINE'
#!/bin/sh
printf 'started\n' >.ordinary-engine  # in the cwd: a launch's Wolt dir, never checked for lodge probes
exit 1
ENGINE
ok enroll alpha
ok enroll beta
ok register telegram.notice
ok grant alpha telegram.notice
echo 'PASS boot' >&3

phase=unfenced  # unenrolled Wolts with ordinary engines start nothing on create or on a real resume
status_of() {  # HTTP status only: no response text is kept
    docker exec --user node "$container" curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 25 \
        -H 'content-type: application/json' -d "$2" "http://127.0.0.1:7777$1"
}
rows_of() {
    api /sessions | python3 -c 'import json,sys
print(" ".join(sorted(r["status"] for r in json.load(sys.stdin) if r.get("wolt") == sys.argv[1])))' "$1"
}
gates() {  # the broker's audited launch-open decisions so far
    inside /opt/woltspace/tools/woltspace/bin/python -I -c '
import sqlite3
db = sqlite3.connect("file:/var/lib/woltspace-secrets/registry.db?mode=ro", uri=True)
print(db.execute("SELECT count(*) FROM audit WHERE op = ?", ("launch-open",)).fetchone()[0])'
}
gamma=$(status_of /sessions/new/lodge '{"wolt":"gamma"}')
[[ $gamma =~ ^4[0-9][0-9]$ && $(rows_of gamma) =~ ^(|stopped)$ ]]  # claude: refused before any launch
delta=$(status_of /sessions/new/lodge '{"wolt":"delta"}')
[[ $delta != 200 && $(rows_of delta) == stopped ]]  # codex: refused at the protected launch gate
d=$(api /sessions | python3 -c 'import json,sys
print(next(r["name"] for r in json.load(sys.stdin) if r.get("wolt") == "delta"))')
before=$(gates)
resume=$(status_of "/sessions/$d/resume" '{"prompt":"fixture-notice"}')
(( $(gates) == before + 1 ))  # the resume really reached the gate, and was refused there
[[ $(rows_of delta) == stopped ]]
for wolt in gamma delta; do [[ ! -e $WOLTSPACE_WOLTS_DIR/$wolt/.ordinary-engine ]]; done
census=0  # pgrep: 1 is "no match"; a match (0), a pgrep error (2, 3) or a docker error (125+) all fail
inside pgrep -f '/home/node/.local/bin/claude|/usr/local/bin/codex' || census=$?
(( census == 1 ))
printf 'PASS unfenced refused (gamma create=%s rows=%s; delta create=%s resume=%s)\n' \
    "$gamma" "$(rows_of gamma)" "$delta" "$resume" >&3

phase=unarmed
a=$(post /sessions/new/lodge '{"wolt":"alpha","prompt":"fixture-notice"}' | field name)
a_pane=$(api "/sessions/$a" | field runtime pane_id)
wait_for shows "$a_pane" 'fixture notice unavailable' 1
accepts 0
echo 'PASS unarmed' >&3

phase=positive
touch "$root/ledger/return"
first=$(admin arm telegram.notice | field id)
post "/sessions/$a/resume" '{"prompt":"fixture-notice"}'
wait_for shows "$a_pane" 'fixture notice ok' 1
accepts 1
[[ $(arm_state "$first") == ok ]]
post "/sessions/$a/resume" '{"prompt":"fixture-notice"}'  # spent
wait_for shows "$a_pane" 'fixture notice unavailable' 2
accepts 1
echo 'PASS positive and spent' >&3

phase=sibling
second=$(admin arm telegram.notice | field id)
b=$(post /sessions/new/lodge '{"wolt":"beta","prompt":"fixture-notice"}' | field name)
b_pane=$(api "/sessions/$b" | field runtime pane_id)
wait_for shows "$b_pane" 'fixture notice denied' 1
a_state=$(state_of "$a")
b_state=$(state_of "$b")
a_engine=$(engine_of "$a_state")
[[ $a_engine =~ ^[1-9][0-9]*$ ]]
printf '%s %s /usr/bin/telegram-notice 7777\n' "$a_state/action" "$a_engine" | \
    inside sh -c 'cat >"$1/home/probe-target"; chown 991:991 "$1/home/probe-target"' sh "$b_state"
post "/sessions/$b/resume" '{"prompt":"fixture-probe"}'
wait_for shows "$b_pane" 'fixture complete' 1
[[ $(inside cat "$b_state/home/probe-result") == fenced ]]
[[ $(arm_state "$second") == armed ]] && accepts 1
echo 'PASS sibling denied and fenced' >&3

phase=node  # trusted for session input and the connector, but never A's private endpoint
docker exec --user node "$container" /opt/woltspace/tools/woltspace/bin/python -I -c '
import os, sys
for path, flags in ((sys.argv[1] + "/request", os.O_WRONLY), (sys.argv[1] + "/reply", os.O_RDONLY)):
    try:
        os.close(os.open(path, flags | os.O_NONBLOCK))
        raise SystemExit("node opened " + path)
    except PermissionError:
        pass
' "$a_state/action"
[[ $(arm_state "$second") == armed ]] && accepts 1
echo 'PASS node cannot open the endpoint' >&3

phase=stale  # a descriptor held past stop reaches nothing on the fresh launch
inside /opt/woltspace/tools/woltspace/bin/python -I -c '
import os, sys, time
fd = os.open(sys.argv[1] + "/request", os.O_WRONLY | os.O_NONBLOCK)
open("/run/stale-ready", "w").close()
while not os.path.exists("/run/stale-go"):
    time.sleep(.05)
try:
    os.write(fd, b"n")
    result = "written"
except BrokenPipeError:
    result = "refused"
open("/run/stale-result", "w").write(result)
' "$a_state/action" &
pid=$!
wait_for inside test -e /run/stale-ready
post "/sessions/$a/stop" '{}' | field status | grep -Fx stopped
post "/sessions/$a/resume" '{"prompt":"fixture-reuse"}'
a_pane=$(api "/sessions/$a" | field runtime pane_id)  # the fresh launch's pane
wait_for shows "$a_pane" 'fixture complete' 1
inside touch /run/stale-go
wait "$pid"
pid=
[[ $(inside cat /run/stale-result) == refused ]]
[[ $(arm_state "$second") == armed ]] && accepts 1
echo 'PASS stale descriptor refused' >&3

phase=fresh-positive  # the separately armed operation, on the fresh launch
post "/sessions/$a/resume" '{"prompt":"fixture-notice"}'
wait_for shows "$a_pane" 'fixture notice ok' 1
accepts 2
[[ $(arm_state "$second") == ok ]]
echo 'PASS fresh launch positive' >&3

phase=stop-pending  # a stalled connector cannot hold the ordinary stop past its receipt budget
rm -f "$root/ledger/return"
third=$(admin arm telegram.notice | field id)
post "/sessions/$a/resume" '{"prompt":"fixture-notice"}'
wait_for accepts 3  # the stand-in took it and now hangs
started=$SECONDS
post "/sessions/$a/stop" '{}' | field status | grep -Fx stopped
(( SECONDS - started <= 12 ))
[[ -z $(inside find "$a_state" -name action) && -z $(engine_of "$a_state") ]]
settled() { [[ $(arm_state "$third") == unknown ]]; }
wait_for settled  # spent and ambiguous, never replayed
accepts 3
echo 'PASS stop during a stalled notice' >&3

phase=finish
post "/sessions/$b/stop" '{}' | field status | grep -Fx stopped
[[ -z $(inside find /run/woltspace-engine -name action) ]]
docker stop --time 15 "$container"
[[ $(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$container") == 'exited 0' ]]
docker rm "$container"
container=
accepts 3
printf 'PASS notice entry: unfenced refused, unarmed, one accept per arm, sibling and node fenced, stale refused\n' >&3
