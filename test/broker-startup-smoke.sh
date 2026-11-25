#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|forced-stop-resume|clean-stop|cleanup|start-port-conflict|start-permission|start-id-init|start-oom|start-early-exit|start-docker-run|start-launcher-exit|start-unknown|start-missing-file|start-import-error|start-init-command) ;;
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
phase=setup

cleanup() {
    local status=$? cleaned=0
    trap - EXIT
    # Only remove the container and image that this run attempted to create.
    if [[ ${owned:-false} == true ]]; then
        if docker container inspect "$name" >/dev/null; then
            docker rm -f "$name" || cleaned=1
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
if docker container inspect "$name" || docker image inspect "$WOLTSPACE_IMAGE"; then failure_line=$LINENO; exit 1; fi
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

# Raw launcher output and xtrace stay in the private run root, then cleanup removes them.
# Categories are evidence hints, not a claim that the underlying cause is proven.
start_diagnostic() {
    local state category source_line
    state=$(docker inspect -f '{{.State.Running}} {{.State.ExitCode}} {{.State.OOMKilled}}' "$name" 2>/dev/null) || state=''
    read -r category source_line < <(python3 - "$root/start.out" "$root/start.trace" "$state" <<'PYDIAG'
import pathlib, re, sys
output = pathlib.Path(sys.argv[1]).read_text(errors="replace").lower()
trace = pathlib.Path(sys.argv[2]).read_text(errors="replace")
state = sys.argv[3].split()
commands = re.findall(r"^\++broker-launcher:([1-9][0-9]{0,5}): (.*)$", trace, re.M)
line, last = commands[-1] if commands else ("1", "")
category = "start-unknown"
if len(state) == 3 and state[2] == "true":
    category = "start-oom"
elif any(text in output for text in ("port is already allocated", "address already in use")):
    category = "start-port-conflict"
elif any(text in output for text in ("invalid user", "invalid group", "usermod:", "groupmod:", "uid_map", "gid_map")):
    category = "start-id-init"
elif any(text in output for text in ("permission denied", "operation not permitted", "permissionerror:", "cannot connect to the docker daemon")):
    category = "start-permission"
elif "filenotfounderror:" in output:
    category = "start-missing-file"
elif "modulenotfounderror:" in output or "importerror:" in output:
    category = "start-import-error"
elif "container_entrypoint.py" in output and "subprocess.calledprocesserror:" in output:
    category = "start-init-command"
elif len(state) == 3 and state[0] == "false" and state[1].isdigit():
    category = "start-early-exit"
elif last.startswith("docker run "):
    category = "start-docker-run"
elif len(state) == 3 and state[0] == "true":
    category = "start-launcher-exit"
print(category, line)
PYDIAG
    ) || { category=start-unknown; source_line=1; }
    annotate_failure "${category:-start-unknown}" "${source_line:-1}"
}

phase=flag-off
printf 'DEV_MODE=false\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
start_line=$((LINENO + 1))
(umask 077; PS4='+broker-launcher:${LINENO}: ' BASH_XTRACEFD=4 bash -x ./woltspace start 4>"$root/start.trace" >"$root/start.out" 2>&1) || {
    status=$?
    failure_line=$start_line
    start_diagnostic
    exit "$status"
}
health
./woltspace stop
[[ -z $(docker ps -aq --filter "name=^/${name}$") ]]
echo 'PASS flag-off' >&3
