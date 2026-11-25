#!/usr/bin/env bash
set -Eeuo pipefail

exec 3>&1 >/dev/null 2>&1
failure_line=1
annotate_failure() {
    local failed_phase=$1 source_line=$2
    case "$failed_phase" in
        setup|image-build|flag-off|flag-on|forced-stop-resume|clean-stop|cleanup) ;;
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

phase=flag-off
printf 'DEV_MODE=false\nWOLTSPACE_PUBLIC_TUNNEL=false\n' >"$WOLTSPACE_WOLTS_DIR/.env"
./woltspace start
health
./woltspace stop
[[ -z $(docker ps -aq --filter "name=^/${name}$") ]]
echo 'PASS flag-off' >&3
