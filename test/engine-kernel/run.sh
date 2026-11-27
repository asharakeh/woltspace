#!/usr/bin/env bash
set -Eeuo pipefail
exec 3>&1 >/dev/null 2>&1
phase=setup
root=
owned=0
reported=0
failure_line=1
trap 'failure_line=$LINENO' ERR
cleanup() {
    local status=$? failed=0
    trap - EXIT
    trap '' INT TERM
    if (( owned )) && docker image inspect "$image"; then
        docker image rm "$image" || failed=1
        if docker image inspect "$image"; then failed=1; fi  # read back: the owned tag is gone
    fi
    if [[ -n $root ]] && { ! rm -rf -- "$root" || [[ -e $root ]]; }; then failed=1; fi
    if (( failed )); then
        printf '::error::broker-smoke phase=cleanup line=%s\n' "$LINENO" >&3
        exit 1
    fi
    if (( status != 0 && reported == 0 )); then
        printf '::error::broker-smoke phase=%s line=%s\n' "$phase" "$failure_line" >&3
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'failure_line=$LINENO; exit 1' INT TERM
root=$(mktemp -d)
image="engine-kernel:${root##*.}"
phase=image-build
if docker image inspect "$image"; then failure_line=$LINENO; exit 1; fi
owned=1
mkdir "$root/home" "$root/wolts"
HOME="$root/home" XDG_CONFIG_HOME="$root/config" XDG_DATA_HOME="$root/data" \
    WOLTSPACE_WOLTS_DIR="$root/wolts" WOLTSPACE_IMAGE="$image" WOLTSPACE_CONTAINER="engine-kernel-${root##*.}" \
    WOLTSPACE_LOCAL=true WOLTSPACE_NODE_SUDO=false ./woltspace build --local
image_id=$(docker image inspect --format '{{.Id}}' "$image")
curl --fail --silent --show-error --max-time 120 --proto '=https' \
    https://registry.npmjs.org/@openai/codex/-/codex-0.172.0-linux-x64.tgz -o "$root/release.tgz"
prefix=package/vendor/x86_64-unknown-linux-musl/bin
mkdir "$root/fixture"
for name in codex codex-code-mode-host; do
    tar -xOzf "$root/release.tgz" "$prefix/$name" > "$root/fixture/$name"
    chmod 0555 "$root/fixture/$name"
done
rm -- "$root/release.tgz"
cp test/engine-step-zero/worker.py test/engine-kernel/lane.py test/engine-kernel/probe.py \
    test/engine-kernel/fence.py "$root/fixture/"
chmod 0444 "$root"/fixture/*.py
phase=setup
reported=1
python3 -I test/engine-kernel/kernel_host.py "$image_id" "$root/fixture" >&3
