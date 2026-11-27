#!/usr/bin/env bash
set -Eeuo pipefail
exec 3>&1 >/dev/null 2>&1
phase=setup
root=
reported=0
failure_line=1
trap 'failure_line=$LINENO' ERR
cleanup() {
    local status=$?
    trap - EXIT
    trap '' INT TERM
    if [[ -n $root ]] && { ! rm -rf -- "$root" || [[ -e $root ]]; }; then
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
image=python@sha256:1284ed9f6807edb3fb05db99bce501971395b964ea445bc6d19d4eb5712ffeb6
phase=image-build
docker pull --platform linux/amd64 "$image"
image_id=$(docker image inspect --format '{{.Id}}' "$image")
curl --fail --silent --show-error --max-time 120 --proto '=https' \
    https://registry.npmjs.org/@openai/codex/-/codex-0.172.0-linux-x64.tgz -o "$root/release.tgz"
prefix=package/vendor/x86_64-unknown-linux-musl/bin
for name in codex codex-code-mode-host; do
    tar -xOzf "$root/release.tgz" "$prefix/$name" > "$root/$name"
    chmod 0555 "$root/$name"
done
rm -- "$root/release.tgz"
cp test/engine-step-zero/worker.py "$root/worker.py"
chmod 0444 "$root/worker.py"
phase=setup
reported=1
python3 -I test/engine-step-zero/host.py "$image_id" "$root" >&3
