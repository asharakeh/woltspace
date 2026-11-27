"""Local lane of the kernel fixture: same lifecycle, plain subprocesses instead of docker exec."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kernel_host  # noqa: E402
import lane  # noqa: E402

BIN = Path("/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/"
           "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin")


@pytest.mark.skipif(not (BIN / "codex").is_file(), reason="stock codex not installed")
def test_two_fenced_stock_lanes(tmp_path):
    assert hashlib.sha256((BIN / "codex").read_bytes()).hexdigest() == kernel_host.zero.BINARY_SHA256
    fixture, state = tmp_path / "fixture", tmp_path / "state"
    fixture.mkdir()
    state.mkdir()
    for name in ("codex", "codex-code-mode-host"):
        (fixture / name).symlink_to(BIN / name)
    for source in ("lane.py", "probe.py", "fence.py", "../engine-step-zero/worker.py"):
        shutil.copy(HERE / source, fixture)
    lanes = kernel_host.Lanes([], os.path.realpath(sys.executable), str(fixture), str(state), state, [])
    try:
        kernel_host.lifecycle(lanes)
    finally:
        for worker in lanes.workers:
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=5)
        for name in "ab":
            control = state / "ctl" / f"{name}.json"
            launcher = json.loads(control.read_text()).get("launcher") if control.exists() else None
            if launcher and launcher in lane.tree(1)[1] and lane.tree(1)[1][launcher][1] != "Z":
                lane.kill_tree(launcher)
    assert lanes.engines() == 0
