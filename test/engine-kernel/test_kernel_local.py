"""Local lane of the kernel fixture: same lifecycle, plain subprocesses instead of docker exec."""
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kernel_host  # noqa: E402
import lane  # noqa: E402

BIN = Path("/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/"
           "codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin")
pytestmark = pytest.mark.skipif(not (BIN / "codex").is_file(), reason="stock codex not installed")


@contextlib.contextmanager
def adopted():
    """This process is a child subreaper meanwhile: any orphan becomes our own, stable child.
    On exit, children left must end within 5 s by themselves; after that every child, including
    ones adopted later, is killed and listed until none remain."""
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    escaped = []
    try:
        yield escaped
    finally:
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                continue
            if time.monotonic() > deadline:
                for task in os.listdir("/proc/self/task"):
                    with open(f"/proc/self/task/{task}/children") as children:
                        for child in map(int, children.read().split()):
                            if child not in escaped:
                                escaped.append(child)
                            os.kill(child, 9)  # our unreaped child: the pid cannot be reused
            time.sleep(.05)
        ctypes.CDLL(None).prctl(36, 0, 0, 0, 0)


def lanes_for(tmp_path):
    assert hashlib.sha256((BIN / "codex").read_bytes()).hexdigest() == kernel_host.zero.BINARY_SHA256
    fixture, state = tmp_path / "fixture", tmp_path / "state"
    fixture.mkdir()
    state.mkdir()
    for name in ("codex", "codex-code-mode-host"):
        (fixture / name).symlink_to(BIN / name)
    for source in ("lane.py", "probe.py", "fence.py", "../engine-step-zero/worker.py"):
        shutil.copy(HERE / source, fixture)
    return kernel_host.Lanes([], os.path.realpath(sys.executable), str(fixture), str(state), state, [])


def end(lanes):
    for worker in lanes.workers:  # Popen handles we own
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)
    for control in (lanes.host_state / "ctl").glob("?.json"):
        if control.is_file():  # never open the early-failure FIFO
            lane.reclaim(json.loads(control.read_text()))  # identity-checked; stale records signal nothing


def test_two_fenced_stock_lanes(tmp_path):
    lanes = lanes_for(tmp_path)
    with adopted() as escaped:
        try:
            kernel_host.lifecycle(lanes)
        finally:
            end(lanes)
    assert escaped == []


def test_driver_death_before_publication_starts_nothing(tmp_path):
    lanes = lanes_for(tmp_path)
    for name in ("a", "ctl", "lodge"):
        (lanes.host_state / name).mkdir()
    (lanes.host_state / "ctl" / "b.json").write_text(json.dumps({"port": 9, "pid": os.getpid()}))
    with adopted() as escaped:
        try:
            worker = lanes.driver("a")
            assert worker.stdout.readline().startswith("prepared abi=")
            record = lanes.host_state / "ctl" / "a.json"
            record.unlink()
            os.mkfifo(record)  # the launcher record write now blocks: no reader
            zero = kernel_host.zero
            zero.tell(worker, "go")
            zero.until(lambda: Path(f"/proc/{worker.pid}/syscall").read_text().startswith("257 "))
            worker.kill()  # driver dies mid-publication, its teardown never runs
            worker.wait(timeout=5)
        finally:
            end(lanes)
    assert escaped == []
    assert not (lanes.host_state / "a" / "probe").exists()
    assert not list((lanes.host_state / "a").rglob("*.jsonl"))


def test_stale_record_signals_nothing():
    child = kernel_host.subprocess.Popen(["/bin/sleep", "30"])  # owned stand-in reusing a recorded pid
    try:
        lane.reclaim({"launcher": child.pid, "start": "1", "members": [[child.pid, "1"]]})
        assert lane.born(child.pid) is not None and child.poll() is None
    finally:
        child.kill()
        child.wait(timeout=5)
