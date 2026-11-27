"""Host driver: one product-image container, two fenced stock Codex lanes. Fixed output only.

Reuses step zero's Run (exact cleanup), exercise() modes and stdio helpers.
"""
import errno
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("stepzero", HERE.parent / "engine-step-zero" / "host.py")
zero = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zero)
FILES = ("codex", "codex-code-mode-host", "worker.py", "lane.py", "probe.py", "fence.py")


class Lanes:
    """Where lane drivers run: `prefix` is [] locally or a docker exec of the lab container."""

    def __init__(self, prefix, python, fixture, state, host_state, workers):
        self.prefix, self.python, self.fixture, self.state = prefix, python, fixture, state
        self.host_state, self.workers = host_state, workers

    def lane(self, *args):
        return [*self.prefix, self.python, "-I", f"{self.fixture}/lane.py", *args]

    def driver(self, lane):
        worker = subprocess.Popen(self.lane("drive", self.fixture, self.state, lane),
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        self.workers.append(worker)
        return worker

    def census(self):
        """Live fixture-recorded members (pid + start time) per lane; no command-line matching."""
        out = subprocess.run(self.lane("census", self.state), stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, check=True, timeout=30).stdout.split()
        assert out[0] == "census"
        return dict(field.split("=") for field in out[1:])


def boot(lanes, names):
    drivers = [lanes.driver(lane) for lane in names]
    for worker in drivers:
        assert zero.select.select([worker.stdout], [], [], 45)[0], "worker deadline"
        abi = worker.stdout.readline().removeprefix("prepared abi=").strip()
        if not (abi.isdigit() and int(abi) >= 6):
            print(f"MEASURE landlock abi={abi if abi.isalnum() else 'none'} kernel={os.uname().release}", flush=True)
            raise AssertionError("landlock abi below 6")
    for worker in drivers:
        zero.tell(worker, "go")
    for worker in drivers:
        zero.expect(worker, "ready")  # only after its fenced probe matched PROBE
    return drivers, int(abi)


def lifecycle(lanes):
    zero.phase = "lifecycle-start"
    for name in ("a", "b", "ctl", "lodge"):
        (lanes.host_state / name).mkdir(mode=0o700)
    (lanes.host_state / "lodge" / "secret").write_text("dummy-lodge-value\n")
    (left, right), abi = boot(lanes, "ab")
    print(f"MEASURE landlock abi={abi} kernel={os.uname().release}", flush=True)
    zero.tell(left, "overlap")
    zero.tell(right, "overlap")
    a_state, b_state = lanes.host_state / "a", lanes.host_state / "b"
    zero.until(lambda: all((state / "arrived").is_file() for state in (a_state, b_state)))
    for state in (a_state, b_state):
        (state / "release").touch()
    zero.expect(left, "complete")
    zero.expect(right, "complete")
    original, sibling = (a_state / "thread").read_text(), (b_state / "thread").read_text()
    assert original != sibling and lanes.census() == {"a": "3", "b": "3"}  # launcher, engine, descendant
    zero.tell(left, "reuse")
    zero.expect(left, "complete")
    assert (a_state / "thread").read_text() == original
    print("PASS lifecycle-start", flush=True)

    zero.phase = "lifecycle-stop"
    stopped = subprocess.run(lanes.lane("stop", lanes.state, "a"), stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, check=True, timeout=30).stdout.split()
    counts = dict(field.split("=") for field in stopped[1:])
    assert stopped[0] == "stopped" and int(counts["tree"]) >= 2 and int(counts["term_survivors"]) >= 1
    assert lanes.census() == {"a": "0", "b": "3"}  # TERM-ignoring descendant gone, sibling whole
    left.stdin.close()  # the trusted driver outlives its engine; end it
    assert left.wait(timeout=10) == 1
    zero.tell(right, "survive")
    zero.expect(right, "complete")
    assert (b_state / "thread").read_text() == sibling
    print(f"PASS lifecycle-stop tree={counts['tree']} term_survivors={counts['term_survivors']}", flush=True)

    zero.phase = "lifecycle-resume"
    (resumed,), _ = boot(lanes, "a")
    zero.tell(resumed, "resume")
    zero.expect(resumed, "complete")
    assert (a_state / "thread").read_text() == original
    for worker in (resumed, right):
        zero.tell(worker, "exit")
        assert worker.wait(timeout=15) == 0
    assert lanes.census() == {"a": "0", "b": "0"}
    print("PASS lifecycle-resume", flush=True)


class Run(zero.Run):
    def create(self, lane, broken=False):
        name = f"{self.root.name}-{lane}"
        assert zero.docker("container", "inspect", name, check=False).returncode != 0
        self.names[name] = None
        state = self.root / lane
        state.mkdir(mode=0o700)
        args = ["create", "--name", name, "--label", self.label, "--network", "none",
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", "256",
                "--entrypoint", "/does-not-exist" if broken else "/bin/sh",
                "--mount", f"type=bind,src={state},dst=/state"]
        for filename in FILES:
            args += ["--mount", f"type=bind,src={self.files / filename},dst=/fixture/{filename},readonly"]
        ident = zero.docker(*args, self.image, "-c", "trap '' TERM; : > /state/armed; exec sleep infinity").stdout.strip()
        assert len(ident) == 64 and all(c in "0123456789abcdef" for c in ident)
        self.names[name] = ident
        info = self.inspect(ident)
        host = info["HostConfig"]
        assert info["Id"] == ident and info["Image"] == self.image
        assert host["NetworkMode"] == "none" and not host["Privileged"] and host["CapDrop"] == ["ALL"]
        assert host["ReadonlyRootfs"] and not host["PortBindings"] and host["PidMode"] == ""
        mounts = {entry["Destination"]: (entry["Source"], entry["RW"]) for entry in info["Mounts"]}
        assert mounts == {"/state": (str(state), True),
                          **{f"/fixture/{f}": (str(self.files / f), False) for f in FILES}}
        return ident, state


def docker_lifecycle(run):
    zero.phase = "lifecycle-start"
    ident, state = run.create("lab")
    run.start(ident, state)
    (state / "armed").unlink()
    lifecycle(Lanes([zero.DOCKER, "exec", "-i", ident], "/usr/bin/python3", "/fixture",
                    "/state", state, run.workers))
    run.inventory(ident)
    assert len(run.processes) >= 1 and zero.docker("top", ident, "-eo", "pid").stdout.count("\n") == 2


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    import fence
    try:
        print(f"MEASURE host landlock abi={fence.abi()}", flush=True)
    except OSError as error:
        print(f"MEASURE host landlock abi={errno.errorcode.get(error.errno, 'other')}", flush=True)
    signal.signal(signal.SIGTERM, zero.terminate)
    signal.signal(signal.SIGINT, zero.terminate)
    zero.Run, zero.lifecycle = Run, docker_lifecycle
    try:
        image, files = sys.argv[1], Path(sys.argv[2]).resolve()
        for name, digest in zip(FILES[:2], (zero.BINARY_SHA256, zero.SIDECAR_SHA256), strict=True):
            with (files / name).open("rb") as stream:
                assert zero.hashlib.file_digest(stream, "sha256").hexdigest() == digest
        assert len(image) == 71 and image.startswith("sha256:")
        for mode in ("success", "failed-start", "interrupt"):
            zero.exercise(image, files, mode)
    except (Exception, KeyboardInterrupt) as error:
        trace, line = error.__traceback__, 1
        while trace is not None:
            if Path(trace.tb_frame.f_code.co_filename).parent == HERE:
                line = trace.tb_lineno
            trace = trace.tb_next
        print(f"::error::broker-smoke phase={zero.phase} line={line}", flush=True)
        sys.exit(1)
