"""Host-side Docker lifecycle driver. Output contains only fixed phases."""
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time


BINARY_SHA256 = "ad83b94c093f0cdd8176a6bc8005a461bdf23a759863e157d40f562b8a9d664d"
SIDECAR_SHA256 = "1800682c85429ff546b23a1aa96b5c1405fe74ac6743690d89d6dc5cfaf3b4f1"
FILES = ("codex", "codex-code-mode-host", "worker.py")
DOCKER = "/usr/bin/docker"
LABEL = "org.woltspace.engine-proof"
phase = "setup"


class Interrupted(Exception):
    pass


def terminate(*_):
    raise Interrupted


def docker(*args, check=True):
    return subprocess.run([DOCKER, *args], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, check=check, timeout=30)


def until(predicate):
    deadline = time.monotonic() + 25
    while not predicate():
        assert time.monotonic() < deadline, "readiness deadline"
        time.sleep(.025)


def expect(worker, expected):
    assert select.select([worker.stdout], [], [], 45)[0], "worker deadline"
    assert worker.stdout.readline() == expected + "\n", "worker phase mismatch"


def tell(worker, command):
    worker.stdin.write(command + "\n")
    worker.stdin.flush()


class Run:
    def __init__(self, image, files):
        self.root = Path(tempfile.mkdtemp(prefix="engine-zero-"))
        self.image = image
        self.files = files
        self.label = f"{LABEL}={self.root.name}"
        self.names = {}
        self.workers = []
        self.processes = set()

    def matching(self, kind):
        command = {"container": ("ls", "-aq"), "network": ("ls", "-q"),
                   "volume": ("ls", "-q")}[kind]
        return docker(kind, *command, "--filter", f"label={self.label}").stdout.split()

    def inspect(self, container):
        return json.loads(docker("container", "inspect", container).stdout)[0]

    def create(self, lane, broken=False):
        name = f"{self.root.name}-{lane}"
        assert docker("container", "inspect", name, check=False).returncode != 0
        self.names[name] = None
        state = self.root / lane
        state.mkdir(mode=0o700)
        args = [
            "create", "--name", name, "--label", self.label, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", f"{os.getuid()}:{os.getgid()}", "--pids-limit", "128",
            "--mount", f"type=bind,src={state},dst=/state",
        ]
        for filename in FILES:
            args += ["--mount", f"type=bind,src={self.files / filename},dst=/fixture/{filename},readonly"]
        command = ["/does-not-exist"] if broken else [
            "/bin/sh", "-c", "trap '' TERM; : > /state/armed; exec sleep infinity",
        ]
        ident = docker(*args, self.image, *command).stdout.strip()
        assert len(ident) == 64 and all(c in "0123456789abcdef" for c in ident)
        self.names[name] = ident
        info = self.inspect(ident)
        assert info["Id"] == ident and info["Image"] == self.image
        host = info["HostConfig"]
        assert host["NetworkMode"] == "none" and not host["Privileged"]
        assert host["ReadonlyRootfs"] and host["CapDrop"] == ["ALL"]
        assert not host["PortBindings"] and host["PidMode"] == ""
        mounts = {entry["Destination"]: (entry["Type"], entry["Source"], entry["RW"])
                  for entry in info["Mounts"]}
        assert mounts == {
            "/state": ("bind", str(state), True),
            **{f"/fixture/{file}": ("bind", str(self.files / file), False)
               for file in FILES},
        }
        return ident, state

    def start(self, ident, state):
        (state / "armed").unlink(missing_ok=True)
        docker("start", ident)
        until(lambda: (state / "armed").is_file())
        info = self.inspect(ident)
        assert info["State"]["Running"] and info["State"]["Pid"] > 0
        networks = info["NetworkSettings"]["Networks"]
        assert set(networks) == {"none"} or not networks
        assert all(not network["IPAddress"] for network in networks.values())
        pid = info["State"]["Pid"]
        self.processes.add(pid)
        return pid

    def inventory(self, ident):
        if self.inspect(ident)["State"]["Running"]:
            pids = docker("top", ident, "-eo", "pid").stdout.splitlines()[1:]
            self.processes.update(int(pid) for pid in pids)

    def namespaces(self, ident):
        output = docker("exec", ident, "/bin/sh", "-c",
                        "readlink /proc/self/ns/pid /proc/self/ns/mnt /proc/self/ns/net; "
                        "cat /proc/net/dev").stdout.splitlines()
        assert [line.split("[")[0] for line in output[:3]] == ["pid:", "mnt:", "net:"]
        assert [line.split(":")[0].strip() for line in output[5:]] == ["lo"]
        return output[:3]

    def worker(self, ident, lane):
        worker = subprocess.Popen(
            [DOCKER, "exec", "-i", ident, "/usr/local/bin/python3", "-I",
             "/fixture/worker.py", lane],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, start_new_session=True,
        )
        self.workers.append(worker)
        expect(worker, "ready")
        return worker

    def cleanup(self):
        # Names are registered before creation. Resolve a missing receipt by
        # inspecting the exact name and checking its run label before removal.
        active = set(self.matching("container"))
        observed = set()
        for name, ident in self.names.items():
            info = docker("container", "inspect", name, check=False)
            if info.returncode:
                assert ident is None, "recorded container disappeared"
                continue
            row = json.loads(info.stdout)[0]
            assert row["Config"]["Labels"].get(LABEL) == self.root.name
            assert ident is None or row["Id"] == ident
            observed.add(row["Id"])
            self.inventory(row["Id"])
            docker("rm", "-f", row["Id"])
        assert all(any(ident.startswith(short) for ident in observed) for short in active)
        for worker in self.workers:
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=5)
            worker.stdin.close()
            worker.stdout.close()
        for kind in ("container", "network", "volume"):
            assert not self.matching(kind), "owned Docker resource survived"
        for name in self.names:
            assert docker("container", "inspect", name, check=False).returncode != 0
        until(lambda: all(not Path(f"/proc/{pid}").exists() for pid in self.processes))
        shutil.rmtree(self.root)
        assert not self.root.exists()


def lifecycle(run):
    global phase
    phase = "lifecycle-start"
    a, a_state = run.create("a")
    b, b_state = run.create("b")
    assert a != b and a_state != b_state
    a_pid = run.start(a, a_state)
    b_pid = run.start(b, b_state)
    assert a_pid != b_pid
    assert all(left != right for left, right in zip(run.namespaces(a), run.namespaces(b), strict=True))
    left, right = run.worker(a, "a"), run.worker(b, "b")
    tell(left, "overlap")
    tell(right, "overlap")
    until(lambda: all((state / "arrived").is_file() for state in (a_state, b_state)))
    for state in (a_state, b_state):
        (state / "release").touch()
    expect(left, "complete")
    expect(right, "complete")
    original = (a_state / "thread").read_text()
    sibling = (b_state / "thread").read_text()
    assert original != sibling
    tell(left, "reuse")
    expect(left, "complete")
    assert (a_state / "thread").read_text() == original
    print("PASS lifecycle-start", flush=True)

    phase = "lifecycle-stop"
    run.inventory(a)
    docker("kill", "--signal", "TERM", a)
    assert run.inspect(a)["State"]["Pid"] == a_pid
    docker("kill", "--signal", "KILL", a)
    assert docker("wait", a).stdout.strip() == "137"
    left.wait(timeout=10)
    assert not run.inspect(a)["State"]["Running"] and not Path(f"/proc/{a_pid}").exists()
    assert run.inspect(b)["State"]["Pid"] == b_pid
    tell(right, "survive")
    expect(right, "complete")
    assert (b_state / "thread").read_text() == sibling
    print("PASS lifecycle-stop", flush=True)

    phase = "lifecycle-resume"
    run.start(a, a_state)
    resumed = run.worker(a, "a")
    tell(resumed, "resume")
    expect(resumed, "complete")
    assert (a_state / "thread").read_text() == original
    for worker in (resumed, right):
        tell(worker, "exit")
        assert worker.wait(timeout=10) == 0
    print("PASS lifecycle-resume", flush=True)


def exercise(image, files, mode):
    global phase
    phase = "setup"
    run = Run(image, files)
    try:
        assert all(not run.matching(kind) for kind in ("container", "network", "volume"))
        if mode == "success":
            lifecycle(run)
        elif mode == "failed-start":
            phase = "lifecycle-start"
            ident, state = run.create("failed", broken=True)
            assert docker("start", ident, check=False).returncode != 0
            info = run.inspect(ident)
            assert not info["State"]["Running"] and info["State"]["Error"]
            assert not list(state.iterdir())
        else:
            phase = "lifecycle-stop"
            ident, state = run.create("interrupt")
            run.start(ident, state)
            os.kill(os.getpid(), signal.SIGTERM)
            raise AssertionError("interrupt was not delivered")
    except Interrupted:
        assert mode == "interrupt" and phase == "lifecycle-stop"
    finally:
        failed_phase = phase
        phase = "cleanup"
        run.cleanup()
        phase = failed_phase
    print(f"PASS cleanup {mode}", flush=True)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        image, files = sys.argv[1], Path(sys.argv[2]).resolve()
        for name, digest in zip(FILES[:2], (BINARY_SHA256, SIDECAR_SHA256), strict=True):
            with (files / name).open("rb") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == digest
        assert len(image) == 71 and image.startswith("sha256:")
        for mode in ("success", "failed-start", "interrupt"):
            exercise(image, files, mode)
    except (Exception, KeyboardInterrupt) as error:
        trace = error.__traceback__
        while trace.tb_next is not None:
            trace = trace.tb_next
        line = trace.tb_lineno
        print(f"::error::broker-smoke phase={phase} line={line}", flush=True)
        sys.exit(1)
