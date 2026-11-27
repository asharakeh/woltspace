"""Root supervisor for the installed, credential-free stock fixture."""
import ctypes
from http.server import HTTPServer
import json
import os
from pathlib import Path
import select
import signal
import socket
import sys
import threading
import time
from types import SimpleNamespace

from . import dummy_broker, protected_launcher as launcher
from .broker_startup import protected


def serve(fd, state, principal):
    for name in ("codex", "codex-code-mode-host", "worker.py", "lane.py", "fence.py"):
        protected(launcher.STOCK / name)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(launcher.STOCK))
    import fence
    import lane
    import worker

    devices = Path("/proc/net/dev").read_text().splitlines()[2:]
    if [line.partition(":")[0].strip() for line in devices] != ["lo"]:
        return 1
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    stopped = threading.Event()

    def stop(*_):
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    # A single worker-owned directory holds all private Codex state.
    for name in ("HOME", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                 "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
        env[name] = str(state / "home")
    control, home = state / "control", state / "home"
    worker.ROOT, worker.WORKDIR = control, home
    with socket.socket(fileno=fd) as channel, HTTPServer(("127.0.0.1", 0), worker.Endpoint) as endpoint:
        channel.settimeout(2)
        raw, _, flags, _ = channel.recvmsg(512)
        if flags & socket.MSG_TRUNC:
            return 1
        hello = json.loads(raw)
        if hello.pop("result") != "ok" or hello.get("principal") != principal:
            return 1
        endpoint.accepted = []
        expected = (control / "thread").read_text().strip() if (control / "thread").is_file() else None
        config = f"""
model = "fixture"
model_provider = "fixture"
check_for_update_on_startup = false
approval_policy = "never"
sandbox_mode = "read-only"
[model_providers.fixture]
name = "Local fixture"
base_url = "http://127.0.0.1:{endpoint.server_port}"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
"""
        config_file = os.memfd_create("fixture-config", os.MFD_CLOEXEC)
        os.write(config_file, config.encode())
        os.lseek(config_file, 0, os.SEEK_SET)
        with os.fdopen(os.open("/dev/null", os.O_WRONLY), "wb") as null:
            engine_in, engine_out = os.pipe(), os.pipe()
            try:
                pid = os.fork()
                if pid == 0:
                    try:
                        os.dup2(engine_in[0], 0)
                        os.dup2(engine_out[1], 1)
                        os.dup2(null.fileno(), 2)
                        os.setgroups([])
                        os.setgid(launcher.WORKER_UID)
                        os.setuid(launcher.WORKER_UID)
                        os.chdir(home)
                        with os.fdopen(config_file, "rb") as incoming, os.fdopen(
                            os.open("config.toml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC |
                                    os.O_NOFOLLOW | os.O_NONBLOCK, 0o600), "wb"
                        ) as outgoing:
                            outgoing.write(incoming.read())
                        os.closerange(3, os.sysconf("SC_OPEN_MAX"))
                        fence.fence(home, endpoint.server_port, (launcher.STOCK,))
                        binary = str(launcher.STOCK / "codex")
                        os.execve(binary, [binary, "app-server", "--listen", "stdio://"], env)
                    finally:
                        os._exit(127)
                os.close(config_file)
                os.close(engine_in[0])
                os.close(engine_out[1])
                threading.Thread(target=endpoint.serve_forever, daemon=True).start()
                child = SimpleNamespace(stdin=os.fdopen(engine_in[1], "wb"),
                                        stdout=os.fdopen(engine_out[0], "rb"))
                finished = threading.Event()
                threading.Thread(target=drive, args=(worker, child, endpoint, channel, hello,
                                                  principal, expected, finished), daemon=True).start()
                closed = select.poll()
                closed.register(0, select.POLLHUP | select.POLLRDHUP | select.POLLERR)
                while not (stopped.is_set() or finished.is_set() or closed.poll(50)):
                    pass
            finally:
                reap(lane)
    return 0


def drive(worker, child, endpoint, channel, hello, principal, expected, finished):
    def commands():
        for line in iter(lambda: sys.stdin.buffer.readline(64), b""):
            if not line.endswith(b"\n"):
                while line and not line.endswith(b"\n"):
                    line = sys.stdin.buffer.readline(64)
                print("fixture refused", flush=True)
                continue
            if line == b"ping\n":
                channel.send(json.dumps({**hello, "action": dummy_broker.ACTION}).encode())
                status = json.loads(channel.recv(512)).get("result")
                print("dummy ok" if status == "ok" else "dummy refused", flush=True)
            elif line in (b"fixture-overlap\n", b"fixture-reuse\n", b"fixture-resume\n", b"fixture-survive\n"):
                yield line.decode().strip().removeprefix("fixture-")
            else:
                print("fixture refused", flush=True)
        yield "exit"

    def output(value, *, flush=False):
        if value == "ready":
            sys.stdout.buffer.write(launcher.STOCK_READY)
            sys.stdout.buffer.flush()
        elif value == "complete":
            print("fixture complete", flush=True)

    try:
        worker.sys = SimpleNamespace(stdin=commands())
        worker.print = output
        worker._drive(child, endpoint, principal, expected)
    except (AssertionError, OSError, ValueError, KeyError):
        pass  # worker result and diagnostics are never sent to the pane
    finally:
        finished.set()


def reap(lane):
    deadline = time.monotonic() + 6
    while True:
        for pid, start in lane.tree(os.getpid()).items():
            lane.owned_signal(pid, start, signal.SIGKILL)
        try:
            os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("protected tree not reaped")
        time.sleep(.025)


if __name__ == "__main__":
    sys.exit(serve(int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]))
