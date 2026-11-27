"""Trusted lane driver and stop tool. Engine and probe run fenced under a per-lane subreaper.

drive <fixture> <state> <lane>: stdio protocol prepared/go, then step zero's verbs.
stop <state> <lane>: forced stop of that lane's whole launcher tree.
"""
import ctypes
import errno
from http.server import HTTPServer
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import sys
import threading
import time
from types import SimpleNamespace

PROBE = {"sibling_state": "EACCES", "control_state": "EACCES", "lodge_file": "EACCES",
         "sibling_tcp": "EACCES", "decoy_tcp": "EACCES", "tcp_bind": "EACCES",
         "udp": "EPERM", "unix": "EPERM", "signal_sibling": "EPERM",
         "signal_launcher": "EPERM", "sibling_proc": "EACCES"}


def tree(root):
    """Live (non-zombie) descendants of root, by a full /proc parent walk."""
    parents = {}
    for entry in filter(str.isdigit, os.listdir("/proc")):
        try:
            with open(f"/proc/{entry}/stat") as stat:
                fields = stat.read().rsplit(")", 1)[1].split()
        except OSError:
            continue
        parents[int(entry)] = (int(fields[1]), fields[0], fields[19])
    found, frontier = set(), {root}
    while frontier:
        frontier = {pid for pid, row in parents.items() if row[0] in frontier} - found
        found |= frontier
    return {pid for pid in found if parents[pid][1] != "Z"}, parents


def kill_tree(launcher, window=0.0):
    """TERM, observe for `window`, then KILL every descendant, then the launcher."""
    first, _ = tree(launcher)
    for pid in first:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    time.sleep(window)
    survivors, _ = tree(launcher)
    deadline = time.monotonic() + 10
    while (left := tree(launcher)[0]):
        assert time.monotonic() < deadline, "descendants survived SIGKILL"
        for pid in left:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(.02)
    os.kill(launcher, signal.SIGKILL)
    return first, survivors


def stop(state, lane):
    info = json.loads((state / "ctl" / f"{lane}.json").read_text())
    _, parents = tree(info["launcher"])
    assert parents.get(info["launcher"], (0, "", ""))[2] == info["start"], "launcher identity"
    first, survivors = kill_tree(info["launcher"], window=1.0)
    deadline = time.monotonic() + 10
    while info["launcher"] in (live := tree(1)[1]) and live[info["launcher"]][1] != "Z":
        assert time.monotonic() < deadline, "launcher survived"
        time.sleep(.02)
    print(f"stopped tree={len(first)} term_survivors={len(survivors)}", flush=True)


def spawn(argv, env, stdin, stdout, own, port, reads, keep=()):
    import fence
    pid = os.fork()
    if pid == 0:
        try:
            os.dup2(stdin, 0)
            os.dup2(stdout, 1)
            os.dup2(os.open("/dev/null", os.O_WRONLY), 2)
            for fd in keep:
                os.set_inheritable(fd, True)
            os.chdir(own)
            fence.fence(own, port, reads)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)


def drive(fixture, state, lane):
    sys.path.insert(0, str(fixture))
    import fence
    import worker
    other = {"a": "b", "b": "a"}[lane]
    own = state / lane
    own.mkdir(mode=0o700, exist_ok=True)
    worker.ROOT = own
    saved = own / "thread"
    expected = saved.read_text().strip() if saved.exists() else None
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for name in ("HOME", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
                 "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "TMPDIR"):
        (own / name.lower()).mkdir(mode=0o700, exist_ok=True)
        env[name] = str(own / name.lower())
    server = HTTPServer(("127.0.0.1", 0), worker.Endpoint)
    server.accepted = []
    port = server.server_port
    decoy = socket.create_server(("127.0.0.1", 0))  # stands in for any lodge/broker TCP endpoint
    (own / "codex_home" / "config.toml").write_text(
        f'model = "fixture"\nmodel_provider = "fixture"\ncheck_for_update_on_startup = false\n'
        f'approval_policy = "never"\nsandbox_mode = "read-only"\n[model_providers.fixture]\n'
        f'name = "Local fixture"\nbase_url = "http://127.0.0.1:{port}"\nwire_api = "responses"\n'
        f'request_max_retries = 0\nstream_max_retries = 0\n[analytics]\nenabled = false\n')
    control = state / "ctl" / f"{lane}.json"
    control.write_text(json.dumps({"port": port, "pid": os.getpid()}))
    try:
        abi = fence.abi()
    except OSError as error:
        abi = errno.errorcode.get(error.errno, "other")
    print(f"prepared abi={abi}", flush=True)
    assert sys.stdin.readline() == "go\n", "go"
    sibling = json.loads((state / "ctl" / f"{other}.json").read_text())
    engine_in, engine_out, probe_out = os.pipe(), os.pipe(), os.pipe()
    channel, inherited = socket.socketpair()
    token = secrets.token_hex(8)
    python = os.path.realpath(sys.executable)
    launcher = os.fork()
    if launcher == 0:
        try:
            os.setsid()
            assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
            spawn([str(fixture / "codex"), "app-server", "--listen", "stdio://"], env,
                  engine_in[0], engine_out[1], own, port, [fixture])
            spawn([python, "-I", str(fixture / "probe.py"), str(own), str(state / other),
                   str(state / "ctl"), str(state / "lodge" / "secret"), str(port),
                   str(sibling["port"]), str(decoy.getsockname()[1]), str(sibling["pid"]),
                   str(inherited.fileno()), token], {"PATH": "/usr/bin:/bin"},
                  os.open("/dev/null", os.O_RDONLY), probe_out[1], own, port, [fixture],
                  keep=[inherited.fileno()])
            for fd in (*engine_in, *engine_out, *probe_out):
                os.close(fd)
            while True:
                try:
                    os.wait()
                except ChildProcessError:
                    time.sleep(.05)
        finally:
            os._exit(0)
    for fd in (engine_in[0], engine_out[1], probe_out[1]):
        os.close(fd)
    inherited.close()
    with open(f"/proc/{launcher}/stat") as stat:
        start = stat.read().rsplit(")", 1)[1].split()[19]
    control.write_text(json.dumps({"port": port, "pid": os.getpid(), "launcher": launcher, "start": start}))
    serving = None
    try:
        channel.sendall(token.encode())
        assert select.select([probe_out[0]], [], [], 20)[0], "probe deadline"
        with os.fdopen(probe_out[0]) as stream:
            result = json.loads(stream.readline())
        mismatch = sorted(key for key, value in PROBE.items()
                          if result.get(key) != value or result["descendant"].get(key) != value)
        own_ok = all(result[key] == "ok" for key in ("own_state", "own_tcp", "inherited_channel"))
        assert not mismatch and own_ok and result["no_new_privs"] == "1", f"probe {mismatch}"
        # No separate line: "ready" (printed by _drive) is reached only after this probe check.
        child = SimpleNamespace(stdin=os.fdopen(engine_in[1], "wb"), stdout=os.fdopen(engine_out[0], "rb"))
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        thread = worker._drive(child, server, lane, expected)
        assert not list(own.rglob("auth.json")), "unexpected auth state"
        saved.write_text(thread + "\n")
    finally:
        if tree(launcher)[1].get(launcher, (0, "Z"))[1] != "Z":
            kill_tree(launcher)
        os.waitpid(launcher, 0)
        if serving is not None:
            server.shutdown()
        server.server_close()
        decoy.close()


if __name__ == "__main__":
    if sys.argv[1] == "stop":
        stop(Path(sys.argv[2]), sys.argv[3])
    else:
        drive(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
