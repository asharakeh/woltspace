"""Trusted lane driver and stop tool. Engine and probe run fenced under a per-lane subreaper.

drive <fixture> <state> <lane>: stdio protocol prepared/go, then step zero's verbs.
stop <state> <lane>: forced stop of that lane's whole launcher tree.
census <state>: live recorded members (pid + start time) per lane.
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


def ident(pid):
    """(ppid, start time) of a live, non-zombie pid, else None."""
    try:
        with open(f"/proc/{pid}/stat") as stat:
            fields = stat.read().rsplit(")", 1)[1].split()
    except OSError:
        return None
    return None if fields[0] == "Z" else (int(fields[1]), fields[19])


def born(pid):
    return (ident(pid) or (0, None))[1]


def tree(root):
    """{pid: start} of live descendants of root, by a full /proc parent walk."""
    rows = {int(entry): row for entry in filter(str.isdigit, os.listdir("/proc")) if (row := ident(entry))}
    found, frontier = {}, {root}
    while frontier:
        frontier = {pid for pid, (ppid, _) in rows.items() if ppid in frontier and pid not in found}
        found.update({pid: rows[pid][1] for pid in frontier})
    return found


def owned_signal(pid, start, sig):
    """Signal only through a pidfd whose process still has the recorded start time."""
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return False
    try:
        if start is None or born(pid) != start:
            return False
        signal.pidfd_send_signal(fd, sig)
        return True
    except ProcessLookupError:
        return False
    finally:
        os.close(fd)


def kill_tree(launcher, start, window=0.0, members=()):
    """TERM the tree, observe for `window`, KILL it and live recorded members, then the launcher."""
    if born(launcher) != start:
        return {}, {}  # stale record: nothing is signalled
    first = tree(launcher)
    for pid, when in first.items():
        owned_signal(pid, when, signal.SIGTERM)
    time.sleep(window)
    survivors = tree(launcher)
    deadline = time.monotonic() + 10
    while (left := {**tree(launcher), **{pid: when for pid, when in members if born(pid) == when}}):
        assert time.monotonic() < deadline, "descendants survived SIGKILL"
        for pid, when in left.items():
            owned_signal(pid, when, signal.SIGKILL)
        time.sleep(.02)
    owned_signal(launcher, start, signal.SIGKILL)
    return first, survivors


def reclaim(record):
    """Recovery from a lane record alone: identity-checked, never a bare pid."""
    if record.get("start"):
        kill_tree(record["launcher"], record["start"], members=record["members"])
    for pid, when in record.get("members", []):
        owned_signal(pid, when, signal.SIGKILL)


def census(state):
    counts = []
    for lane in "ab":
        record = json.loads((state / "ctl" / f"{lane}.json").read_text())
        owned = [[record.get("launcher"), record.get("start")], *record.get("members", [])]
        counts.append(f"{lane}={sum(when is not None and born(pid) == when for pid, when in owned)}")
    print("census", *counts, flush=True)


def stop(state, lane):
    record = json.loads((state / "ctl" / f"{lane}.json").read_text())
    assert born(record["launcher"]) == record["start"], "stale launcher record"
    first, survivors = kill_tree(record["launcher"], record["start"], 1.0, record["members"])
    deadline = time.monotonic() + 10
    while born(record["launcher"]) == record["start"]:
        assert time.monotonic() < deadline, "launcher survived"
        time.sleep(.02)
    print(f"stopped tree={len(first)} term_survivors={len(survivors)}", flush=True)


def publish(control, record, generation):
    """Complete snapshot to a same-directory temp file, then atomic replace: readers and recovery
    only ever see the previous or the new full record."""
    temporary = control.with_name(f".{control.name}.{generation}.tmp")
    with open(temporary, "w") as stream:
        stream.write(json.dumps(record))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, control)


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
    return pid


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
    publish(control, {"port": port, "pid": os.getpid()}, 0)
    try:
        abi = fence.abi()
    except OSError as error:
        abi = errno.errorcode.get(error.errno, "other")
    print(f"prepared abi={abi}", flush=True)
    assert sys.stdin.readline() == "go\n", "go"
    sibling = json.loads((state / "ctl" / f"{other}.json").read_text())
    engine_in, engine_out, probe_out = os.pipe(), os.pipe(), os.pipe()
    gate, report = os.pipe(), os.pipe()
    channel, inherited = socket.socketpair()
    token = secrets.token_hex(8)
    python = os.path.realpath(sys.executable)
    launcher = os.fork()
    if launcher == 0:
        try:
            os.close(gate[1])
            if os.read(gate[0], 1) != b"1":
                os._exit(0)  # released only after the driver published this launcher
            os.setsid()
            assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
            engine = spawn([str(fixture / "codex"), "app-server", "--listen", "stdio://"], env,
                           engine_in[0], engine_out[1], own, port, [fixture])
            probe = spawn([python, "-I", str(fixture / "probe.py"), str(own), str(state / other),
                           str(state / "ctl"), str(state / "lodge" / "secret"), str(port),
                           str(sibling["port"]), str(decoy.getsockname()[1]), str(sibling["pid"]),
                           str(inherited.fileno()), token], {"PATH": "/usr/bin:/bin"},
                          os.open("/dev/null", os.O_RDONLY), probe_out[1], own, port, [fixture],
                          keep=[inherited.fileno()])
            os.write(report[1], f"{engine} {probe}".encode())
            for fd in (*engine_in, *engine_out, *probe_out, *report, gate[0]):
                os.close(fd)
            while True:
                try:
                    os.wait()
                except ChildProcessError:
                    time.sleep(.05)
        finally:
            os._exit(0)
    record = {"port": port, "pid": os.getpid(), "launcher": launcher, "start": None, "members": []}
    serving = None
    try:
        for fd in (engine_in[0], engine_out[1], probe_out[1], gate[0], report[1]):
            os.close(fd)
        inherited.close()
        record["start"] = born(launcher)
        publish(control, record, 1)  # published while the launcher is still gated
        os.write(gate[1], b"1")
        assert select.select([report[0]], [], [], 10)[0], "launch report"
        record["members"] = [[int(pid), born(int(pid))] for pid in os.read(report[0], 64).split()]
        publish(control, record, 2)
        channel.sendall(token.encode())
        assert select.select([probe_out[0]], [], [], 20)[0], "probe deadline"
        with os.fdopen(probe_out[0]) as stream:
            result = json.loads(stream.readline())
        descendant = [result["descendant_pid"], result["descendant_start"]]
        assert born(descendant[0]) == descendant[1], "descendant identity"
        record["members"].append(descendant)
        publish(control, record, 3)
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
        reclaim(record)
        os.kill(launcher, signal.SIGKILL)  # own unreaped child: its pid cannot be reused yet
        os.waitpid(launcher, 0)
        if serving is not None:
            server.shutdown()
        server.server_close()
        decoy.close()


if __name__ == "__main__":
    if sys.argv[1] == "stop":
        stop(Path(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == "census":
        census(Path(sys.argv[2]))
    else:
        drive(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
