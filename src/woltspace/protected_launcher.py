"""Protected offline launcher and node-owned terminal bridge for Docker."""
from array import array
from collections import OrderedDict
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import termios
import time
import tty

from . import dummy_broker

PATH = Path("/run/woltspace-launch.sock")
ENGINE_STATE = Path("/run/woltspace-engine")
STOCK = Path("/usr/local/lib/woltspace-stock-fixture")
PROFILE = Path("/etc/woltspace/stock-fixture")
WORKER_UID = 991
PROCESS = b"wolt-dummy"
WOLTS = Path("/workspace/wolts")  # the lodge's tree inside the container
OUTPUT = (b"dummy ok", b"dummy refused", b"dummy fenced", b"dummy open")  # all the bridge shows
READY = b"protected dummy ready\n"
STOCK_READY = b"protected stock ready\n"
STOCK_OUTPUT = (b"fixture complete", b"fixture refused")


def deny_new_channels():
    """Keep the inherited dummy socket usable while denying new connections."""
    libc = ctypes.CDLL(None, use_errno=True)
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    for option, value in ((38, 1), (4, 0)):  # no_new_privs, non-dumpable
        if libc.prctl(option, value, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "prctl failed")
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("seccomp allocation failed")
    try:
        # Also deny io_uring, which can submit socket operations asynchronously.
        for name in (b"socket", b"socketpair", b"connect", b"io_uring_setup"):
            number = lib.seccomp_syscall_resolve_name(name)
            if number < 0 or lib.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0):
                raise RuntimeError("seccomp rule failed")
        if lib.seccomp_load(context):
            raise RuntimeError("seccomp load failed")
    finally:
        lib.seccomp_release(context)


def redeem(raw):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(5)
        client.connect(str(dummy_broker.SOCKET))
        client.sendall(raw)
        word = array("i").itemsize
        reply, ancillary, flags, _ = client.recvmsg(512, socket.CMSG_SPACE(word), socket.MSG_CMSG_CLOEXEC)
        fds = array("i")
        for level, kind, data in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                fds.frombytes(data)
        try:
            while reply and not reply.endswith(b"\n") and len(reply) < 512:
                chunk = client.recv(512 - len(reply))
                if not chunk:
                    break
                reply += chunk
            if flags & socket.MSG_CTRUNC or len(fds) != 1 or not reply.endswith(b"\n"):
                raise ValueError("protected launch refused")
            result = json.loads(reply, object_pairs_hook=dummy_broker._unique)
            if result == {"result": "ok"}:
                return fds.pop(), None
            if not isinstance(result, dict) or result.keys() != {"result", "principal", "conversation"}:
                raise ValueError("protected launch refused")
            principal, conversation = result["principal"], result["conversation"]
            if result["result"] != "ok" or not valid_identity(principal, conversation):
                raise ValueError("protected launch refused")
            return fds.pop(), (principal, conversation)
        finally:
            for fd in fds:
                os.close(fd)


def valid_identity(principal, conversation):
    return (isinstance(principal, str) and dummy_broker.PRINCIPAL.fullmatch(principal) is not None
            and isinstance(conversation, str)
            and dummy_broker.CHECKS["conversation"].fullmatch(conversation) is not None)


def private_engine_state(principal, conversation):
    """Root-owned parents prevent the worker from substituting a state directory."""
    if not valid_identity(principal, conversation):
        raise ValueError("protected launch refused")
    parent = ENGINE_STATE / principal
    state = parent / conversation
    for directory, mode, uid in ((ENGINE_STATE, 0o711, 0), (parent, 0o711, 0),
                                 (state, 0o711, 0), (state / "control", 0o700, 0),
                                 (state / "home", 0o700, WORKER_UID)):
        try:
            directory.mkdir(mode)
        except FileExistsError:
            pass
        else:
            os.chmod(directory, mode)
            os.chown(directory, uid, uid)
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode
                or (info.st_uid, info.st_gid) != (uid, uid)):
            raise ValueError("unsafe protected state")
    return state


def stock_enabled():
    """Only the root-installed opt-in selects the disposable stock profile."""
    from .broker_startup import protected

    try:
        PROFILE.lstat()
    except FileNotFoundError:
        return False
    protected(PROFILE)
    if not PROFILE.is_file() or PROFILE.read_bytes() != b"stock-fixture\n":
        raise ValueError("invalid protected stock profile")
    return True


def request(conn, node_uid):
    _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != node_uid:
        raise ValueError("protected launch refused")
    conn.settimeout(2)
    with conn.makefile("rb") as stream:
        raw = stream.readline(dummy_broker.MAX_REQUEST + 1)
    if len(raw) > dummy_broker.MAX_REQUEST or not raw.endswith(b"\n"):
        raise ValueError("protected launch refused")
    selector = json.loads(raw, object_pairs_hook=dummy_broker._unique)
    if (not dummy_broker.Broker.launch_selector(selector)
            or selector["op"] not in {"launch-redeem", "launch-receipt"}):
        raise ValueError("protected launch refused")
    return selector


def _receipt(session, attempt, timeout):
    """Read a bounded, root-peer launcher observation."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(str(PATH))
            _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0:
                return {}
            selector = {"op": "launch-receipt", "session": session, "attempt": attempt}
            conn.sendall(json.dumps(selector).encode() + b"\n")
            with conn.makefile("rb") as stream:
                reply = json.loads(stream.readline(128), object_pairs_hook=dummy_broker._unique)
            if (isinstance(reply, dict) and reply.keys() == {"result", "epoch"}
                    and isinstance(reply["epoch"], str) and re.fullmatch(r"[0-9a-f]{32}", reply["epoch"])
                    and reply["result"] in ("pending", "reaped", "no-owned-launch", "unrecorded", "unavailable")):
                return reply
    except (OSError, ValueError, RecursionError):
        pass
    return {}


def launcher_epoch(session, attempt):
    return _receipt(session, attempt, 1).get("epoch")


def reap_status(session, attempt, timeout, epoch=None):
    reply = _receipt(session, attempt, timeout)
    if epoch is not None and reply.get("epoch") == epoch:
        return reply["result"]
    return "unavailable"


class NoOwnedLaunch(ValueError):
    """The exact launch could not reach process creation."""


def spawn(conn, node_uid, selector=None, stock=False):
    selector = request(conn, node_uid) if selector is None else selector
    if selector["op"] != "launch-redeem":
        raise ValueError("protected launch refused")
    try:
        fd, identity = redeem(json.dumps(selector).encode() + b"\n")
    except (OSError, ValueError, RecursionError) as error:
        if stock:
            raise NoOwnedLaunch("protected launch refused") from error
        raise
    try:
        conn.setblocking(True)
        if stock:
            try:
                if identity is None:
                    raise ValueError("protected launch refused")
                state = private_engine_state(*identity)
            except (OSError, ValueError) as error:
                raise NoOwnedLaunch("protected launch refused") from error
            return subprocess.Popen(
                [sys.executable, "-I", "-m", "woltspace.protected_stock",
                 str(fd), str(state), identity[0]],
                cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                start_new_session=True, stdin=conn, stdout=conn, stderr=subprocess.DEVNULL,
                pass_fds=(fd,),
            )
        return subprocess.Popen(
            [sys.executable, "-I", "-m", "woltspace.protected_launcher", "worker", str(fd)],
            cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            user=WORKER_UID, group=WORKER_UID, extra_groups=[], start_new_session=True,
            stdin=conn, stdout=conn, stderr=subprocess.DEVNULL, pass_fds=(fd,),
        )
    finally:
        os.close(fd)


def serve():
    node_uid = pwd.getpwnam("node").pw_uid
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    stock = stock_enabled()
    children, receipts = {}, OrderedDict()
    epoch = secrets.token_hex(16)

    def remember(key, result):
        receipts[key] = result
        receipts.move_to_end(key)
        if len(receipts) > dummy_broker.BINDINGS:
            receipts.popitem(last=False)

    with dummy_broker.listen(PATH, 0o666) as listener:
        listener.settimeout(.1)
        print("accepted", flush=True)
        try:
            while not stopped:
                for key, child in list(children.items()):
                    code = child.poll()
                    if code is not None:
                        del children[key]
                        if stock:
                            remember(key, "reaped" if code == 0 else "unavailable")
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                with conn:
                    try:
                        selector = request(conn, node_uid)
                        key = selector["session"], selector["attempt"]
                        if selector["op"] == "launch-receipt":
                            if stock:
                                result = ("pending" if key in children
                                          else receipts.get(key, "unrecorded"))
                                conn.sendall(json.dumps({"result": result, "epoch": epoch}).encode() + b"\n")
                        elif (len(children) < dummy_broker.BINDINGS and key not in children
                              and (not stock or not any(name == key[0] for name, _ in children))):
                            if stock:
                                if key in receipts:
                                    continue
                                remember(key, "unavailable")
                            try:
                                children[key] = spawn(conn, node_uid, selector, stock)
                            except NoOwnedLaunch:
                                remember(key, "no-owned-launch")
                                continue
                            if stock:
                                for previous in [saved for saved in receipts
                                                 if saved[0] == key[0] and saved != key]:
                                    receipts[previous] = "unavailable"
                    except (OSError, ValueError, RecursionError):
                        pass  # close this connection; the node reports a fixed refusal
        finally:
            failed = False
            for child in children.values():
                try:
                    child.terminate() if stock else child.kill()
                except OSError:
                    failed = True
            deadline = time.monotonic() + 10
            for child in children.values():
                try:
                    child.wait(timeout=max(0, deadline - time.monotonic()))
                except (OSError, subprocess.TimeoutExpired):
                    failed = True
            PATH.unlink(missing_ok=True)
            if failed:
                raise RuntimeError("protected launcher shutdown unconfirmed")


def fenced() -> bool:
    """The dummy's own boundary check, from inside its fence: no new channel of any kind (so no lodge
    route, tmux server, peer pane or broker socket) and no write into the lodge's tree."""
    for make in (lambda: socket.socket(socket.AF_UNIX), lambda: socket.socket(socket.AF_INET),
                 lambda: socket.socket(socket.AF_INET6), socket.socketpair):
        try:
            made = make()
        except PermissionError:
            continue
        for sock in made if isinstance(made, tuple) else (made,):
            sock.close()
        return False
    probe = WOLTS / f".fence-probe-{os.getpid()}"
    try:
        os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except PermissionError:
        return True
    probe.unlink()
    return False


def worker(fd):
    if os.geteuid() != WORKER_UID or os.getgroups() or os.isatty(0) or os.isatty(1):
        return 1
    deny_new_channels()
    with socket.socket(fileno=fd) as channel:
        hello = json.loads(channel.recv(512))
        if hello.pop("result") != "ok":
            return 1
        sys.stdout.buffer.write(READY)
        sys.stdout.buffer.flush()
        for line in iter(lambda: sys.stdin.buffer.readline(4096), b""):
            if line == b"exit\n":
                return 0
            if line == b"probe\n":
                print("dummy fenced" if fenced() else "dummy open", flush=True)
            if line == b"ping\n":
                channel.send(json.dumps({**hello, "action": dummy_broker.ACTION}).encode())
                result = json.loads(channel.recv(512)).get("result")
                print("dummy ok" if result == "ok" else "dummy refused", flush=True)
    return 0


def bridge(session, attempt):
    prctl = ctypes.CDLL(None).prctl
    if prctl(15, ctypes.c_char_p(b"wolt-dummy-wait"), 0, 0, 0):
        return 1
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(8)
        conn.connect(str(PATH))
        req = {"op": "launch-redeem", "session": session, "attempt": attempt}
        conn.sendall(json.dumps(req).encode() + b"\n")
        with conn.makefile("rb", buffering=0) as io:
            ready_message = io.readline(max(len(READY), len(STOCK_READY)) + 1)
            if ready_message not in (READY, STOCK_READY):
                return 1
        allowed = OUTPUT + STOCK_OUTPUT if ready_message == STOCK_READY else OUTPUT
        conn.settimeout(None)
        # The worker gets no PTY or terminal pathname. Flush queued input on
        # both transitions so leftover worker keystrokes cannot reach a shell.
        fd = sys.stdin.fileno()
        original = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd, termios.TCSAFLUSH)
            if prctl(15, ctypes.c_char_p(PROCESS), 0, 0, 0):
                return 1
            sys.stdout.buffer.write(ready_message)
            sys.stdout.buffer.flush()
            pending = b""
            while True:
                ready, _, _ = select.select([fd, conn], [], [])
                if conn in ready:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return 0
                    pending += chunk
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        if line not in allowed:
                            return 1
                        sys.stdout.buffer.write(line + b"\n")
                        sys.stdout.buffer.flush()
                    if len(pending) > max(map(len, allowed)):
                        return 1
                if fd in ready:
                    chunk = os.read(fd, 4096)
                    if not chunk:
                        return 0
                    conn.sendall(chunk.replace(b"\r", b"\n"))
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, original)


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        serve()
    elif len(sys.argv) == 3 and sys.argv[1] == "worker":
        sys.exit(worker(int(sys.argv[2])))
    elif len(sys.argv) == 4 and sys.argv[1] == "bridge":
        try:
            sys.exit(bridge(*sys.argv[2:]))
        except (OSError, termios.error, KeyboardInterrupt):
            sys.exit("protected session unavailable")
    else:
        sys.exit(2)
