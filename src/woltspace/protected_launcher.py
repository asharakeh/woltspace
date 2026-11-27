"""Protected offline launcher and node-owned terminal bridge for Docker."""
from array import array
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import tty

from . import dummy_broker

PATH = Path("/run/woltspace-launch.sock")
WORKER_UID = 991
PROCESS = b"wolt-dummy"
READY = b"protected dummy ready\n"


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
            if (flags & socket.MSG_CTRUNC or len(fds) != 1
                    or json.loads(reply) != {"result": "ok"}):
                raise ValueError("protected launch refused")
            return fds.pop()
        finally:
            for fd in fds:
                os.close(fd)


def spawn(conn, node_uid):
    _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != node_uid:
        raise ValueError("protected launch refused")
    conn.settimeout(2)
    with conn.makefile("rb") as stream:
        raw = stream.readline(dummy_broker.MAX_REQUEST + 1)
    if len(raw) > dummy_broker.MAX_REQUEST or not raw.endswith(b"\n"):
        raise ValueError("protected launch refused")
    selector = json.loads(raw, object_pairs_hook=dummy_broker._unique)
    if (not isinstance(selector, dict) or selector.get("op") != "launch-redeem"
            or not dummy_broker.Broker.launch_selector(selector)):
        raise ValueError("protected launch refused")
    fd = redeem(json.dumps(selector).encode() + b"\n")
    try:
        conn.setblocking(True)
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
    children = []
    with dummy_broker.listen(PATH, 0o666) as listener:
        listener.settimeout(.1)
        print("accepted", flush=True)
        try:
            while not stopped:
                children = [p for p in children if p.poll() is None]
                try:
                    conn, _ = listener.accept()
                except TimeoutError:
                    continue
                with conn:
                    try:
                        if len(children) < dummy_broker.BINDINGS:
                            children.append(spawn(conn, node_uid))
                    except (OSError, ValueError, RecursionError):
                        pass  # close this connection; the node reports a fixed refusal
        finally:
            for child in children:
                child.kill()
            for child in children:
                child.wait()
            PATH.unlink(missing_ok=True)


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
            if io.readline(len(READY) + 1) != READY:
                return 1
        conn.settimeout(None)
        # The worker gets no PTY or terminal pathname. Flush queued input on
        # both transitions so leftover worker keystrokes cannot reach a shell.
        fd = sys.stdin.fileno()
        original = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd, termios.TCSAFLUSH)
            if prctl(15, ctypes.c_char_p(PROCESS), 0, 0, 0):
                return 1
            sys.stdout.buffer.write(READY)
            sys.stdout.buffer.flush()
            while True:
                ready, _, _ = select.select([fd, conn], [], [])
                if conn in ready:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return 0
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
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
