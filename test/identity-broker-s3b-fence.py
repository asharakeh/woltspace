"""Disposable Docker proof. Root launches one fixed offline worker on pipes."""
import ctypes
import errno
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys


WORKER_UID = 991
INPUT = "launch-input"
ROUTE = "launch.sock"


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


def denied(operation, expected):
    try:
        operation()
    except OSError as exc:
        if exc.errno == expected:
            return
        raise
    raise AssertionError("expected denial")


def check_channels():
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
        denied(lambda: socket.socket(family), errno.EPERM)
    denied(socket.socketpair, errno.EPERM)


def worker(fd, directory, parent_pid, node_pid, tmux_socket):
    assert os.getuid() == os.geteuid() == os.getgid() == WORKER_UID
    assert not os.getgroups() and not any(os.isatty(fd) for fd in range(3))
    deny_new_channels()
    check_channels()
    tmux = subprocess.run(
        ["/usr/bin/tmux", "-S", tmux_socket, "has-session", "-t", "=main"],
        capture_output=True, timeout=3,
    )
    assert tmux.returncode == 1
    curl = subprocess.run(
        ["/usr/bin/curl", "--noproxy", "*", "--max-time", "2", "-fsS",
         "http://127.0.0.1:7777/health"],
        capture_output=True, timeout=3,
    )
    assert curl.returncode == 7
    denied(lambda: os.open(directory / INPUT, os.O_RDONLY), errno.EACCES)
    denied(lambda: os.open(directory / INPUT, os.O_WRONLY), errno.EACCES)
    denied(lambda: os.open(Path(__file__), os.O_WRONLY), errno.EACCES)
    denied(lambda: os.kill(parent_pid, 0), errno.EPERM)
    denied(lambda: os.kill(node_pid, 0), errno.EPERM)
    with socket.socket(fileno=fd) as channel:
        assert channel.recv(64) == b"dummy.ping"
        channel.sendall(b"dummy.pong")


def launch(directory, node_pid, tmux_socket):
    assert os.getuid() == os.geteuid() == 0
    assert pwd.getpwnam("node").pw_uid not in {0, WORKER_UID}
    assert not any(entry.pw_uid == WORKER_UID for entry in pwd.getpwall())
    assert directory.stat().st_uid == 0 and directory.stat().st_mode & 0o777 == 0o755
    assert str(tmux_socket) == f"/tmp/tmux-{pwd.getpwnam('node').pw_uid}/default"
    protected = directory / INPUT
    with protected.open("x") as handle:
        handle.write("dummy.ping")
    protected.chmod(0o600)
    with socket.socket(socket.AF_UNIX) as route:
        route.bind(str(directory / ROUTE))
        route.listen(1)
        run_worker(directory, node_pid, tmux_socket, protected.read_bytes())


def run_worker(directory, node_pid, tmux_socket, request):
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with parent, child:
        parent.settimeout(5)
        with subprocess.Popen(
            [sys.executable, "-I", "-S", __file__, "--worker", str(child.fileno()),
             str(directory), str(os.getpid()), str(node_pid), tmux_socket],
            cwd=directory, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            user=WORKER_UID, group=WORKER_UID, extra_groups=[],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            pass_fds=(child.fileno(),), start_new_session=True,
        ) as process:
            child.close()
            try:
                parent.sendall(request)
                assert parent.recv(64) == b"dummy.pong"
                assert process.wait(timeout=5) == 0
                assert parent.recv(64) == b""
            finally:
                if process.poll() is None:
                    process.kill()


if __name__ == "__main__":
    if sys.argv[1] == "--worker":
        worker(int(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6])
    else:
        launch(Path(__file__).parent, int(sys.argv[1]), sys.argv[2])
