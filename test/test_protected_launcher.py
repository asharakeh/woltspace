"""Run the trusted bridge against a disposable PTY and private socket."""
import os
from pathlib import Path
import pty
import select
import socket
import subprocess
import sys
import tempfile
import termios

from woltspace import protected_launcher as launcher


def test_bridge_filters_worker_output_and_restores_terminal():
    with tempfile.TemporaryDirectory(prefix="ws-pty.", dir="/tmp") as directory:
        path = Path(directory) / "p.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            server.settimeout(5)
            master, slave = pty.openpty()
            try:
                original = termios.tcgetattr(slave)
                bridge = subprocess.Popen(
                    [sys.executable, "-c",
                     "from pathlib import Path; import sys; from woltspace import protected_launcher as p; "
                     "p.PATH = Path(sys.argv[1]); sys.exit(p.bridge('alpha', 'a'*12))",
                     str(path)],
                    stdin=slave, stdout=slave, stderr=subprocess.PIPE,
                )
                try:
                    with server.accept()[0] as client:
                        client.settimeout(5)
                        assert b'"attempt": "aaaaaaaaaaaa"' in client.recv(512)
                        client.sendall(launcher.READY)
                        assert terminal_line(master) == b"protected dummy ready\r\n"
                        os.write(master, b"ping\r")
                        assert client.recv(64) == b"ping\n"
                        client.sendall(b"dummy ok\n")
                        assert terminal_line(master) == b"dummy ok\r\n"
                        client.sendall(b"unexpected output\n")
                        assert bridge.wait(timeout=5) == 1
                        assert client.recv(1) == b""
                        assert not select.select([master], [], [], 0)[0]
                        assert termios.tcgetattr(slave) == original
                finally:
                    if bridge.poll() is None:
                        bridge.kill()
                    bridge.communicate(timeout=5)
            finally:
                os.close(master)
                os.close(slave)


def terminal_line(fd):
    line = b""
    while not line.endswith(b"\n"):
        assert select.select([fd], [], [], 5)[0]
        line += os.read(fd, 128)
    return line


def test_launcher_rejects_non_node_before_redemption(monkeypatch):
    import pytest

    def unexpected(*_):
        pytest.fail("non-node peer reached broker redemption")

    monkeypatch.setattr(launcher, "redeem", unexpected)
    server, client = socket.socketpair()
    with server, client:
        client.sendall(b'{"op":"launch-redeem","session":"alpha","attempt":"aaaaaaaaaaaa"}\n')
        with pytest.raises(ValueError, match="protected launch refused"):
            launcher.spawn(server, os.getuid() + 1)


def test_the_dummy_probe_reports_its_own_fence(tmp_path, monkeypatch):
    import errno
    import pytest

    monkeypatch.setattr(launcher, "WOLTS", tmp_path)
    assert launcher.fenced() is False  # an ordinary process: sockets open, tree writable
    assert not list(tmp_path.iterdir())  # the probe file is removed again

    def refused(*_, **__):
        raise PermissionError(errno.EPERM, "denied")

    tmp_path.chmod(0o555)
    try:
        if os.access(tmp_path, os.W_OK):
            pytest.skip("this uid writes through directory modes")
        assert launcher.fenced() is False  # a read-only tree, but sockets still open
        monkeypatch.setattr(launcher.socket, "socket", refused)
        monkeypatch.setattr(launcher.socket, "socketpair", refused)
        assert launcher.fenced() is True
    finally:
        tmp_path.chmod(0o755)
    assert launcher.fenced() is False  # no sockets, but the tree is writable again
    assert set(launcher.OUTPUT) >= {b"dummy fenced", b"dummy open"}  # both answers pass the bridge
