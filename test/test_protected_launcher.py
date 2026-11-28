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


def test_private_engine_state_refuses_a_wrong_owner(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import pytest

    root = tmp_path / "engine"
    root.mkdir(mode=0o711)
    original = Path.lstat

    def lstat(path):
        info = original(path)
        if path == root:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=123, st_gid=123)
        return info

    monkeypatch.setattr(launcher, "ENGINE_STATE", root)
    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(ValueError, match="unsafe protected state"):
        launcher.private_engine_state("p-" + "a" * 32, "11223344-5566-7788-99aa-bbccddeeff00")
    assert not list(root.iterdir())


def test_reap_status_rejects_a_nonroot_peer(monkeypatch):
    import io
    import struct
    from unittest.mock import MagicMock

    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.getsockopt.return_value = struct.pack("3i", 42, 123, 123)
    conn.makefile.return_value = io.BytesIO(b'{"result":"reaped"}\n')
    monkeypatch.setattr(launcher.socket, "socket", lambda *_: conn)
    assert launcher.reap_status("alpha", "a" * 12, 1) == "unavailable"
    conn.sendall.assert_not_called()


def test_stock_replacement_waits_and_invalidates_the_old_receipt(monkeypatch):
    import json
    from contextlib import nullcontext
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    old, new = "a" * 12, "b" * 12
    requests = iter([
        ("launch-redeem", old), ("launch-redeem", new), ("launch-receipt", old),
        ("launch-receipt", old), ("launch-redeem", new), ("launch-receipt", old),
    ])
    child = MagicMock()
    child.poll.return_value = None
    spawned, replies = [], []
    handler = None

    class Listener:
        def settimeout(self, _):
            pass

        def accept(self):
            if replies == ["pending"]:
                child.poll.return_value = 0
                replies.append("between")
                raise TimeoutError
            try:
                op, attempt = next(requests)
            except StopIteration:
                handler()
                raise TimeoutError
            conn = MagicMock()
            conn.__enter__.return_value = conn
            conn.selector = {"op": op, "session": "alpha", "attempt": attempt}
            conn.sendall.side_effect = lambda body: replies.append(json.loads(body)["result"])
            return conn, None

    def install(_, callback):
        nonlocal handler
        handler = callback

    def spawn(conn, uid, selector, stock):
        spawned.append(selector["attempt"])
        return child

    monkeypatch.setattr(launcher, "stock_enabled", lambda: True)
    monkeypatch.setattr(launcher.signal, "signal", install)
    monkeypatch.setattr(launcher.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=123))
    monkeypatch.setattr(launcher, "PATH", MagicMock())
    monkeypatch.setattr(launcher.dummy_broker, "listen", lambda *_: nullcontext(Listener()))
    monkeypatch.setattr(launcher, "request", lambda conn, _: conn.selector)
    monkeypatch.setattr(launcher, "spawn", spawn)
    launcher.serve()
    assert spawned == [old, new]
    assert replies == ["pending", "between", "reaped", "unavailable"]


def test_reap_status_rejects_another_launcher_epoch(monkeypatch):
    import io
    import struct
    from unittest.mock import MagicMock

    conn = MagicMock()
    conn.__enter__.return_value = conn
    conn.getsockopt.return_value = struct.pack("3i", 42, 0, 0)
    conn.makefile.side_effect = lambda *_: io.BytesIO(
        b'{"result":"no-owned-launch","epoch":"' + b'a' * 32 + b'"}\n')
    monkeypatch.setattr(launcher.socket, "socket", lambda *_: conn)
    assert launcher.reap_status("alpha", "a" * 12, 1, "b" * 32) == "unavailable"
    assert launcher.reap_status("alpha", "a" * 12, 1, "a" * 32) == "no-owned-launch"


def test_stock_refused_redeem_is_an_exact_pre_spawn_failure(monkeypatch):
    import pytest

    def refused(_):
        raise ValueError("broker refused")

    monkeypatch.setattr(launcher, "redeem", refused)
    monkeypatch.setattr(launcher.subprocess, "Popen", lambda *_a, **_kw: pytest.fail("unexpected spawn"))
    server, client = socket.socketpair()
    with server, client:
        selector = {"op": "launch-redeem", "session": "alpha", "attempt": "a" * 12}
        with pytest.raises(launcher.NoOwnedLaunch):
            launcher.spawn(server, os.getuid(), selector, stock=True)
