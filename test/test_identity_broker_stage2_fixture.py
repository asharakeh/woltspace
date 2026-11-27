"""Exercise the hosted fixture through the actual broker on a private Linux socket."""

import os
from pathlib import Path
import runpy
import socket
import sys
from tempfile import TemporaryDirectory
import threading

import pytest

from woltspace import dummy_broker


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux Unix credentials and inherited channels")
def test_hosted_dispatch_fixture_locally(monkeypatch, capsys):
    # Safe-test owns TMPDIR; use a short name for the Unix address.
    with TemporaryDirectory(prefix="s2-") as scratch:
        root = Path(scratch)
        store = root / "policy"
        store.mkdir(mode=0o700)
        path = root / "a.sock"
        broker = dummy_broker.Broker(store)
        monkeypatch.setattr(dummy_broker, "ADMIN_UID", os.geteuid())
        assert broker.apply({"op": "enroll", "wolt": "wolt-a"})["result"] == "ok"
        assert broker.apply({"op": "register", "action": "dummy.ping"})["result"] == "ok"
        assert broker.apply({"op": "grant", "wolt": "wolt-a", "action": "dummy.ping"})["result"] == "ok"
        stopping = threading.Event()

        def serve(server):
            while not stopping.is_set():
                try:
                    conn, _ = server.accept()
                except socket.timeout:
                    continue
                with conn:
                    broker.answer(conn)

        module = runpy.run_path(str(Path(__file__).with_name("identity_broker_stage2_fixture.py")))
        exercise = module["exercise"]
        exercise.__globals__.update(ADMIN=str(path), REGISTRY=str(store / "registry.db"))
        with dummy_broker.listen(path) as server:
            server.settimeout(0.1)
            thread = threading.Thread(target=serve, args=(server,), daemon=True)
            thread.start()
            try:
                exercise()
                assert capsys.readouterr().out.startswith("dispatch submissions=12 ok=6 denied=3 busy=3 ")
            finally:
                stopping.set()
                thread.join(timeout=5)
                assert not thread.is_alive()
