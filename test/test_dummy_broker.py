"""Owner-only dummy broker: real sockets, real files; only the admin uid is mocked to this test's uid."""
import json
import os
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from woltspace import dummy_broker as broker


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "policy"
    path.mkdir(mode=0o700)
    return path


def ask(store, request, admin=True, monkeypatch=None):
    if admin:
        monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())
    ours, theirs = socket.socketpair()  # the kernel reports this process as the peer
    with ours, theirs:
        theirs.sendall(request if isinstance(request, bytes) else json.dumps(request).encode() + b"\n")
        broker.answer(ours, store)
        return json.loads(theirs.recv(256))["result"]


def test_owner_enrolls_registers_grants_runs_and_revokes(store, monkeypatch):
    run = lambda wolt, action=broker.ACTION: ask(store, {"op": "run", "wolt": wolt, "action": action}, monkeypatch=monkeypatch)
    change = lambda op, wolt: ask(store, {"op": op, "wolt": wolt, "action": broker.ACTION}, monkeypatch=monkeypatch)
    assert ask(store, {"op": "enroll", "wolt": "wolt-a"}, monkeypatch=monkeypatch) == "ok"
    assert ask(store, {"op": "enroll", "wolt": "wolt-b"}, monkeypatch=monkeypatch) == "ok"
    assert change("grant", "wolt-a") == "not-registered"
    assert ask(store, {"op": "register", "action": broker.ACTION}, monkeypatch=monkeypatch) == "ok"
    assert change("grant", "wolt-a") == "ok"
    assert change("grant", "wolt-c") == "unknown-wolt"
    assert [run("wolt-a"), run("wolt-b"), run("wolt-c"), run("wolt-a", "other.send")] == [
        "ok", "not-granted", "unknown-wolt", "unknown-action"]
    # Policy is the volume's file, re-read per request: a restarted broker sees the same grants.
    assert json.loads((store / "policy.json").read_text()) == {"version": 1, "wolts": ["wolt-a", "wolt-b"], "grants": ["wolt-a"]}
    assert broker.load(store)["registered"] is True
    assert change("revoke", "wolt-a") == "ok" and run("wolt-a") == "not-granted"
    key = (store / "action.key").read_text()
    audit = [json.loads(line) for line in (store / "audit.log").read_text().splitlines()]
    assert len(audit) == 12 and all(set(entry) == {"caller", "op", "action", "result"} for entry in audit)
    assert {e["caller"] for e in audit} == {"host-admin"} and audit[-1] == {
        "caller": "host-admin", "op": "run", "action": broker.ACTION, "result": "not-granted"}
    for path in store.iterdir():  # the synthetic secret stays in its own file only
        assert path.name == "action.key" or key[:16] not in path.read_text()
    assert {p.name: oct(p.stat().st_mode & 0o777) for p in store.iterdir()} == {
        "policy.json": "0o600", "action.key": "0o400", "audit.log": "0o600"}


@pytest.mark.parametrize("op", ["enroll", "register", "grant", "revoke", "run"])
def test_worker_is_denied_every_operation_and_changes_nothing(store, op):
    request = {"op": op, **{field: ("wolt-a" if field == "wolt" else broker.ACTION) for field in broker.FIELDS[op]}}
    assert ask(store, request, admin=False) == "denied"
    assert sorted(p.name for p in store.iterdir()) == ["audit.log"]
    assert json.loads((store / "audit.log").read_text())["caller"] == "worker"


@pytest.mark.parametrize("raw", [b"not json\n", b"[]\n", b'{"op": "grant", "wolt": "wolt-a"}\n',
    b'{"op": "enroll", "wolt": "wolt-a", "extra": 1}\n', b'{"op": "enroll", "wolt": "Wolt A"}\n',
    b'{"op": "enroll", "wolt": 7}\n', b'{"op": ["enroll"], "wolt": "wolt-a"}\n', b'{"op": {}}\n', b'{"op": "shell", "wolt": "wolt-a"}\n',
    b'{"op": "enroll", "wolt": "' + b"a" * 600 + b'"}\n', b"\xff\n", b""])
def test_malformed_requests_are_refused_without_effect(store, monkeypatch, raw):
    assert ask(store, raw, monkeypatch=monkeypatch) == "invalid"
    assert sorted(p.name for p in store.iterdir()) == ["audit.log"]
    assert json.loads((store / "audit.log").read_text())["op"] in set(broker.FIELDS) | {"other"}


@pytest.mark.parametrize("damage", ["json", "schema", "grant-not-enrolled", "key", "symlink", "mode", "hardlink",
    "dir-mode", "extra-file", "fifo"])
def test_damaged_store_fails_closed(store, monkeypatch, damage, tmp_path):
    for op in ({"op": "enroll", "wolt": "wolt-a"}, {"op": "register", "action": broker.ACTION},
               {"op": "grant", "wolt": "wolt-a", "action": broker.ACTION}):
        assert ask(store, op, monkeypatch=monkeypatch) == "ok"
    policy = store / "policy.json"
    if damage == "json":
        policy.write_text("{")
    elif damage == "schema":
        policy.write_text('{"version": 1, "wolts": ["wolt-a"], "grants": ["wolt-a"], "owner": true}')
    elif damage == "grant-not-enrolled":
        policy.write_text('{"version": 1, "wolts": [], "grants": ["wolt-a"]}')
    elif damage == "key":
        (store / "action.key").chmod(0o600)
        (store / "action.key").write_text("short")
        (store / "action.key").chmod(0o400)
    elif damage == "symlink":
        (tmp_path / "decoy.json").write_text(policy.read_text())
        (tmp_path / "decoy.json").chmod(0o600)  # only the link itself is wrong
        policy.unlink()
        policy.symlink_to(tmp_path / "decoy.json")
    elif damage == "mode":
        policy.chmod(0o644)
    elif damage == "hardlink":
        os.link(policy, tmp_path / "second-name")
    elif damage == "fifo":
        policy.unlink()
        os.mkfifo(policy, 0o600)
    elif damage == "dir-mode":
        store.chmod(0o755)
    else:
        (store / "notes.txt").write_text("unexpected")
    with pytest.raises((ValueError, OSError)):
        broker.load(store)
    assert ask(store, {"op": "run", "wolt": "wolt-a", "action": broker.ACTION}, monkeypatch=monkeypatch) in {"invalid", "error"}


def test_capacity_is_a_fixed_refusal_that_keeps_the_policy_loadable(store, monkeypatch):
    for n in range(64):
        assert ask(store, {"op": "enroll", "wolt": f"wolt-{n}"}, monkeypatch=monkeypatch) == "ok"
    assert ask(store, {"op": "enroll", "wolt": "wolt-x"}, monkeypatch=monkeypatch) == "full"
    assert ask(store, {"op": "enroll", "wolt": "wolt-0"}, monkeypatch=monkeypatch) == "ok"  # already enrolled
    assert len(broker.load(store)["wolts"]) == 64


def test_unclean_stop_leftovers_do_not_block_restart(store, monkeypatch):
    assert ask(store, {"op": "enroll", "wolt": "wolt-a"}, monkeypatch=monkeypatch) == "ok"
    (store / "policy.json.tmp").write_text("half-written")  # a crash between write and rename
    assert broker.load(store)["wolts"] == ["wolt-a"]
    assert ask(store, {"op": "enroll", "wolt": "wolt-b"}, monkeypatch=monkeypatch) == "ok"
    assert not (store / "policy.json.tmp").exists()


def test_admin_client_over_the_real_socket(store, monkeypatch, capsys):
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="wsb.") as short:  # AF_UNIX path limit
        path = Path(short) / "admin.sock"
        server = broker.listen(path)
        server.close()
        server = broker.listen(path)  # a stale socket from an unclean stop is replaced
        with server:
            worker = threading.Thread(target=lambda: broker.answer(server.accept()[0], store))
            worker.start()
            assert broker.admin(["enroll", "wolt-a"], path) == 0
            worker.join(5)
        assert capsys.readouterr().out == '{"result": "ok"}\n'
        assert broker.admin(["enroll", "wolt-a"], path) == 1  # nobody listening: unavailable
        assert broker.admin(["grant", "wolt-a"], path) == 2  # wrong arity never reaches the broker
    assert capsys.readouterr().out == '{"result": "unavailable"}\n'
