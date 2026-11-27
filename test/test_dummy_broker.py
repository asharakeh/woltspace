"""Identity broker stage 1: real sockets, real SQLite files; only the admin uid is mocked to this test's uid."""
import json
import os
import socket
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest

from woltspace import dummy_broker as broker

A = broker.ACTION


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "policy"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())


def ask(b, request):
    ours, theirs = socket.socketpair()  # the kernel reports this process as the peer
    with ours, theirs:
        theirs.sendall(request if isinstance(request, bytes) else json.dumps(request).encode() + b"\n")
        theirs.shutdown(socket.SHUT_WR)
        b.answer(ours)
        return json.loads(theirs.recv(256))


def op(b, name, wolt=None, action=A, to=None):
    request = {"op": name, **{f: {"wolt": wolt, "action": action, "to": to}[f] for f in broker.FIELDS[name]}}
    return ask(b, request)["result"]


def rows(store, sql):
    with sqlite3.connect(store / "registry.db") as db:
        return db.execute(sql).fetchall()


def test_owner_ids_grants_rename_retire_and_redacted_audit(store, owner):
    b = broker.Broker(store)
    first, second = (ask(b, {"op": "enroll", "wolt": w}) for w in ("wolt-a", "wolt-b"))
    assert first["result"] == "ok" and first["id"].startswith("p-") and first["id"] != second["id"]
    assert ask(b, {"op": "enroll", "wolt": "wolt-a"}) == first  # replay returns the same stable id
    assert op(b, "grant", "wolt-a") == "not-registered"
    assert op(b, "register") == "ok" and op(b, "grant", "wolt-a") == "ok"
    assert [op(b, "run", w) for w in ("wolt-a", "wolt-b", "wolt-c")] == ["ok", "not-granted", "unknown-wolt"]
    assert op(b, "run", "wolt-a", "other.send") == "unknown-action" and op(b, "grant", "wolt-c") == "unknown-wolt"
    assert op(b, "rename", "wolt-a", to="wolt-b") == "exists" and op(b, "run", "wolt-a") == "ok"
    assert op(b, "rename", "wolt-a", to="wolt-x") == "ok"  # the id and its grant follow the rename
    assert ask(b, {"op": "enroll", "wolt": "wolt-x"})["id"] == first["id"]
    assert [op(b, "run", "wolt-x"), op(b, "run", "wolt-a")] == ["ok", "unknown-wolt"]
    assert op(b, "retire", "wolt-x") == "ok" and op(b, "run", "wolt-x") == "unknown-wolt"
    fresh = ask(b, {"op": "enroll", "wolt": "wolt-x"})  # a recreated name inherits nothing
    assert fresh["id"] not in (first["id"], second["id"]) and op(b, "run", "wolt-x") == "not-granted"
    again = ask(b, {"op": "enroll", "wolt": "wolt-a"})  # the first name, now free, is a new principal too
    assert again["result"] == "ok" and again["id"] not in (first["id"], fresh["id"])
    assert op(b, "revoke", "wolt-b") == "ok"  # nothing to revoke is still a recorded no-op
    assert rows(store, "SELECT id, name, retired FROM principals ORDER BY rowid") == [
        (first["id"], None, 1), (second["id"], "wolt-b", 0), (fresh["id"], "wolt-x", 0), (again["id"], "wolt-a", 0)]
    assert rows(store, "SELECT * FROM grants") == []
    audit = rows(store, "SELECT caller, op, principal, action, result FROM audit")
    assert len(audit) == 23 and {r[0] for r in audit} == {"host-admin"}
    assert audit[-1] == ("host-admin", "revoke", second["id"], A, "ok")
    key = (store / "action.key").read_bytes()
    raw = b"".join(p.read_bytes() for p in store.iterdir() if p.name != "action.key")
    assert all(key[i:i + 16] not in raw for i in range(0, 64, 16))  # custody apart from the registry
    assert b"wolt-a" not in b"".join(str(r).encode() for r in audit)  # audit holds ids, not names
    assert {p.name: oct(p.stat().st_mode & 0o777) for p in store.iterdir()} == {
        "registry.db": "0o600", "action.key": "0o400"}


@pytest.mark.parametrize("name", list(broker.FIELDS))
def test_worker_is_denied_every_operation_and_changes_nothing(store, name):
    b = broker.Broker(store)
    key = (store / "action.key").read_bytes()  # custody is initialized at startup, before any request
    assert op(b, name, "wolt-a", to="wolt-b") == "denied"
    assert rows(store, "SELECT count(*) FROM principals UNION ALL SELECT count(*) FROM resources") == [(0,), (0,)]
    assert rows(store, "SELECT caller, op, principal, result FROM audit") == [("worker", name, None, "denied")]
    assert (store / "action.key").read_bytes() == key


@pytest.mark.parametrize("raw", [b"not json\n", b"[]\n", b'{"op": "grant", "wolt": "wolt-a"}\n',
    b'{"op": "enroll", "wolt": "wolt-a", "extra": 1}\n', b'{"op": "enroll", "wolt": "Wolt A"}\n',
    b'{"op": "enroll", "wolt": 7}\n', b'{"op": ["enroll"], "wolt": "wolt-a"}\n', b'{"op": {}}\n', b'{"op": "enroll", "wolt": "wolt-a"}',
    b'{"op": "enroll", "wolt": "wolt-a", "wolt": "wolt-b"}\n', b'{"op": "enroll", "wolt": "wolt-a"}\n{}\n', b'{"op": "shell", "wolt": "wolt-a"}\n',
    b'{"op": "rename", "wolt": "wolt-a", "to": "../x"}\n', b'{"op": "enroll", "wolt": "' + b"a" * 600 + b'"}\n', b"\xff\n", b""])
def test_malformed_requests_are_refused_without_effect(store, owner, raw):
    b = broker.Broker(store)
    assert ask(b, raw) == {"result": "invalid"}
    assert rows(store, "SELECT count(*) FROM principals") == [(0,)]
    assert rows(store, "SELECT result FROM audit") == [("invalid",)]


def test_restart_or_old_snapshot_keeps_retained_grants_inactive_until_the_owner_grants(store, owner):
    b = broker.Broker(store)
    assert [op(b, "enroll", "wolt-a"), op(b, "register"), op(b, "grant", "wolt-a")] == ["ok"] * 3
    snapshot = (store / "registry.db").read_bytes()  # an old copy, taken while the grant stood
    assert op(b, "revoke", "wolt-a") == "ok" and op(b, "run", "wolt-a") == "not-granted"
    (store / "registry.db").write_bytes(snapshot)  # restore the old media; broker stopped and started
    b = broker.Broker(store)
    assert rows(store, "SELECT count(*) FROM grants") == [(1,)]  # the history row is kept
    assert op(b, "run", "wolt-a") == "inactive"  # ... and confers nothing on its own
    assert op(b, "grant", "wolt-a") == "ok" and op(b, "run", "wolt-a") == "ok"
    b = broker.Broker(store)  # an ordinary restart is conservative too
    assert op(b, "run", "wolt-a") == "inactive" and op(b, "revoke", "wolt-a") == "ok"
    assert op(b, "run", "wolt-a") == "not-granted"


@pytest.mark.parametrize("damage", ["s1-layout", "key-only", "foreign-db", "schema-drift", "version", "garbage",
    "symlink", "mode", "hardlink", "dir-mode", "extra-file", "fifo", "over-capacity", "key-symlink", "key-mode",
    "key-hardlink", "key-malformed"])
def test_incompatible_or_damaged_volume_fails_closed_untouched(store, owner, damage, tmp_path):
    if damage not in {"s1-layout", "key-only"}:
        b = broker.Broker(store)
        assert op(b, "enroll", "wolt-a") == "ok"
        del b
    db = store / "registry.db"
    if damage == "s1-layout":
        (store / "policy.json").write_text('{"version": 1, "wolts": ["wolt-a"], "grants": ["wolt-a"]}')
        (store / "audit.log").write_text("")
    elif damage == "key-only":
        (store / "action.key").write_text("0" * 64)
    elif damage in {"foreign-db", "schema-drift", "version", "over-capacity"}:
        with sqlite3.connect(db) as conn:  # same table names and version still differ from the contract
            conn.executescript({"foreign-db": "CREATE TABLE notes (x)", "version": "PRAGMA user_version = 2",
                "schema-drift": "DROP TABLE audit; CREATE TABLE audit (seq INTEGER PRIMARY KEY, caller, op,"
                                " principal, action, result, body)",
                "over-capacity": "INSERT INTO principals (id, name) SELECT 'p-' || value, 'w' || value"
                                 " FROM json_each('[" + ",".join(map(str, range(65))) + "]')"}[damage])
    elif damage.startswith("key-"):
        key = store / "action.key"
        if damage == "key-symlink":
            (tmp_path / "decoy.key").write_bytes(key.read_bytes())
            (tmp_path / "decoy.key").chmod(0o400)
            key.unlink()
            key.symlink_to(tmp_path / "decoy.key")
        elif damage == "key-mode":
            key.chmod(0o440)
        elif damage == "key-hardlink":
            os.link(key, tmp_path / "second-key")
        else:
            key.chmod(0o600)
            key.write_text("f" * 63 + "\n")
            key.chmod(0o400)
    elif damage == "garbage":
        db.write_bytes(b"not a database" * 100)
    elif damage == "symlink":
        (tmp_path / "decoy.db").write_bytes(db.read_bytes())
        (tmp_path / "decoy.db").chmod(0o600)  # only the link itself is wrong
        db.unlink()
        db.symlink_to(tmp_path / "decoy.db")
    elif damage == "mode":
        db.chmod(0o644)
    elif damage == "hardlink":
        os.link(db, tmp_path / "second-name")
    elif damage == "fifo":
        db.unlink()
        os.mkfifo(db, 0o600)
    elif damage == "dir-mode":
        store.chmod(0o755)
    else:
        (store / "notes.txt").write_text("unexpected")
    before = {p.name: p.lstat().st_mode for p in store.iterdir()}
    content = {p.name: p.read_bytes() for p in store.iterdir() if p.is_file() and not p.is_symlink()}
    with pytest.raises((ValueError, OSError)):
        broker.Broker(store)
    assert {p.name: p.lstat().st_mode for p in store.iterdir()} == before  # nothing wiped or imported
    assert {p.name: p.read_bytes() for p in store.iterdir() if p.is_file() and not p.is_symlink()} == content


def test_a_failed_audit_write_rolls_back_its_mutation_and_a_replay_applies_once(store, owner, monkeypatch):
    b = broker.Broker(store)
    assert [op(b, "enroll", "wolt-a"), op(b, "register")] == ["ok", "ok"]
    real, failed = broker.audit, []

    def audit(db, caller, name, *rest):
        if name == "grant" and not failed:
            failed.append(name)
            raise sqlite3.OperationalError("injected audit write failure")
        return real(db, caller, name, *rest)

    monkeypatch.setattr(broker, "audit", audit)
    assert op(b, "grant", "wolt-a") == "storage-error" and op(b, "run", "wolt-a") == "not-granted"
    assert rows(store, "SELECT count(*) FROM grants") == [(0,)]  # the grant went with its audit row
    assert op(b, "grant", "wolt-a") == "ok" and op(b, "grant", "wolt-a") == "ok"  # replay is idempotent
    assert op(b, "run", "wolt-a") == "ok" and rows(store, "SELECT count(*) FROM grants") == [(1,)]
    assert [r for r in rows(store, "SELECT op, result FROM audit") if r[0] == "grant"] == [("grant", "ok")] * 2


def test_a_failed_commit_keeps_the_narrowing_and_reports_a_storage_error(store, owner):
    b = broker.Broker(store)
    assert [op(b, "enroll", "wolt-a"), op(b, "register"), op(b, "grant", "wolt-a")] == ["ok"] * 3

    def commit():
        raise sqlite3.OperationalError("injected disk failure")

    b.writer.commit = commit
    assert op(b, "revoke", "wolt-a") == "storage-error"
    assert b.authz.admit("wolt-a", A) == "not-granted"  # failure is conservative
    assert rows(store, "SELECT count(*) FROM grants") == [(1,)]
    assert op(broker.Broker(store), "run", "wolt-a") == "inactive"


def until(check):
    deadline = time.monotonic() + 5
    while not check():
        assert time.monotonic() < deadline
        time.sleep(.01)


def test_one_writer_groups_queued_work_orders_narrowing_and_bounds_pending(store, owner, monkeypatch):
    monkeypatch.setattr(broker, "PENDING", 3)
    b = broker.Broker(store)
    assert [op(b, "enroll", w) for w in ("wolt-a", "wolt-b")] + [op(b, "register"), op(b, "grant", "wolt-a")] == ["ok"] * 4
    gate, calls, real = threading.Semaphore(0), [], b.writer.commit

    def commit():  # each commit waits for the test to let it through
        calls.append(1)
        assert gate.acquire(timeout=5)
        real()

    b.writer.commit = commit
    replies = {}
    def later(key, *args):
        thread = threading.Thread(target=lambda: replies.update({key: op(b, *args)}), daemon=True)
        thread.start()
        return thread
    threads = [later("hold", "enroll", "wolt-c")]
    until(lambda: len(calls) == 1)  # the writer is inside a commit; what follows queues behind it
    threads.append(later("revoke-a", "revoke", "wolt-a"))
    until(lambda: b.writer.queue.qsize() == 1)
    assert b.authz.admit("wolt-a", A) == "not-granted"  # narrowed before it is durable
    threads += [later("grant-b", "grant", "wolt-b")]
    until(lambda: b.writer.queue.qsize() == 2)
    threads += [later("regrant-a", "grant", "wolt-a")]
    until(lambda: b.writer.queue.qsize() == 3)
    assert op(b, "revoke", "wolt-b") == "busy"  # bounded: refused at once, and nothing changed for it
    assert b.authz.admit("wolt-b", A) == "not-granted"  # the queued grant is not visible
    gate.release()
    until(lambda: len(calls) == 2)  # the three queued mutations are written, in one commit
    assert b.authz.admit("wolt-b", A) == "not-granted"  # ... and still invisible until it lands
    gate.release()
    for thread in threads:
        thread.join(5)
    assert replies == {"hold": "ok", "revoke-a": "ok", "grant-b": "ok", "regrant-a": "ok"}
    assert len(calls) == 2  # each queued mutation kept its own audit row inside the shared commit
    assert [b.authz.admit(w, A) for w in ("wolt-a", "wolt-b")] == ["ok", "ok"]
    assert rows(store, "SELECT count(*) FROM grants") == [(2,)]
    assert rows(store, "SELECT op, result FROM audit")[-3:] == [("revoke", "ok"), ("grant", "ok"), ("grant", "ok")]


@pytest.mark.parametrize("last", ["revoke", "retire", "rename"])
def test_queued_narrowing_applies_by_id_after_a_queued_enroll_and_grant(store, owner, last):
    b = broker.Broker(store)
    assert op(b, "register") == "ok"
    gate, entered, real = threading.Event(), threading.Event(), b.writer.commit
    b.writer.commit = lambda: (entered.set(), gate.wait(5), real())
    threads = [threading.Thread(daemon=True, target=op, args=(b, "enroll", "wolt-z"))]
    threads[0].start()
    until(entered.is_set)  # wolt-a is not in the snapshot while all three queue
    for n, args in enumerate([("enroll", "wolt-a"), ("grant", "wolt-a"), (last, "wolt-a", A, "wolt-b")]):
        threads.append(threading.Thread(daemon=True, target=op, args=(b, *args)))
        threads[-1].start()
        until(lambda: b.writer.queue.qsize() == n + 1)
    gate.set()
    for thread in threads:
        thread.join(5)
    assert (b.authz.admit("wolt-a", A), b.authz.admit("wolt-b", A)) == {
        "revoke": ("not-granted", "unknown-wolt"), "retire": ("unknown-wolt", "unknown-wolt"),
        "rename": ("unknown-wolt", "ok")}[last]  # the snapshot matches what was committed
    assert rows(store, "SELECT count(*) FROM grants") == [(1 if last == "rename" else 0,)]


@pytest.mark.parametrize("when", ["first", "again"])
def test_register_never_touches_custody_and_a_failed_one_changes_nothing(store, owner, monkeypatch, when):
    b = broker.Broker(store)
    key, real_audit, real_commit = (store / "action.key").read_bytes(), broker.audit, b.writer.commit
    assert op(b, "enroll", "wolt-a") == "ok" and (when == "first" or op(b, "register") == "ok")
    resources = rows(store, "SELECT * FROM resources")

    def audit(db, caller, name, *rest):
        if name == "register":
            raise sqlite3.OperationalError("injected audit write failure")
        return real_audit(db, caller, name, *rest)

    def commit():
        raise sqlite3.OperationalError("injected disk failure")

    monkeypatch.setattr(broker, "audit", audit)
    assert op(b, "register") == "storage-error"
    monkeypatch.setattr(broker, "audit", real_audit)
    b.writer.commit = commit
    assert op(b, "register") == "storage-error"
    b.writer.commit = real_commit
    assert rows(store, "SELECT * FROM resources") == resources and (store / "action.key").read_bytes() == key
    assert op(b, "grant", "wolt-a") == ("not-registered" if when == "first" else "ok")
    assert op(b, "register") == "ok" and op(b, "register") == "ok"  # replay-safe: one row, same custody
    assert len(rows(store, "SELECT * FROM resources")) == 1 and (store / "action.key").read_bytes() == key
    assert op(b, "grant", "wolt-a") == "ok" and op(b, "run", "wolt-a") == "ok"


def test_capacity_is_a_fixed_refusal(store, owner):
    b = broker.Broker(store)
    for n in range(64):
        assert op(b, "enroll", f"wolt-{n}") == "ok"
    assert op(b, "enroll", "wolt-x") == "full" and op(b, "enroll", "wolt-0") == "ok"
    assert op(b, "retire", "wolt-0") == "ok" and op(b, "enroll", "wolt-x") == "ok"
    broker.Broker(store)


def test_admin_client_over_the_real_socket(store, owner, capsys):
    b = broker.Broker(store)
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="wsb.") as short:  # AF_UNIX path limit
        path = Path(short) / "admin.sock"
        broker.listen(path).close()
        server = broker.listen(path)  # a stale socket from an unclean stop is replaced
        with server:
            worker = threading.Thread(target=lambda: b.answer(server.accept()[0]))
            worker.start()
            assert broker.admin(["enroll", "wolt-a"], path) == 0
            worker.join(5)
        reply = json.loads(capsys.readouterr().out)
        assert reply == {"result": "ok", "id": rows(store, "SELECT id FROM principals")[0][0]}
        assert broker.admin(["enroll", "wolt-a"], path) == 1  # nobody listening: unavailable, not a storage error
        assert broker.admin(["rename", "wolt-a"], path) == 2  # wrong arity never reaches the broker
    assert capsys.readouterr().out == '{"result": "unavailable"}\n'


def test_unsafe_custody_fails_the_action_closed(store, owner):
    b = broker.Broker(store)
    assert [op(b, "enroll", "wolt-a"), op(b, "register"), op(b, "grant", "wolt-a")] == ["ok"] * 3
    (store / "action.key").chmod(0o644)
    assert op(b, "run", "wolt-a") == "storage-error" and op(b, "run", "wolt-b") == "unknown-wolt"
