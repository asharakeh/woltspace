"""Identity broker stage 1: real sockets, real SQLite files; only the admin uid is mocked to this test's uid."""
from array import array
import json
import os
import socket
import sqlite3
import subprocess
import sys
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
    "key-hardlink", "key-malformed", "view-only", "wal"])
def test_incompatible_or_damaged_volume_fails_closed_untouched(store, owner, damage, tmp_path):
    if damage not in {"s1-layout", "key-only", "view-only"}:
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
            conn.executescript({"foreign-db": "CREATE TABLE notes (x)", "version": "PRAGMA user_version = 3",
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
    elif damage == "view-only":  # a clean version-0 file with a schema object that is not ours
        with sqlite3.connect(db) as conn:
            conn.execute("CREATE VIEW v AS SELECT 1")
        db.chmod(0o600)
    elif damage == "wal":
        with sqlite3.connect(db) as conn:
            assert conn.execute("PRAGMA journal_mode = WAL").fetchone() == ("wal",)
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


def test_a_crash_mid_write_leaves_a_hot_journal_that_startup_recovers(store, owner):
    b = broker.Broker(store)
    assert op(b, "enroll", "wolt-a") == "ok"
    before = rows(store, "SELECT * FROM principals")
    crash = subprocess.run([sys.executable, "-I", "-c", """
import os, sqlite3, sys
db = sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute("PRAGMA cache_size = 1")
db.execute("BEGIN IMMEDIATE")
db.executemany("INSERT INTO audit (caller, op, action, result) VALUES ('x', 'x', ?, 'x')", [("x" * 900,)] * 400)
os._exit(0)  # no commit, no rollback: the journal stays hot
""", str(store / "registry.db")], timeout=30)
    assert crash.returncode == 0 and (store / "registry.db-journal").exists()
    b = broker.Broker(store)  # a legitimate journal is recovered, not refused
    assert rows(store, "SELECT * FROM principals") == before and not (store / "registry.db-journal").exists()
    assert op(b, "enroll", "wolt-a") == "ok" and len(rows(store, "SELECT * FROM audit")) == 2


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


def test_admission_never_sees_part_of_a_committed_batch(store, owner):
    b = broker.Broker(store)
    assert op(b, "register") == "ok"
    gate, entered, real = threading.Event(), threading.Event(), b.writer.commit
    b.writer.commit = lambda: (entered.set(), gate.wait(5), real())
    threads = [threading.Thread(daemon=True, target=op, args=(b, "enroll", "wolt-z"))]
    threads[0].start()
    until(entered.is_set)
    for n, args in enumerate([("enroll", "wolt-a"), ("grant", "wolt-a"), ("retire", "wolt-a")]):
        threads.append(threading.Thread(daemon=True, target=op, args=(b, *args)))
        threads[-1].start()
        until(lambda: b.writer.queue.qsize() == n + 1)
    seen, real_drop = [], b.authz.drop

    def drop(*args):  # the retire callback: enroll and grant of this batch are already applied
        reader = threading.Thread(daemon=True, target=lambda: seen.append(b.authz.admit("wolt-a", A)))
        reader.start()
        reader.join(.3)
        seen.append("blocked" if reader.is_alive() else "read")
        real_drop(*args)

    b.authz.drop = drop
    gate.set()
    for thread in threads:
        thread.join(5)
    until(lambda: len(seen) == 2)
    assert seen == ["blocked", "unknown-wolt"]  # a mid-publication read waits and sees only the commit


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


def enrolled(b, name):
    return ask(b, {"op": "enroll", "wolt": name})["id"]


def test_dispatch_binding_instance_and_stable_id_are_checked_separately(store, owner):
    b = broker.Broker(store)
    alpha, beta = enrolled(b, "alpha"), enrolled(b, "beta")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    old = b.dispatch.bind(alpha, "conversation-a")
    other = b.dispatch.bind(beta, "conversation-b")
    assert b.dispatch.bind(beta, "conversation-a") is None
    assert b.dispatch.submit(old._replace(principal=beta), A).result(5) == "denied"
    assert b.dispatch.submit(old._replace(instance=other.instance), A).result(5) == "denied"
    assert b.dispatch.submit(other, A).result(5) == "denied"
    assert b.dispatch.submit(old, "other.send").result(5) == "unknown-action"
    assert b.dispatch.submit(old, A).result(5) == "ok"
    current = b.dispatch.bind(alpha, old.session)
    assert current.instance != old.instance and current.principal == old.principal
    assert b.dispatch.submit(old, A).result(5) == "denied"
    b.dispatch.end(old)  # an old transport closing must not end the replacement
    assert op(b, "rename", "alpha", to="new-alpha") == "ok"
    assert b.dispatch.submit(current, A).result(5) == "ok"
    b.dispatch.end(current)
    assert b.dispatch.submit(current, A).result(5) == "denied"


def test_dispatch_limits_fairness_and_revoke_under_load(store, owner, monkeypatch, record_property):
    b = broker.Broker(store)
    assert op(b, "register") == "ok"
    alpha, beta, gamma = [enrolled(b, name) for name in ("alpha", "beta", "gamma")]
    for name in ("alpha", "beta", "gamma"):
        assert op(b, "grant", name) == "ok"
    sessions = [b.dispatch.bind(alpha, f"a-{i}") for i in range(5)]
    other = [b.dispatch.bind(beta, f"b-{i}") for i in range(5)]
    third = b.dispatch.bind(gamma, "c")
    entered = [threading.Event(), threading.Event()]
    release = [threading.Event(), threading.Event()]
    ticks, calls = [], []
    adapter = b.dispatch._dummy

    def delayed():
        index = len(calls)
        calls.append(time.perf_counter())
        if index < len(entered):
            entered[index].set()
            assert release[index].wait(5)
        return adapter()

    monkeypatch.setattr(b.dispatch, "_dummy", delayed)

    def submit(binding):
        start = time.perf_counter()
        future = b.dispatch.submit(binding, A)
        future.add_done_callback(lambda _: ticks.append(time.perf_counter() - start))
        return future

    start = time.perf_counter()
    try:
        first = submit(sessions[0])
        assert entered[0].wait(5)
        pending = [submit(binding) for binding in sessions[1:4]]
        assert submit(sessions[4]).result(5) == "busy"  # per stable ID across sessions
        second = submit(other[0])
        assert entered[1].wait(5)  # another principal gains the remaining worker
        beta_wait = [submit(binding) for binding in other[1:4]]
        assert submit(third).result(5) == "busy"  # global waiting cap with both slots held
        assert len(calls) == 2
        revoke_start = time.perf_counter()
        assert op(b, "revoke", "alpha") == "ok"
        revoke_latency = time.perf_counter() - revoke_start
        assert len(calls) == 2 and not first.done() and not second.done()
        release[0].set()
        assert first.result(5) == "ok"  # admitted before revoke
        assert [future.result(5) for future in pending] == ["denied"] * 3
        assert submit(third).result(5) == "ok"  # progresses while beta remains held
        assert len(calls) == 3
        release[1].set()
        assert second.result(5) == "ok"
        assert [future.result(5) for future in beta_wait] == ["ok"] * 3
    finally:
        for event in release:
            event.set()
    elapsed = time.perf_counter() - start
    assert rows(store, "SELECT result, count(*) FROM audit WHERE op = 'dispatch' GROUP BY result") == [
        ("denied", 3), ("ok", 6)]
    until(lambda: len(ticks) == 11)
    assert len(calls) == 6
    latency = sorted(ticks)
    for label, index in (("p50_ms", 5), ("p95_ms", 10), ("p99_ms", 10)):
        record_property(label, round(latency[index] * 1000, 3))
    record_property("workload", "11 submissions: 6 ok, 3 denied, 2 busy; fixed 500 ms plus controlled holds")
    record_property("requests_per_second", round(11 / elapsed, 2))
    record_property("revoke_ms", round(revoke_latency * 1000, 3))


@pytest.mark.parametrize("change", ["revoke", "replace", "end"])
def test_dispatch_checks_current_authority_after_intent_commit(store, owner, monkeypatch, change):
    b = broker.Broker(store)
    principal = enrolled(b, "alpha")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    binding = b.dispatch.bind(principal, "a")
    pending, resume = threading.Event(), threading.Event()
    real = b.writer.submit

    def pause_after_commit(work):
        result = real(work)
        if "seq" in result:
            pending.set()
            assert resume.wait(5)
        return result

    monkeypatch.setattr(b.writer, "submit", pause_after_commit)
    future = b.dispatch.submit(binding, A)
    try:
        assert pending.wait(5)
        assert rows(store, "SELECT result FROM audit WHERE op = 'dispatch'") == [("pending",)]
        if change == "revoke":
            assert op(b, "revoke", "alpha") == "ok"
        elif change == "replace":
            assert b.dispatch.bind(principal, "a") != binding
        else:
            b.dispatch.end(binding)
    finally:
        resume.set()
    assert future.result(5) == "denied"
    assert rows(store, "SELECT result FROM audit WHERE op = 'dispatch'") == [("denied",)]


def test_dispatch_crash_leaves_unknown_with_no_replay(store, owner):
    child = subprocess.run([sys.executable, "-I", "-S", "-c", """
import os, runpy, sys
from pathlib import Path
scope = runpy.run_path(sys.argv[1])
b = scope["Broker"](Path(sys.argv[2]))
principal = b.apply({"op": "enroll", "wolt": "alpha"})["id"]
assert b.apply({"op": "register", "action": "dummy.ping"}) == {"result": "ok"}
assert b.apply({"op": "grant", "wolt": "alpha", "action": "dummy.ping"}) == {"result": "ok"}
binding = b.dispatch.bind(principal, "a")
print(binding.instance, flush=True)
b.dispatch._dummy = lambda: os._exit(23)
b.dispatch.submit(binding, "dummy.ping").result(5)
""", broker.__file__, str(store)], capture_output=True, text=True, timeout=15)
    assert child.returncode == 23
    assert rows(store, "SELECT result FROM audit WHERE op = 'dispatch'") == [("pending",)]
    b = broker.Broker(store)
    principal = enrolled(b, "alpha")
    stale = broker.WorkerBinding(principal, "a", child.stdout.strip())
    assert b.dispatch.submit(stale, A).result(5) == "denied"
    current = b.dispatch.bind(principal, "a")
    assert current.instance != stale.instance
    assert b.dispatch.submit(current, A).result(5) == "denied"  # restored grant inactive
    assert op(b, "grant", "alpha") == "ok"
    assert b.dispatch.submit(current, A).result(5) == "ok"
    assert rows(store, "SELECT result FROM audit WHERE op = 'dispatch' ORDER BY seq") == [
        ("unknown",), ("denied",), ("ok",)]


def attach_channel(b, principal, session, *channels):
    request = {"op": "attach", "principal": principal, "session": session}
    client, server = socket.socketpair()
    with client, server:
        payload = json.dumps(request).encode() + b"\n"
        if channels:
            descriptors = array("i", (channel.fileno() for channel in channels))
            client.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)])
        else:
            client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        b.answer(server)
        return json.loads(client.recv(256))["result"]


def packet(channel, hello, **overrides):
    request = {"principal": hello["principal"], "instance": hello["instance"], "action": A}
    channel.send(json.dumps({**request, **overrides}).encode())
    return json.loads(channel.recv(256))["result"]


def test_unprivileged_attach_is_denied_before_descriptor_transfer(store, owner, monkeypatch):
    b = broker.Broker(store)
    principal = enrolled(b, "alpha")
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid() + 1)
    endpoint, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
    with endpoint, worker:
        assert attach_channel(b, principal, "alpha", endpoint) == "denied"
        assert not b.authz.bindings and not b.worker_channels.channels


def test_attached_channels_authorize_packets_and_replace_old_endpoint(store, owner):
    b = broker.Broker(store)
    alpha, beta = enrolled(b, "alpha"), enrolled(b, "beta")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    a_end, a = socket.socketpair(type=socket.SOCK_SEQPACKET)
    b_end, peer = socket.socketpair(type=socket.SOCK_SEQPACKET)
    new_end, replacement = socket.socketpair(type=socket.SOCK_SEQPACKET)
    stream, stream_peer = socket.socketpair()
    with a_end, a, b_end, peer, new_end, replacement, stream, stream_peer:
        for worker in (a, peer, replacement):
            worker.settimeout(5)
        assert attach_channel(b, alpha, "a") == "invalid"
        assert attach_channel(b, alpha, "a", a_end, b_end) == "invalid"
        assert attach_channel(b, alpha, "a", stream) == "invalid"
        assert attach_channel(b, alpha, "a", a_end) == "ok"
        first = json.loads(a.recv(256))
        assert first["result"] == "ok" and first["principal"] == alpha
        assert attach_channel(b, beta, "b", a_end) == "invalid"
        assert attach_channel(b, beta, "a", b_end) == "denied"
        assert attach_channel(b, beta, "b", b_end) == "ok"
        second = json.loads(peer.recv(256))
        a_end.close()
        b_end.close()
        assert packet(a, first, principal=beta) == "denied"
        assert packet(a, first, instance=second["instance"]) == "denied"
        assert packet(peer, second) == "denied"
        assert packet(a, first) == "ok"
        assert attach_channel(b, alpha, "a", new_end) == "ok"
        new_end.close()
        current = json.loads(replacement.recv(256))
        assert current["principal"] == first["principal"] and current["instance"] != first["instance"]
        assert a.recv(256) == b""
        assert packet(replacement, current, instance=first["instance"]) == "denied"
        assert packet(replacement, current) == "ok"
    until(lambda: not b.authz.bindings and not b.worker_channels.channels)


def test_attached_worker_eof_denies_queued_request(store, owner, monkeypatch):
    b = broker.Broker(store)
    alpha = enrolled(b, "alpha")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    running, release = threading.Event(), threading.Event()

    def hold():
        running.set()
        assert release.wait(5)
        return "ok"

    monkeypatch.setattr(b.dispatch, "_dummy", hold)
    direct = b.dispatch.bind(alpha, "running")
    first = b.dispatch.submit(direct, A)
    try:
        assert running.wait(5)
        endpoint, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
        with endpoint, worker:
            worker.settimeout(5)
            assert attach_channel(b, alpha, "a", endpoint) == "ok"
            endpoint.close()
            hello = json.loads(worker.recv(256))
            worker.send(json.dumps({"principal": alpha, "instance": hello["instance"], "action": A}).encode())
            until(lambda: bool(b.dispatch.waiting.get(alpha)))
        worker.close()
    finally:
        release.set()
    assert first.result(5) == "ok"
    until(lambda: "a" not in b.authz.bindings)
    assert rows(store, "SELECT result FROM audit WHERE op = 'dispatch' ORDER BY seq") == [("ok",), ("denied",)]


@pytest.mark.parametrize("side", ["connecting", "accepted"])
def test_attach_refuses_either_side_of_named_seqpacket(store, owner, side):
    b = broker.Broker(store)
    principal = enrolled(b, "alpha")
    with tempfile.TemporaryDirectory(prefix="named-") as root:
        path = str(Path(root) / "listener")
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind(path)
            listener.listen()
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
                peer.connect(path)
                accepted, _ = listener.accept()
                with accepted:
                    channel = peer if side == "connecting" else accepted
                    assert attach_channel(b, principal, "private-session", channel) == "invalid"
    assert not b.authz.bindings
    assert rows(store, "SELECT caller, op, principal, action, result FROM audit WHERE op = 'attach'") == [
        ("host-admin", "attach", principal, "other", "invalid"),
    ]


def test_attach_audit_failure_keeps_previous_binding_and_denies_new_channel(store, owner, monkeypatch):
    b = broker.Broker(store)
    principal = enrolled(b, "alpha")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    original, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
    with original, worker:
        worker.settimeout(5)
        assert attach_channel(b, principal, "private-session", original) == "ok"
        original.close()
        hello = json.loads(worker.recv(256))
        audit = broker.audit

        def fail_attach(db, caller, operation, *args):
            if operation == "attach":
                raise sqlite3.OperationalError("injected attach audit failure")
            return audit(db, caller, operation, *args)

        with monkeypatch.context() as patch:
            patch.setattr(broker, "audit", fail_attach)
            endpoint, replacement = socket.socketpair(type=socket.SOCK_SEQPACKET)
            with endpoint, replacement:
                replacement.settimeout(5)
                assert attach_channel(b, principal, "private-session", endpoint) == "storage-error"
                endpoint.close()
                assert replacement.recv(256) == b""
            assert packet(worker, hello) == "ok"
        assert rows(store, "SELECT caller, op, principal, action, result FROM audit WHERE op = 'attach'") == [
            ("host-admin", "attach", principal, "other", "ok"),
        ]


def launch_exchange(b, request, route):
    server, client = socket.socketpair()
    with server, client:
        client.sendall(json.dumps(request).encode() + b"\n")
        b.answer(server, route)
        raw, ancillary, flags, _ = client.recvmsg(
            512, socket.CMSG_SPACE(array("i").itemsize), socket.MSG_CMSG_CLOEXEC,
        )
        assert not flags & socket.MSG_CTRUNC
        result = json.loads(raw)["result"]
        if not ancillary:
            return result, None
        [(level, kind, data)] = ancillary
        assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
        descriptors = array("i")
        descriptors.frombytes(data)
        [fd] = descriptors
        return result, socket.socket(fileno=fd)


def test_launch_selector_issues_audited_private_socket_once(store, owner, monkeypatch):
    b = broker.Broker(store, node_uid=os.getuid())
    principal = enrolled(b, "alpha")
    assert op(b, "register") == "ok" and op(b, "grant", "alpha") == "ok"
    session = "alpha-" + "a" * 34 + "-sleepy-waterfall-abcdef"
    request = {"session": session, "attempt": "a" * 12}
    launch_open = dict(request, op="launch-open", wolt="alpha")
    redeem = dict(request, op="launch-redeem")
    assert launch_exchange(b, launch_open, "create") == ("denied", None)
    assert launch_exchange(b, launch_open, "launch") == ("ok", None)
    with monkeypatch.context() as patch:
        patch.setattr(broker, "ADMIN_UID", -1)
        assert launch_exchange(b, redeem, "admin") == ("denied", None)
    result, endpoint = launch_exchange(b, redeem, "admin")
    assert result == "ok"
    with endpoint:
        endpoint.settimeout(3)
        hello = json.loads(endpoint.recv(512))
        assert hello["principal"] == principal
        assert packet(endpoint, hello) == "ok"
        assert launch_exchange(b, redeem, "admin") == ("denied", None)
        assert launch_exchange(b, launch_open, "launch") == ("denied", None)
        assert rows(store, "SELECT result FROM audit WHERE op = 'attach'") == [("ok",)]
    until(lambda: not b.authz.bindings)


def test_launch_selectors_refuse_wrong_peer_replaced_cancelled_and_expired(store, owner, monkeypatch):
    b = broker.Broker(store, node_uid=-1)
    enrolled(b, "alpha")
    request = {"session": "alpha-sleepy-bog-abcdef", "attempt": "a" * 12}
    launch_open = dict(request, op="launch-open", wolt="alpha")
    assert launch_exchange(b, launch_open, "launch") == ("denied", None)
    b.node_uid = os.getuid()
    assert launch_exchange(b, launch_open, "launch") == ("ok", None)
    replacement = dict(launch_open, attempt="b" * 12)
    assert launch_exchange(b, replacement, "launch") == ("ok", None)
    assert launch_exchange(b, dict(request, op="launch-redeem"), "admin") == ("denied", None)
    second = {"session": replacement["session"], "attempt": replacement["attempt"]}
    assert launch_exchange(b, dict(second, op="launch-cancel"), "launch") == ("ok", None)
    assert launch_exchange(b, dict(second, op="launch-redeem"), "admin") == ("denied", None)
    monkeypatch.setattr(broker, "ATTEMPT_TTL", 0)
    expired = dict(request, attempt="c" * 12)
    assert launch_exchange(b, dict(expired, op="launch-open", wolt="alpha"), "launch") == ("ok", None)
    assert launch_exchange(b, dict(expired, op="launch-redeem"), "admin") == ("denied", None)
    assert not b.authz.bindings


def test_launch_audit_gates_selector_publication_and_records_refusals(store, owner, monkeypatch):
    b = broker.Broker(store, node_uid=os.getuid())
    principal = enrolled(b, "alpha")
    selector = {"session": "alpha-audit", "attempt": "a" * 12}
    request = dict(selector, op="launch-open", wolt="alpha")
    redeem = dict(selector, op="launch-redeem")
    original = broker.audit

    def fail_open(db, caller, operation, *args):
        if operation == "launch-open":
            raise sqlite3.OperationalError("injected audit failure")
        return original(db, caller, operation, *args)

    with monkeypatch.context() as patch:
        patch.setattr(broker, "audit", fail_open)
        assert launch_exchange(b, request, "launch") == ("storage-error", None)
    assert launch_exchange(b, redeem, "admin") == ("denied", None)
    assert launch_exchange(b, request, "launch") == ("ok", None)
    assert launch_exchange(b, dict(selector, op="launch-cancel"), "launch") == ("ok", None)
    assert launch_exchange(b, redeem, "admin") == ("denied", None)
    assert rows(store, "SELECT caller, op, principal, result FROM audit WHERE op LIKE 'launch-%' ORDER BY seq") == [
        ("host-admin", "launch-redeem", None, "denied"),
        ("node", "launch-open", principal, "ok"),
        ("node", "launch-cancel", principal, "ok"),
        ("host-admin", "launch-redeem", None, "denied"),
    ]


def test_refusals_from_non_owners_are_audited_up_to_a_budget_per_window(store, owner, monkeypatch):
    b = broker.Broker(store, node_uid=-1)  # this caller is no node: every launch-route call is refused
    clock = [100.0]
    monkeypatch.setattr(broker.time, "monotonic", lambda: clock[0])

    def flood(n, route="launch"):
        return {launch_exchange(b, {"op": "launch-open"}, route)[0] for _ in range(n)}

    def counted(result):
        return rows(store, f"SELECT count(*) FROM audit WHERE op = 'launch-control' AND result = '{result}'")[0][0]

    assert flood(broker.DENIALS + 20) == {"denied"}  # always refused ...
    assert (counted("denied"), counted("suppressed")) == (broker.DENIALS, 1)  # ... recorded up to the budget
    status = {"op": "create-status", "request": "f" * 32}  # well formed, refused by the lifecycle itself
    assert {b.create("worker", status)["result"] for _ in range(broker.DENIALS + 5)} == {"unknown-request"}
    assert rows(store, "SELECT result, count(*) FROM audit WHERE op = 'create-status' GROUP BY result ORDER BY result") == [
        ("suppressed", 1), ("unknown-request", broker.DENIALS)]
    request = {"op": "create-request", "request": "e" * 32, "terms": {k: "" for k in broker.TERMS} | {
        "name": "wolt-z", "type": "beaver"}}
    assert b.create("worker", request)["result"] == "ok"  # successful transitions are never limited,
    assert b.create("worker", dict(status, request="e" * 32))["status"] == "pending"  # even past a spent budget
    clock[0] += broker.DENIAL_WINDOW
    assert flood(1) == {"denied"} and counted("denied") == broker.DENIALS + 1  # a new window records again
    assert [op(b, "enroll", f"w{i}") for i in range(broker.DENIALS + 2)] == ["ok"] * (broker.DENIALS + 2)
    assert rows(store, "SELECT count(*) FROM audit WHERE caller = 'host-admin' AND op = 'enroll'") == [
        (broker.DENIALS + 2,)]  # the owner is never limited, refusals included:
    assert {ask(b, b"not json\n")["result"] for _ in range(broker.DENIALS + 2)} == {"invalid"}
    assert rows(store, "SELECT count(*) FROM audit WHERE caller = 'host-admin' AND result = 'invalid'") == [
        (broker.DENIALS + 2,)]
