"""inbox_binding: enrolled sessions, and which one a bound request reaches, for good."""

import sqlite3
import uuid
from contextlib import closing

import pytest

from inbox_support import accept, authority, enroll, ordered, rows, session, usage

import inbox
import inbox_binding
import lodge_db
import sessions


def written(root):
    return [rows(root, f"SELECT count(*) FROM {t}")[0][0]
            for t in ("inbox_messages", "inbox_events", "inbox_usage")]


def inbox_columns(root, name):
    return rows(root, "SELECT inbox_incarnation, inbox_harness, inbox_conversation, inbox_readiness,"
                      " inbox_generation, inbox_revision FROM sessions WHERE name=?", name)


def test_enrollment_makes_its_own_incarnation_and_freezes_the_session_it_found(tmp_path):
    auth = authority(tmp_path)
    session(tmp_path, "s1")
    record = rows(tmp_path, "SELECT record FROM sessions")
    binding = auth.enroll("s1", harness="claude", conversation="conv-s1", readiness="running",
                          generation="g1")
    assert uuid.UUID(binding.incarnation).version == 4
    assert (binding.name, binding.harness, binding.conversation, binding.status, binding.revision) == (
        "s1", "claude", "conv-s1", "running", 1)
    assert auth.enroll("s1", harness="claude", conversation="conv-s1", readiness="running",
                       generation="g1") == binding  # the same again: no second slot
    assert rows(tmp_path, "SELECT value FROM meta WHERE key='inbox:enrollments'") == [("1",)]
    assert rows(tmp_path, "SELECT record FROM sessions") == record
    for change in (dict(readiness="resting"), dict(generation="g2")):
        with pytest.raises(inbox.Refused, match="already_enrolled"):
            auth.enroll("s1", **{**dict(harness="claude", conversation="conv-s1", readiness="running",
                                        generation="g1"), **change})


@pytest.mark.parametrize("row, ask, code", [
    (None, {}, "no_target"),
    ({}, dict(conversation="conv-other"), "binding_mismatch"),
    ({}, dict(harness="codex"), "binding_mismatch"),
    (dict(status="stopped"), {}, "target_ended"),
    (dict(status="failed"), {}, "target_ended"),
    (dict(status=sessions.STOPPING), {}, "target_stopping"),
    ({}, dict(readiness="awake"), "Invalid"),
    ({}, dict(generation="g" * 41), "Invalid"),
])
def test_enrollment_refuses_what_it_cannot_bind_and_writes_nothing(tmp_path, row, ask, code):
    auth = authority(tmp_path)
    if row is not None:
        session(tmp_path, "s1", **row)
    lodge_db.connect(tmp_path).close()
    before = rows(tmp_path, "SELECT * FROM sessions"), rows(tmp_path, "SELECT * FROM meta")
    with pytest.raises(inbox.InboxError) as caught:
        auth.enroll("s1", **{**dict(harness="claude", conversation="conv-s1", readiness="running",
                                    generation="g1"), **ask})
    assert getattr(caught.value, "code", type(caught.value).__name__) == code
    assert (rows(tmp_path, "SELECT * FROM sessions"), rows(tmp_path, "SELECT * FROM meta")) == before


def test_enrollments_are_counted_for_good_and_refused_past_the_limit(tmp_path):
    auth = authority(tmp_path, enrollments=2)
    enroll(auth, "s1")
    with lodge_db.write(tmp_path) as conn:
        conn.execute("DELETE FROM sessions WHERE name='s1'")
    first = enroll(auth, "s1")  # made again: a new incarnation, and a second slot
    with pytest.raises(inbox.Refused, match="enrollments"):
        enroll(auth, "s2")
    assert inbox_columns(tmp_path, "s2") == [(None,) * 6]
    assert rows(tmp_path, "SELECT inbox_incarnation FROM sessions ORDER BY name") == [(first.incarnation,), (None,)]


def test_a_wolt_request_takes_the_newest_eligible_session_and_never_moves(tmp_path):
    auth = authority(tmp_path)
    picked = enroll(auth, "b", last_activity=20, created_at=2)
    enroll(auth, "c", last_activity=20, created_at=2)  # a tie: the name decides
    early = enroll(auth, "a", last_activity=20, created_at=1)
    session(tmp_path, "d", last_activity=90)  # not enrolled
    enroll(auth, "e", last_activity=80)
    session(tmp_path, "e", status="stopped", last_activity=80)
    enroll(auth, "f", last_activity=70, readiness="unknown")
    enroll(auth, "g", last_activity=60, wolt="nunu")
    first = auth.admit("k1", "wolt", "pal", "hi")
    assert (first.recipient, first.conversation) == (picked.incarnation, "conv-b")
    session(tmp_path, "a", last_activity=99)
    assert auth.admit("k1", "wolt", "pal", "hi") == first
    assert auth.admit("k2", "wolt", "pal", "hi").recipient == early.incarnation
    by_name, by_incarnation = (auth.admit("k3", "session-name", "b", "hi"),
                               auth.admit("k4", "incarnation", picked.incarnation, "hi"))
    assert {(s.recipient, s.conversation) for s in (by_name, by_incarnation)} == {
        (picked.incarnation, "conv-b")}
    assert rows(tmp_path, "SELECT request_kind, request_address, bound_harness FROM inbox_messages"
                          " ORDER BY seq") == [("wolt", "pal", "claude"), ("wolt", "pal", "claude"),
                                               ("session-name", "b", "claude"),
                                               ("incarnation", picked.incarnation, "claude")]


def _ended(tmp_path, auth):
    session(tmp_path, "s1", status="completed")


def _recreated(tmp_path, auth):
    with lodge_db.write(tmp_path) as conn:
        conn.execute("DELETE FROM sessions WHERE name='s1'")
    session(tmp_path, "s1")  # the same name, not enrolled


@pytest.mark.parametrize("change, by_name, by_incarnation", [
    (lambda root, auth: session(root, "s1", status=sessions.STOPPING), "target_stopping", "target_stopping"),
    (_ended, "target_ended", "target_ended"),
    (lambda root, auth: session(root, "s1", status="orphaned"), "target_unknown", "target_unknown"),
    (lambda root, auth: session(root, "s1", status="resting"), "target_unknown", "target_unknown"),
    (lambda root, auth: session(root, "s1", conversation="conv-new"), "binding_mismatch", "binding_mismatch"),
    (lambda root, auth: session(root, "s1", harness="codex"), "binding_mismatch", "binding_mismatch"),
    (_recreated, "target_unbound", "no_target"),
])
def test_a_new_key_for_a_session_that_cannot_take_mail_is_refused_whole(tmp_path, change, by_name,
                                                                         by_incarnation):
    auth = authority(tmp_path)
    binding = enroll(auth, "s1")
    change(tmp_path, auth)
    for kind, address, code in (("session-name", "s1", by_name),
                                ("incarnation", binding.incarnation, by_incarnation),
                                ("wolt", "pal", "no_target")):
        with pytest.raises(inbox.Refused, match=code):
            auth.admit("k1", kind, address, "hi")
    assert written(tmp_path) == [0, 0, 0]


def test_a_resting_session_on_its_own_conversation_takes_mail(tmp_path):
    auth = authority(tmp_path)
    binding = enroll(auth, "s1", status="resting", readiness="resting")
    assert auth.admit("k1", "wolt", "pal", "hi").recipient == binding.incarnation
    with pytest.raises(inbox.Refused, match="no_target"):
        auth.admit("k2", "session-name", "nobody", "hi")
    session(tmp_path, "s2")
    with pytest.raises(inbox.Refused, match="target_unbound"):
        auth.admit("k2", "session-name", "s2", "hi")


@pytest.mark.parametrize("change", ["activity", "ended", "deleted", "full", "purged"])
def test_a_retry_returns_the_original_whatever_became_of_its_session(tmp_path, change):
    auth = authority(tmp_path)
    enroll(auth, "s1", last_activity=20)
    enroll(auth, "s2", last_activity=10)
    first = auth.admit("k1", "wolt", "pal", "héllo")
    if change == "activity":
        session(tmp_path, "s2", last_activity=99)
    elif change == "ended":
        session(tmp_path, "s1", status="stopped", last_activity=20)
    elif change == "deleted":
        with lodge_db.write(tmp_path) as conn:
            conn.execute("DELETE FROM sessions WHERE name='s1'")
    elif change == "full":
        auth = authority(tmp_path, keys=1, pending=1, recipient_pending=1)
        with pytest.raises(inbox.Refused, match="keys"):
            auth.admit("k2", "wolt", "pal", "hi")
    else:
        accept(auth.store, first.recipient, first.conversation)
        first = auth.store.status("k1")
    before = rows(tmp_path, "SELECT * FROM inbox_events"), usage(tmp_path)
    assert auth.admit("k1", "wolt", "pal", "héllo") == first
    for kind, address, body in (("wolt", "nunu", "héllo"), ("session-name", "s1", "héllo"),
                                ("incarnation", first.recipient, "héllo"), ("wolt", "pal", "hello")):
        with pytest.raises(inbox.Conflict):
            auth.admit("k1", kind, address, body)
    with pytest.raises(inbox.Conflict):  # the direct API under a bound key, even to the same place
        auth.store.admit("k1", first.recipient, first.conversation, "héllo")
    assert (rows(tmp_path, "SELECT * FROM inbox_events"), usage(tmp_path)) == before


def test_both_apis_share_one_key_space_and_a_bound_session_only_takes_bound_mail(tmp_path):
    auth = authority(tmp_path)
    binding = enroll(auth, "s1")
    direct = auth.store.admit("k1", "s1", "conv-s1", "hi")
    with pytest.raises(inbox.Conflict):
        auth.admit("k1", "session-name", "s1", "hi")
    with pytest.raises(inbox.Refused, match="bound_recipient"):
        auth.store.admit("k2", binding.incarnation, "conv-s1", "hi")
    assert auth.store.admit("k1", "s1", "conv-s1", "hi") == direct
    assert rows(tmp_path, "SELECT key, request_kind FROM inbox_messages") == [("k1", None)]


@pytest.mark.parametrize("outer", ["lodge_write", "registry"])
def test_bound_calls_refuse_to_run_inside_another_write(tmp_path, outer):
    auth = authority(tmp_path)
    enroll(auth, "s1")
    registry = sessions.SessionRegistry(wolts_dir=tmp_path)
    with (lodge_db.write(tmp_path) if outer == "lodge_write" else registry._tx()):
        for call in (lambda: auth.admit("k1", "wolt", "pal", "hi"),
                     lambda: auth.enroll("s1", harness="claude", conversation="conv-s1",
                                         readiness="running", generation="g1")):
            with pytest.raises(inbox.Refused, match="transaction_conflict"):
                call()
    assert written(tmp_path) == [0, 0, 0]


@pytest.mark.parametrize("bad", [
    dict(kind="name"), dict(address=""), dict(address="a" * 41), dict(key="k" * 41), dict(body=b"hi"),
])
def test_a_malformed_bound_request_is_refused_before_the_store_is_touched(tmp_path, bad):
    auth = authority(tmp_path)
    with pytest.raises(inbox.Invalid):
        auth.admit(**{**dict(key="k1", kind="wolt", address="pal", body="hi"), **bad})
    assert not lodge_db.path(tmp_path).exists()
    with pytest.raises(inbox.Invalid, match="incarnation"):
        authority(tmp_path, name_chars=35)
    with pytest.raises(inbox.Invalid):
        inbox_binding.BindingLimits(0, 40)


def test_bound_admission_reads_through_indexes_not_whole_tables(tmp_path, monkeypatch):
    auth = authority(tmp_path)
    binding = enroll(auth, "s1")
    statements, connect = [], lodge_db.connect

    def traced(*args, **kw):
        conn = connect(*args, **kw)
        conn.set_trace_callback(statements.append)
        return conn

    monkeypatch.setattr(lodge_db, "connect", traced)
    for kind, address in (("wolt", "pal"), ("session-name", "s1"), ("incarnation", binding.incarnation)):
        auth.admit(f"k-{kind}", kind, address, "hi")
    reads = [s for s in statements if s.startswith("SELECT") and ("sessions" in s or "inbox_messages" in s)]
    with closing(sqlite3.connect(lodge_db.path(tmp_path))) as conn:
        plans = [" ".join(r[3] for r in conn.execute(f"EXPLAIN QUERY PLAN {s}")) for s in reads]
    assert plans and not [p for p in plans if "SCAN" in p], plans
    assert any("sessions_inbox_pick" in p for p in plans)


def test_one_key_admitted_by_two_processes_at_once_is_one_message(tmp_path):
    auth = authority(tmp_path)
    enroll(auth, "s1")
    op = ("admit", ["k1", "wolt", "pal", "hi"], {})
    first, second = ordered(op, op, tmp_path / "pause", tmp_path)
    assert first == second and "ok" in first
    assert rows(tmp_path, "SELECT count(*) FROM inbox_messages") == [(1,)]
    assert usage(tmp_path)[""] == (1, 2, 1)


def test_the_last_enrollment_slot_goes_to_one_process_only(tmp_path):
    session(tmp_path, "s1")
    session(tmp_path, "s2")
    ask = dict(harness="claude", readiness="running", generation="g1")
    first, second = ordered(("enroll", ["s1"], {**ask, "conversation": "conv-s1"}),
                            ("enroll", ["s2"], {**ask, "conversation": "conv-s2"}),
                            tmp_path / "pause", tmp_path, enrollments=1)
    assert "ok" in first and second == {"refused": "enrollments"}
    assert rows(tmp_path, "SELECT name FROM sessions WHERE inbox_incarnation IS NOT NULL") == [("s1",)]
