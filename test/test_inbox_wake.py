"""The agent lifecycle lock, the launch marker and its publication, and the inbox
wake (lifecycle.py, sessions.py, inbox_wake.py): real lodge.db, real flock, a
fake tmux and a fake native transport."""

import json
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pytest

from inbox_support import limits, rows, wolt

import inbox
import inbox_wake
import lifecycle
import sessions
from session_runtime import RuntimeHandle

LOCK = lifecycle._HELD


def held(root, name="pal"):
    """True while this thread holds the agent's lifecycle lock."""
    key = str(Path(root) / ".space" / "run" / "lifecycle" / f"{name}.lock")
    return bool(LOCK.__dict__.get("counts", {}).get(key))


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    """A lodge with the inbox on, the wolt pal (auto policy), a fake tmux and transport."""
    (tmp_path / ".space").mkdir()
    monkeypatch.setenv("WOLTSPACE_ISOLATION", "external")  # auto policy, whatever ran before
    (tmp_path / "woltspace.json").write_text(json.dumps({"inbox": {"enabled": True}}))
    wolt(tmp_path, "pal")
    for module, attr in ((sessions, "WOLTS_DIR"),):
        monkeypatch.setattr(module, attr, tmp_path)
    calls = types.SimpleNamespace(spawned=[], stopped=[], delivered=[], prepared=[], retired=[])

    def spawn(name, cwd, command):
        record = sessions.SessionRegistry(tmp_path).get(name, check_alive=False)
        calls.spawned.append((name, dict(record.get("launching") or {}), held(tmp_path)))
        return RuntimeHandle(woltspace_session_id=name, tmux_session_name=name, pane_id="%1")

    monkeypatch.setattr(sessions, "_tmux_spawn", spawn)
    monkeypatch.setattr(sessions, "_tmux_stop", lambda data: calls.stopped.append(data) or True)
    monkeypatch.setattr(sessions, "_tmux_alive", lambda data: True)
    monkeypatch.setattr(sessions, "harness_install_problem", lambda *a, **k: None)
    monkeypatch.setattr(sessions, "ensure_site", lambda wolt: None)
    monkeypatch.setattr(sessions, "get_tunnel_url", lambda: "")
    native = types.SimpleNamespace(
        prepare=lambda root, name, harness, attempt: calls.prepared.append(attempt) or {
            "kind": harness, "addr": str(root / ".space" / name / attempt), "attempt": attempt},
        retire=lambda locator: calls.retired.append(locator["attempt"]),
        deliver=lambda record, hint: calls.delivered.append((record.get("name"), hint, held(tmp_path)))
        or ("submitted", "ok"))
    monkeypatch.setitem(sys.modules, "native_adapters", native)
    lodge = types.SimpleNamespace(root=tmp_path, calls=calls, registry=sessions.SessionRegistry(tmp_path),
                                  store=inbox.Store(tmp_path, limits()))
    monkeypatch.setattr(inbox, "LIMITS", limits())
    return lodge


def record(lodge, name):
    return lodge.registry.get(name, check_alive=False)


# -- the lock -------------------------------------------------------------------

def test_the_lock_is_reentrant_and_another_process_waits_for_it(lodge):
    holder = ("import fcntl, os, sys, time; fd = os.open(sys.argv[1], os.O_RDWR);"
              " fcntl.flock(fd, fcntl.LOCK_EX); print('held', flush=True); time.sleep(30)")
    with lifecycle.agent_lock(lodge.root, "pal"):
        with lifecycle.agent_lock(lodge.root, "pal"):
            assert held(lodge.root)
        assert held(lodge.root)
    assert not held(lodge.root)
    path = lodge.root / ".space" / "run" / "lifecycle" / "pal.lock"
    other = subprocess.Popen([sys.executable, "-c", holder, str(path)], stdout=subprocess.PIPE, text=True)
    try:
        assert other.stdout.readline().strip() == "held"
        with pytest.raises(lifecycle.LifecycleBusy):
            with lifecycle.agent_lock(lodge.root, "pal", wait=0.3):
                pass
        with lifecycle.agent_lock(lodge.root, "nunu", wait=0.3):  # per agent
            pass
    finally:
        other.kill()
        other.wait()
    with lifecycle.agent_lock(lodge.root, "pal", wait=0.3):
        pass


def test_a_child_started_under_the_lock_does_not_keep_it(lodge):
    with lifecycle.agent_lock(lodge.root, "pal"):
        child = subprocess.Popen(["sleep", "30"])
    try:
        probe = subprocess.run([sys.executable, "-c", (
            "import fcntl, os, sys; fd = os.open(sys.argv[1], os.O_RDWR);"
            " fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)"),
            str(lodge.root / ".space" / "run" / "lifecycle" / "pal.lock")], timeout=10)
        assert probe.returncode == 0
    finally:
        child.kill()
        child.wait()


# -- the launch marker and its publication ----------------------------------------

def test_a_start_marks_the_attempt_before_the_spawn_and_publishes_it_in_one_write(lodge):
    started = sessions.start_session(wolt="pal", prompt="hi", name="pal-a-b-c")
    (name, marker, locked), = lodge.calls.spawned
    assert name == started["name"] == "pal-a-b-c" and locked
    assert marker["attempt"] and marker["native"]["attempt"] == marker["attempt"]
    assert Path(marker["native"]["addr"]).parent.name == name
    data = record(lodge, name)
    assert "launching" not in data and data["attempt"] == marker["attempt"]
    assert data["native"] == marker["native"] and data["runtime"]["pane_id"] == "%1"


def test_publication_needs_the_exact_attempt(lodge):
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    attempt = sessions.mark_launching(lodge.registry, "pal-a-b-c", "pal", "claude")
    assert not sessions.publish_runtime(lodge.registry, "pal-a-b-c", "pal", "other", {"x": 1})
    assert record(lodge, "pal-a-b-c")["launching"]["attempt"] == attempt
    assert sessions.publish_runtime(lodge.registry, "pal-a-b-c", "pal", attempt, {"x": 1})
    assert not sessions.publish_runtime(lodge.registry, "pal-a-b-c", "pal", attempt, {"y": 2})
    assert record(lodge, "pal-a-b-c")["runtime"] == {"x": 1}


def test_with_the_inbox_off_there_is_no_locator_and_the_command_is_unchanged(lodge, monkeypatch):
    (lodge.root / "woltspace.json").write_text("{}")
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    assert lodge.calls.spawned[0][1]["native"] is None and "native" not in record(lodge, "pal-a-b-c")
    assert not lodge.calls.prepared


@pytest.fixture
def unresolved(lodge, monkeypatch):
    """A start whose spawn never returned: the attempt stays marked."""
    def lost(name, cwd, command):
        raise subprocess.TimeoutExpired("tmux", 10)
    monkeypatch.setattr(sessions, "_tmux_spawn", lost)
    with pytest.raises(subprocess.TimeoutExpired):
        sessions.start_session(wolt="pal", name="pal-a-b-c")
    assert record(lodge, "pal-a-b-c")["launching"]
    return "pal-a-b-c"


@pytest.mark.parametrize("end", [sessions.stop_session, sessions.archive_session, sessions.delete_session])
def test_an_unresolved_launch_is_cleaned_up_but_never_settled(lodge, unresolved, end):
    before = record(lodge, unresolved)
    with pytest.raises(lifecycle.LifecycleUnknown):
        end(unresolved)
    assert lodge.calls.stopped  # the cleanup was still attempted
    after = record(lodge, unresolved)
    assert after["status"] == before["status"] == "running" and after["launching"] == before["launching"]


def test_no_reaper_adoption_or_relaunch_settles_an_unresolved_launch(lodge, unresolved, monkeypatch):
    monkeypatch.setattr(sessions, "_tmux_sessions", lambda: set())
    assert lodge.registry.reconcile() == []
    report = lodge.registry.adopt_runtime_sessions()
    assert {"session": unresolved, "wolt": "pal", "reason": "unresolved launch"} in report["unchanged"]
    seen = record(lodge, unresolved)
    assert sessions.stop_and_settle(lodge.registry, unresolved, seen, lambda s: True,
                                    lambda r: r.update(status="stopped"), wolt="pal") is None
    with pytest.raises(sessions.ResumeFailed, match="unresolved launch"):
        with sessions._relaunch(lodge.registry, unresolved, "pal", "claude"):
            pass
    assert record(lodge, unresolved)["status"] == "running" and record(lodge, unresolved)["launching"]


def test_a_relaunch_is_a_new_attempt_and_its_wait_runs_after_the_lock(lodge, monkeypatch):
    first = sessions.start_session(wolt="pal", name="pal-a-b-c")["name"]
    old = record(lodge, first)
    waits = []
    monkeypatch.setattr(sessions, "_tmux_alive", lambda data: False)
    monkeypatch.setattr(sessions, "_await_agent", lambda *a, **k: waits.append(held(lodge.root)) or True)
    lodge.registry.update(first, harness_session_id="conv-1")
    assert sessions.resume_session(first)["status"] == "respawned"
    new = record(lodge, first)
    assert new["attempt"] != old["attempt"] and new["native"]["attempt"] == new["attempt"]
    assert lodge.calls.retired == [old["attempt"]]  # retired before the replacement
    assert lodge.calls.spawned[-1][2] and waits == [False]


def test_stop_retires_the_locator_before_tmux_stops(lodge, monkeypatch):
    name = sessions.start_session(wolt="pal", name="pal-a-b-c")["name"]
    order = []
    monkeypatch.setattr(sessions, "_tmux_stop", lambda data: order.append(("stop", list(lodge.calls.retired))))
    sessions.stop_session(name)
    assert order == [("stop", [record(lodge, name).get("attempt")])]
    assert record(lodge, name)["status"] == "stopped" and "native" not in record(lodge, name)


# -- the wake ---------------------------------------------------------------------

@pytest.fixture
def wake(lodge, monkeypatch):
    """The wake's view of sessions, controlled: live session and fake starts."""
    state = types.SimpleNamespace(live=None, starts=[])

    def start(**kw):
        state.starts.append((kw, held(lodge.root)))
        sessions.SessionRegistry(lodge.root).create(kw["name"], wolt=kw["wolt"])
        sessions.SessionRegistry(lodge.root).update(kw["name"], attempt="a1", runtime={"x": 1})
        return {"name": kw["name"]}
    monkeypatch.setattr(sessions, "resolve_active_session", lambda wolt, registry=None: state.live)
    monkeypatch.setattr(sessions, "start_session", start)
    return state


def mail(lodge, key="k1", to="pal"):
    return lodge.store.admit("telegram", key, to, "hello", human=True)


def wake_state(lodge):
    return json.loads(rows(lodge.root, "SELECT wake FROM inbox_mailboxes WHERE wolt='pal'")[0][0] or "{}")


def test_no_session_reserves_and_starts_one_with_the_fixed_fetch_instruction(lodge, wake):
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    (kw, locked), = wake.starts
    assert locked and kw["require_auto"] and kw["prompt"] == inbox_wake.START and "hello" not in kw["prompt"]
    assert wake_state(lodge)["reserved"]["session"] == kw["name"]
    assert rows(lodge.root, "SELECT state FROM inbox_messages") == [("queued",)]  # no claim, no ack


def test_a_live_session_gets_one_hint_after_the_lock_and_custody_is_unchanged(lodge, wake):
    mail(lodge)
    wake.live = "pal-live"
    lodge.registry.create("pal-live", wolt="pal")
    for result in ("submitted", "unknown", "failed", "unavailable", "pending"):
        lodge.calls.delivered.clear()
        sys.modules["native_adapters"].deliver = (
            lambda record, hint, r=result: lodge.calls.delivered.append((record["name"], hint, held(lodge.root)))
            or (r, "x"))
        inbox_wake._wake(str(lodge.root), "pal")
        (name, hint, locked), = lodge.calls.delivered
        assert name == "pal-live" and not locked and "woltspace inbox fetch" in hint and "hello" not in hint
    assert not wake.starts
    assert rows(lodge.root, "SELECT state, body FROM inbox_messages") == [("queued", b"hello")]


@pytest.mark.parametrize("why", ["off", "nothing_queued", "archived"])
def test_nothing_happens_without_eligible_mail(lodge, wake, why):
    status = mail(lodge)
    if why == "off":
        (lodge.root / "woltspace.json").write_text("{}")
        inbox_wake.notify_admitted(lodge.root, status)
        time.sleep(0.2)
    else:
        if why == "nothing_queued":
            with sessions.lodge_db.write(lodge.root) as conn:
                conn.execute("UPDATE inbox_messages SET state='acknowledged', acked_at=?", (time.time(),))
        else:
            lodge.store.set_state("pal", "archived")
        inbox_wake._wake(str(lodge.root), "pal")
    assert not wake.starts and not lodge.calls.delivered


def test_a_burst_coalesces_into_one_wake_and_never_raises(lodge, monkeypatch):
    runs, gate = [], threading.Event()
    monkeypatch.setattr(inbox_wake, "_wake", lambda root, wolt: (runs.append(wolt), gate.wait(5)))
    statuses = [mail(lodge, f"k{i}") for i in range(8)]
    for status in statuses:
        inbox_wake.notify_admitted(lodge.root, status)
    gate.set()
    deadline = time.monotonic() + 5
    while inbox_wake._PENDING and time.monotonic() < deadline:
        time.sleep(0.05)
    assert runs == ["pal", "pal"]  # the one running, then one for everything that came meanwhile
    monkeypatch.setattr(inbox, "enabled", lambda root: 1 / 0)
    inbox_wake.notify_admitted(lodge.root, statuses[0])  # logged, never raised


def test_a_reserved_session_without_an_ack_inhibits_until_rearm(lodge, wake):
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    name = wake.starts[0][0]["name"]
    lodge.registry.update(name, status="completed")
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == 1 and wake_state(lodge)["inhibited"] == "no_progress"
    mail(lodge, "k3")  # new mail never clears it
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == 1
    inbox_wake.rearm(lodge.root, "pal")
    deadline = time.monotonic() + 5
    while len(wake.starts) < 2 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert len(wake.starts) == 2


def test_progress_lets_the_next_mail_start_a_fresh_session(lodge, wake):
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    name = wake.starts[0][0]["name"]
    with sessions.lodge_db.write(lodge.root) as conn:
        conn.execute("INSERT INTO inbox_readers(hash, mailbox, session, created_at, acks)"
                     " VALUES (x'01', 1, ?, 0, 1)", (name,))
    lodge.registry.update(name, status="completed")
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == 2 and "inhibited" not in wake_state(lodge)


@pytest.mark.parametrize("ending", ["stopped", "unresolved"])
def test_an_explicit_stop_inhibits_and_an_unresolved_launch_waits(lodge, wake, ending):
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    name = wake.starts[0][0]["name"]
    if ending == "stopped":
        lodge.registry.update(name, status="stopped")
    else:
        lodge.registry.update(name, status="running", launching={"attempt": "a2"})
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == 1
    if ending == "stopped":
        assert wake_state(lodge)["inhibited"] == "stopped"
    else:
        assert "inhibited" not in wake_state(lodge)
        with pytest.raises(lifecycle.LifecycleUnknown):
            inbox_wake.rearm(lodge.root, "pal")


def test_a_policy_that_is_not_auto_inhibits_instead_of_starting(lodge, wake, monkeypatch):
    def refuse(**kw):
        raise PermissionError("not auto")
    monkeypatch.setattr(sessions, "start_session", refuse)
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    assert wake_state(lodge)["inhibited"] == "not_startable"


def test_boot_reconcile_wakes_every_agent_with_queued_mail(lodge, monkeypatch):
    woken = []
    monkeypatch.setattr(inbox_wake, "_schedule", lambda root, wolt: woken.append(wolt))
    wolt(lodge.root, "nunu")
    mail(lodge)
    mail(lodge, "k2", "nunu")
    inbox_wake.reconcile(lodge.root)
    assert sorted(woken) == ["nunu", "pal"]
