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


def mail(lodge, key="k1", to="pal", human=True):
    return lodge.store.admit("telegram", key, to, "hello", human=human)


def wake_state(lodge):
    return json.loads(rows(lodge.root, "SELECT wake FROM inbox_mailboxes WHERE wolt='pal'")[0][0] or "{}")


def test_no_session_reserves_and_starts_one_with_the_fixed_fetch_instruction(lodge, wake):
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    (kw, locked), = wake.starts
    assert locked and kw["prompt"] == inbox_wake.START and "hello" not in kw["prompt"]
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
    monkeypatch.setattr(inbox_wake, "_wake", lambda root, wolt, once=False: (runs.append(wolt), gate.wait(5)))
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
        sessions.stop_session(name)  # the owner's explicit stop
    else:
        lodge.registry.update(name, status="running", launching={"attempt": "a2"})
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == 1
    if ending == "stopped":
        assert wake_state(lodge)["inhibited"] == "stopped"
        inbox_wake.rearm(lodge.root, "pal")  # the owner's rearm outranks the stop it follows
        deadline = time.monotonic() + 5
        while len(wake.starts) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert len(wake.starts) == 2
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


def test_rearm_is_refused_while_any_launch_of_the_agent_is_unresolved(lodge, unresolved):
    mail(lodge)
    with pytest.raises(lifecycle.LifecycleUnknown):
        inbox_wake.rearm(lodge.root, "pal")
    assert record(lodge, unresolved)["launching"]


# -- native wiring after publication, and definite launch failures ----------------

def test_the_child_prepares_after_publication_and_the_engine_gets_the_attempt(lodge, monkeypatch, tmp_path):
    """run-session.sh prepares in the child, after publish_runtime cleared the marker."""
    monkeypatch.delitem(sys.modules, "native_adapters")
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    row = record(lodge, "pal-a-b-c")
    assert "launching" not in row and row["native"]["attempt"] == row["attempt"]
    command = sessions.prepare_session_command("pal-a-b-c", "spawn", "hi")
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "claude").write_text('#!/bin/sh\nenv | grep ^WOLTSPACE_NATIVE_ > "$OUT"; printf "%s\\n" "$@" >> "$OUT"\n')
    (fake / "claude").chmod(0o755)
    out = tmp_path / "engine.txt"
    subprocess.run(["bash", "-c", command], env={"PATH": f"{fake}:/usr/bin:/bin", "OUT": str(out)},
                   check=True, timeout=30)
    seen = out.read_text().splitlines()
    assert f"WOLTSPACE_NATIVE_ATTEMPT={row['attempt']}" in seen
    assert f"WOLTSPACE_NATIVE_DIR={row['native']['addr']}" in seen
    settings = Path(seen[seen.index("--settings") + 1])
    assert settings.parent == Path(row["native"]["addr"]) and settings.is_file()


def test_a_failed_new_session_is_a_definite_non_start(lodge, monkeypatch):
    def refused(name, cwd, command):
        raise subprocess.CalledProcessError(1, ["tmux", "new-session"])
    monkeypatch.setattr(sessions, "_tmux_spawn", refused)
    with pytest.raises(subprocess.CalledProcessError):
        sessions.start_session(wolt="pal", name="pal-a-b-c")
    row = record(lodge, "pal-a-b-c")
    assert "launching" not in row and (row["status"], row["stop_reason"]) == ("stopped", "launch_failed")
    assert lodge.calls.retired == lodge.calls.prepared  # its attempt is retired
    sessions.delete_session("pal-a-b-c")  # settles normally: nothing UNKNOWN left


def test_a_failed_resume_paste_keeps_the_prior_runtime_and_raises(lodge, monkeypatch):
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    lodge.registry.update("pal-a-b-c", harness_session_id="conv-1")
    before = record(lodge, "pal-a-b-c")
    monkeypatch.setattr(sessions, "resolve_agent_handle", lambda *a, **k: None)
    monkeypatch.setattr(sessions, "_runtime", lambda: types.SimpleNamespace(handle_is_alive=lambda h: True))

    def broken(target, text, settle=0.0):
        raise subprocess.CalledProcessError(1, ["tmux", "paste-buffer"])
    monkeypatch.setattr(sessions, "_tmux_paste", broken)
    with pytest.raises(sessions.ResumeFailed, match="could not be pasted"):
        sessions.resume_session("pal-a-b-c")
    after = record(lodge, "pal-a-b-c")
    assert "launching" not in after and after["runtime"] == before["runtime"]
    assert after["status"] == before["status"] == "running" and "stop_reason" not in after
    assert len(lodge.calls.retired) == 2  # the old attempt before the paste, the failed one after


# -- a1c8ea5: hints despite an inhibition, once per attempt, human mail, owner notice ---------

@pytest.fixture
def notices(monkeypatch):
    told = []
    monkeypatch.setitem(sys.modules, "inbox_notice", types.SimpleNamespace(  # the owner's notices only
        notice=lambda root, wolt, reason, owner: owner and told.append((wolt, reason))))
    return told


def test_an_inhibited_wolt_with_a_live_session_still_gets_its_hint(lodge, wake, notices):
    mail(lodge)
    lodge.store.set_wake("pal", {"inhibited": "not_startable"})
    lodge.registry.create("pal-live", wolt="pal")
    wake.live = "pal-live"
    inbox_wake._wake(str(lodge.root), "pal")
    assert [d[0] for d in lodge.calls.delivered] == ["pal-live"] and not wake.starts and not notices


def test_once_hints_each_attempt_once_and_retries_while_nothing_was_placed(lodge, wake):
    mail(lodge)
    lodge.registry.create("pal-live", wolt="pal")
    lodge.registry.update("pal-live", attempt="a1")
    wake.live = "pal-live"
    results = iter([("pending", "not_ready")] + [("submitted", "ok")] * 3)
    sys.modules["native_adapters"].deliver = lambda record, hint: (
        lodge.calls.delivered.append(record["attempt"]) or next(results))
    for _ in range(3):
        inbox_wake._wake(str(lodge.root), "pal", once=True)
    assert lodge.calls.delivered == ["a1", "a1"]  # retried after not_ready, then never again
    lodge.registry.update("pal-live", attempt="a2")  # a resume: a new attempt
    inbox_wake._wake(str(lodge.root), "pal", once=True)
    assert lodge.calls.delivered == ["a1", "a1", "a2"]
    inbox_wake._wake(str(lodge.root), "pal")  # a new arrival hints regardless
    assert len(lodge.calls.delivered) == 4


@pytest.mark.parametrize("human", [True, False])
def test_any_mail_starts_the_wolt_in_its_own_mode_when_nothing_is_resumable(lodge, wake, human):
    mail(lodge, human=human)
    inbox_wake._wake(str(lodge.root), "pal")
    (kw, _), = wake.starts
    assert not kw.get("require_auto")  # its own recorded mode: never refused for not being auto


def test_the_owner_is_told_whenever_mail_neither_hints_nor_starts(lodge, wake, notices, monkeypatch):
    def refuse(**kw):
        raise PermissionError("prompt mode")
    monkeypatch.setattr(sessions, "start_session", refuse)
    mail(lodge, human=False)  # agent mail only: inbox_notice would stay silent, so none is reserved
    inbox_wake._wake(str(lodge.root), "pal")
    assert notices == []
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")  # not_startable, retried for the owner's mail, refused again
    inbox_wake._wake(str(lodge.root), "pal")  # a repeat wake, a resend, a ready call: no second notice
    assert notices == [("pal", "not_startable")]
    mail(lodge, "k3")  # new owner mail: its own notice
    inbox_wake._wake(str(lodge.root), "pal")
    lodge.registry.create("pal-x", wolt="pal")
    lodge.registry.update("pal-x", launching={"attempt": "a9"})
    inbox_wake._wake(str(lodge.root), "pal")  # same mail, a changed reason: a fresh notice
    inbox_wake._wake(str(lodge.root), "pal")
    assert notices == [("pal", "not_startable"), ("pal", "not_startable"), ("pal", "launch_unknown")]


# -- readiness pickup: announce, validate, schedule once ---------------------------------

def test_only_the_sessions_own_reader_for_its_current_attempt_schedules_a_pickup(lodge, monkeypatch):
    scheduled = []
    monkeypatch.setattr(inbox_wake, "_schedule", lambda root, wolt, once=False: scheduled.append((wolt, once)))
    for name in ("pal-a", "pal-b"):
        lodge.registry.create(name, wolt="pal")
        lodge.registry.update(name, attempt=f"{name}-1", runtime={"x": 1})
    store = inbox.Store(lodge.root, limits(name_chars=64))
    token = store.grant("pal-a", "pal")
    assert inbox_wake.ready(lodge.root, token, "pal-a", "pal-a-1") and scheduled == [("pal", True)]
    assert not inbox_wake.ready(lodge.root, token, "pal-b", "pal-b-1")  # not its own session
    assert not inbox_wake.ready(lodge.root, token, "pal-a", "pal-a-0")  # a stale attempt
    assert not inbox_wake.ready(lodge.root, "t" * 43, "pal-a", "pal-a-1")  # no reader
    lodge.registry.update("pal-a", launching={"attempt": "pal-a-2"})
    assert not inbox_wake.ready(lodge.root, token, "pal-a", "pal-a-1")  # a relaunch in flight
    assert scheduled == [("pal", True)]


def test_a_published_ready_file_announces_itself_once_and_a_failure_is_ignored(tmp_path, monkeypatch):
    import http.server
    import native_adapters
    calls = []

    class Lodge(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            calls.append((self.path, self.headers["X-Woltspace-Inbox-Token"],
                          json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass
    server = http.server.HTTPServer(("127.0.0.1", 0), Lodge)
    threading.Thread(target=server.handle_request, daemon=True).start()
    monkeypatch.setenv("WOLTSPACE_API", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setenv("WOLTSPACE_INBOX_TOKEN", "tok")
    monkeypatch.setenv("WOLTSPACE_WOLT_SESSION", "pal-a")
    assert native_adapters.write_ready(tmp_path, {"attempt": "a1", "kind": "claude"})
    server.server_close()
    assert calls == [("/inbox/ready", "tok", {"session": "pal-a", "attempt": "a1"})]
    monkeypatch.setenv("WOLTSPACE_API", "http://127.0.0.1:9")  # nobody there: still published
    assert native_adapters.write_ready(tmp_path, {"attempt": "a2", "kind": "claude"})


def test_a_resume_that_finds_the_agent_running_schedules_a_pickup(lodge, monkeypatch):
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    picked = []
    monkeypatch.setattr(inbox_wake, "schedule_pickup", lambda root, wolt: picked.append(wolt))
    monkeypatch.setattr(sessions, "resolve_agent_handle",
                        lambda data, harness, include_launching=False: RuntimeHandle("pal-a-b-c", "pal-a-b-c"))
    monkeypatch.setattr(sessions, "_paste_into_live_agent", lambda *a: True)
    monkeypatch.setattr(sessions, "_await_input_ready", lambda *a, **k: True)
    assert sessions.resume_session("pal-a-b-c", "hello")["status"] == "delivered"
    assert picked == ["pal"]


@pytest.mark.parametrize("inhibited, starts", [("not_startable", 1), ("stopped", 0), ("no_progress", 0)])
def test_owner_mail_retries_only_a_policy_refusal(lodge, wake, notices, inhibited, starts):
    mail(lodge)
    lodge.store.set_wake("pal", {"inhibited": inhibited})
    inbox_wake._wake(str(lodge.root), "pal")
    assert len(wake.starts) == starts and not any(kw.get("require_auto") for kw, _ in wake.starts)



def test_whichever_comes_later_of_publication_and_readiness_hints_once(lodge, monkeypatch):
    scheduled = []
    monkeypatch.setattr(inbox_wake, "_schedule", lambda root, wolt, once=False: scheduled.append((wolt, once)))
    store = inbox.Store(lodge.root, limits(name_chars=64))
    early = []

    def spawn(name, cwd, command):  # the backend says ready before its publication
        attempt = record(lodge, name)["launching"]["attempt"]
        early.append(inbox_wake.ready(lodge.root, store.grant(name, "pal"), name, attempt))
        return RuntimeHandle(name, name, "%1")
    monkeypatch.setattr(sessions, "_tmux_spawn", spawn)
    sessions.start_session(wolt="pal", name="pal-a-b-c")
    assert early == [False] and scheduled == [("pal", True)]  # refused while launching; publication schedules
    mail(lodge)  # publication before ready: the pickup finds the backend not ready, which counts for nothing
    monkeypatch.setattr(sessions, "resolve_active_session", lambda wolt, registry=None: "pal-a-b-c")
    results = iter([("pending", "not_ready"), ("submitted", "claimed")])
    sys.modules["native_adapters"].deliver = (
        lambda record_, hint: lodge.calls.delivered.append(record_["attempt"]) or next(results))
    inbox_wake._wake(str(lodge.root), "pal", once=True)  # the publication's pickup
    token = store.grant("pal-a-b-c", "pal")
    assert inbox_wake.ready(lodge.root, token, "pal-a-b-c", record(lodge, "pal-a-b-c")["attempt"])
    inbox_wake._wake(str(lodge.root), "pal", once=True)  # the ready call's pickup
    inbox_wake._wake(str(lodge.root), "pal", once=True)  # a repeat: this attempt is hinted
    assert len(lodge.calls.delivered) == 2


@pytest.mark.parametrize("result", [("unknown", "timeout"), ("failed", "OSError"), ("pending", "not_ready")])
def test_only_a_hint_that_reached_the_engine_counts_once(lodge, wake, result):
    mail(lodge)
    lodge.registry.create("pal-live", wolt="pal")
    lodge.registry.update("pal-live", attempt="a1")
    wake.live = "pal-live"
    sys.modules["native_adapters"].deliver = lambda record_, hint: lodge.calls.delivered.append(1) or result
    inbox_wake._wake(str(lodge.root), "pal", once=True)
    inbox_wake._wake(str(lodge.root), "pal", once=True)
    assert len(lodge.calls.delivered) == 2 and "hinted" not in wake_state(lodge)



# -- resume first (owner, 29 Oct): mail resumes a resting wolt in its own mode, no paste --------

@pytest.fixture
def resting(lodge, monkeypatch):
    """A resting prompt-mode session of pal with a conversation to resume; tmux gone."""
    sessions.start_session(wolt="pal", name="pal-rest", execution_policy="prompt")
    lodge.registry.update("pal-rest", status="resting", harness_session_id="conv-1")
    sent = types.SimpleNamespace(spawned=[], input=[])
    monkeypatch.setattr(sessions, "_tmux_alive", lambda data: False)
    monkeypatch.setattr(sessions, "_await_agent", lambda *a, **k: True)
    monkeypatch.setattr(sessions, "_tmux_spawn", lambda name, cwd, command: sent.spawned.append(command)
                        or RuntimeHandle(name, name, "%2"))
    for typing in ("_tmux_paste", "_tmux_send_keys", "deliver_message"):
        if hasattr(sessions, typing):
            monkeypatch.setattr(sessions, typing, lambda *a, **k: sent.input.append(a))
    monkeypatch.setattr(sessions, "resolve_active_session", lambda wolt, registry=None: None)
    return sent


def test_agent_mail_resumes_a_resting_prompt_mode_wolt_with_no_input_and_a_pickup(lodge, resting, monkeypatch):
    picked = []
    monkeypatch.setattr(inbox_wake, "_schedule", lambda root, wolt, once=False: picked.append((wolt, once)))
    monkeypatch.setattr(sessions, "start_session", lambda **kw: pytest.fail("a new session instead of a resume"))
    mail(lodge, human=False)
    inbox_wake._wake(str(lodge.root), "pal")
    (command,) = resting.spawned
    assert "--resume" in command and "pal-rest" in command and resting.input == []  # nothing typed or pasted
    assert command.endswith("pal-rest --resume")  # no prompt rides along either
    row = record(lodge, "pal-rest")
    assert row["status"] == "running" and row["execution_policy"]["mode"] == "prompt"  # its own mode
    assert wake_state(lodge)["reserved"]["session"] == "pal-rest"
    assert picked == [("pal", True)]  # the post-publication pickup hints once the backend is ready


def test_an_owners_stop_still_blocks_a_resume_and_a_start(lodge, resting, monkeypatch, notices):
    monkeypatch.setattr(sessions, "start_session", lambda **kw: pytest.fail("started after a stop"))
    lodge.registry.update("pal-rest", wake_inhibit=True)  # what stop_session leaves on the record
    mail(lodge, human=False)
    inbox_wake._wake(str(lodge.root), "pal")
    assert resting.spawned == [] and wake_state(lodge)["inhibited"] == "stopped"


@pytest.mark.parametrize("failure", [sessions.ResumeFailed("no agent came up"), subprocess.TimeoutExpired("tmux", 10)])
def test_a_failed_or_unknown_resume_never_falls_back_to_a_new_session(lodge, resting, monkeypatch, failure):
    def resume(name, prompt=""):
        raise failure
    monkeypatch.setattr(sessions, "resume_session", resume)
    monkeypatch.setattr(sessions, "start_session", lambda **kw: pytest.fail("a second worker after a failed resume"))
    mail(lodge, human=False)
    inbox_wake._wake(str(lodge.root), "pal")  # the resume fails: logged, the reservation holds
    assert wake_state(lodge)["reserved"]["session"] == "pal-rest"
    mail(lodge, "k2", human=False)
    inbox_wake._wake(str(lodge.root), "pal")  # still no new session: no_progress per the existing rule
    assert wake_state(lodge)["inhibited"] == "no_progress"
