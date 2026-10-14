"""No paste until the agent's input is live (#555, part B).

Finding the agent process is not enough: Claude Code's process exists about a
second before its input handler mounts, and a paste in that gap is lost. Every
TUI we run takes its terminal raw when input goes live, so delivery waits for
the pane's tty to leave cooked mode — outside any session lock — and refuses,
rather than pastes, when it never does.

Fake runtimes and a fake clock throughout: no tmux, no real waiting.
"""

import os
import pty
import subprocess
import sys
import time
import tty
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "container"))
sys.path.insert(0, str(ROOT / "container" / "lib"))

import sessions  # noqa: E402
from harnesses import LAUNCHING_NAMES  # noqa: E402
from runtime_context import RuntimeContext  # noqa: E402
from session_runtime import (  # noqa: E402
    RuntimeHandle,
    SessionRuntime,
    TmuxSessionRuntime,
    set_runtime,
)

from conftest import FakeSessionRuntime  # noqa: E402


NAME = "pal-boot-den-abc123"
PANE = "%5"


# ---------------------------------------------------------------------------
# The tty check, on a real pty
# ---------------------------------------------------------------------------

@pytest.fixture
def pty_pair():
    master, slave = pty.openpty()
    try:
        yield SimpleNamespace(slave=slave, path=os.ttyname(slave))
    finally:
        os.close(slave)
        os.close(master)


class TestTtyIsRaw:
    def test_a_cooked_terminal_is_not_raw(self, pty_pair):
        from session_runtime import tty_is_raw
        assert tty_is_raw(pty_pair.path) is False

    def test_a_terminal_set_raw_is_raw(self, pty_pair):
        from session_runtime import tty_is_raw
        tty.setraw(pty_pair.slave)
        assert tty_is_raw(pty_pair.path) is True

    def test_a_missing_tty_is_unknown(self, tmp_path):
        from session_runtime import tty_is_raw
        assert tty_is_raw(str(tmp_path / "no-such-tty")) is None

    def test_a_file_that_is_not_a_terminal_is_unknown(self, tmp_path):
        from session_runtime import tty_is_raw
        plain = tmp_path / "plain"
        plain.write_text("")
        assert tty_is_raw(str(plain)) is None


# ---------------------------------------------------------------------------
# The probe reads the exact persisted pane
# ---------------------------------------------------------------------------

class _Runner:
    """subprocess.run stand-in answering `display-message` with a tty path."""

    def __init__(self, tty_path="", error=None):
        self.tty_path = tty_path
        self.error = error
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if self.error is not None:
            raise self.error
        return SimpleNamespace(stdout=f"{self.tty_path}\n", returncode=0)


class TestInputReadyProbe:
    def _runtime(self, runner):
        return TmuxSessionRuntime(RuntimeContext(tmux_bin="tmux-test"), runner=runner)

    def test_is_part_of_the_runtime_contract(self):
        assert "input_ready" in SessionRuntime.__dict__
        assert isinstance(FakeSessionRuntime(), SessionRuntime)

    def test_reads_the_tty_of_the_handles_own_pane(self, pty_pair):
        runner = _Runner(pty_pair.path)
        handle = RuntimeHandle(NAME, "persisted-tmux", "%42")

        assert self._runtime(runner).input_ready(handle) is False
        # The pane id, never the session: tmux resolves a session name to
        # whichever pane is active, which need not be the one we paste into.
        assert runner.calls == [
            ["tmux-test", "display-message", "-p", "-t", "%42", "#{pane_tty}"],
        ]

    def test_a_raw_pane_is_ready(self, pty_pair):
        tty.setraw(pty_pair.slave)
        runner = _Runner(pty_pair.path)
        handle = RuntimeHandle(NAME, NAME, "%42")
        assert self._runtime(runner).input_ready(handle) is True

    @pytest.mark.parametrize("pane", ["", NAME])
    def test_without_an_exact_pane_there_is_no_answer(self, pane):
        runner = _Runner("/dev/pts/0")
        handle = RuntimeHandle(NAME, NAME, pane)
        assert self._runtime(runner).input_ready(handle) is None
        assert runner.calls == []

    def test_a_pane_tmux_cannot_find_is_unknown(self):
        runner = _Runner(error=subprocess.CalledProcessError(1, "tmux"))
        assert self._runtime(runner).input_ready(RuntimeHandle(NAME, NAME, "%42")) is None

    def test_a_pane_without_a_tty_is_unknown(self):
        runner = _Runner("")
        assert self._runtime(runner).input_ready(RuntimeHandle(NAME, NAME, "%42")) is None


# ---------------------------------------------------------------------------
# A session that boots on a script
# ---------------------------------------------------------------------------

class Clock:
    """Stands in for the sessions module's `time`: sleeping advances it.

    Every sleep moves the booting script one step on, so a test reads as a
    timeline of what the lodge saw at each look.
    """

    def __init__(self):
        self.now = 0.0
        self.sleeps = 0
        self.events = []

    def monotonic(self):
        return self.now

    def time(self):
        return time.time()

    def sleep(self, seconds):
        self.events.append(("sleep", seconds))
        self.now += seconds
        self.sleeps += 1


class BootingRuntime(FakeSessionRuntime):
    """One pane whose processes and terminal mode follow a script.

    Each step is (process, raw): process is "agent" (the harness is up, under
    run-session.sh), "shim" (only run-session.sh, still launching) or "none"
    (a husk); raw is what the pane's terminal reports. The last step holds.
    """

    def __init__(self, clock, steps, *, alive=True):
        super().__init__(alive=alive, panes=[(PANE, "100", True)])
        self.clock = clock
        self.steps = steps

    @property
    def step(self):
        return self.steps[min(self.clock.sleeps, len(self.steps) - 1)]

    def _matching_panes_for_handle(self, handle, process_names):
        panes = self.panes_for_session(handle.tmux_session_name)
        if not panes:
            return None
        process, _raw = self.step
        if process == "agent":
            return panes
        if process == "shim" and set(process_names) & LAUNCHING_NAMES:
            return panes
        return []

    def input_ready(self, handle):
        raw = self.step[1]
        self.clock.events.append(("probe", handle.pane_id, raw))
        return raw

    def paste(self, handle, text, settle=0.0, *, process_names=None):
        super().paste(handle, text, settle, process_names=process_names)
        self.clock.events.append(("paste", self.pastes[-1][0]))


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    """One claude session, stamped and running, with a recording lock."""
    import paths

    monkeypatch.setattr(sessions, "WOLTS_DIR", tmp_path)
    monkeypatch.setattr(paths, "WOLTS_DIR", tmp_path)
    (tmp_path / "pal" / "wolt").mkdir(parents=True)
    reg = sessions.SessionRegistry(tmp_path)
    reg.create(NAME, wolt="pal", harness="claude", dir=str(tmp_path / "pal"))
    reg.update(
        NAME, wolt="pal",
        harness_session_id=str(uuid.uuid4()),
        runtime=RuntimeHandle(NAME, NAME, PANE).to_record(),
    )

    clock = Clock()
    monkeypatch.setattr(sessions, "time", clock)

    real_lock = sessions.SessionRegistry._lock

    @contextmanager
    def recording_lock(self, wolt, name):
        clock.events.append(("lock",))
        with real_lock(self, wolt, name):
            yield

    monkeypatch.setattr(sessions.SessionRegistry, "_lock", recording_lock)

    installed = []

    def boot(*steps, alive=True):
        runtime = BootingRuntime(clock, list(steps), alive=alive)
        set_runtime(runtime)
        installed.append(runtime)
        return runtime

    record = reg._path("pal", NAME)
    yield SimpleNamespace(
        reg=reg, clock=clock, events=clock.events, boot=boot,
        record_text=lambda: record.read_text(),
    )
    if installed:
        set_runtime(None)


def _pastes(events):
    return [e for e in events if e[0] == "paste"]


# ---------------------------------------------------------------------------
# deliver_message — inter-wolt messages and the lodge's /message
# ---------------------------------------------------------------------------

class TestDeliverWaitsForInput:
    def test_pastes_once_after_the_flip_and_the_beat(self, lodge):
        runtime = lodge.boot(("agent", False), ("agent", False), ("agent", True))

        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)

        assert res["status"] == "delivered"
        assert lodge.events == [
            ("probe", PANE, False), ("sleep", 0.25),
            ("probe", PANE, False), ("sleep", 0.25),
            ("probe", PANE, True), ("sleep", 1.0),
            # The lock is taken only once the wait is over; under it, one
            # look without waiting, then the paste.
            ("lock",), ("probe", PANE, True),
            ("paste", PANE),
        ]
        assert [text for _pane, text, _settle in runtime.pastes] == ["hello"]

    def test_a_session_ready_at_once_pays_no_wait(self, lodge):
        lodge.boot(("agent", True))
        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        assert res["status"] == "delivered"
        assert not [e for e in lodge.events if e[0] == "sleep"]
        assert len(_pastes(lodge.events)) == 1

    def test_an_unreadable_terminal_pastes_at_once_and_says_so(self, lodge, capsys):
        lodge.boot(("agent", None))
        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        assert res["status"] == "delivered"
        assert not [e for e in lodge.events if e[0] == "sleep"]
        assert len(_pastes(lodge.events)) == 1
        assert len(capsys.readouterr().err.strip().splitlines()) == 1

    def test_an_agent_that_never_takes_input_gets_nothing(self, lodge):
        runtime = lodge.boot(("agent", False))

        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)

        assert res == {
            "status": "agent-booting",
            "session": NAME,
            "detail": "the agent is still booting",
        }
        assert runtime.pastes == []
        # The whole timeout, polled every quarter second...
        assert lodge.clock.now == 15.0
        assert lodge.events.count(("sleep", 0.25)) == 60
        # ...and not one moment of it under the session lock.
        last_sleep = max(i for i, e in enumerate(lodge.events) if e[0] == "sleep")
        assert all(i > last_sleep for i, e in enumerate(lodge.events) if e == ("lock",))

    def test_a_session_still_launching_for_the_whole_wait_gets_nothing(self, lodge):
        runtime = lodge.boot(("shim", None))
        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        assert res["status"] == "agent-booting"
        assert runtime.pastes == []
        assert lodge.clock.now == 15.0

    def test_launching_then_the_agent_then_raw_is_one_paste(self, lodge):
        runtime = lodge.boot(
            ("shim", None), ("shim", None), ("agent", False), ("agent", True),
        )

        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)

        assert res["status"] == "delivered"
        assert lodge.events == [
            ("sleep", 0.25), ("sleep", 0.25),
            ("probe", PANE, False), ("sleep", 0.25),
            ("probe", PANE, True), ("sleep", 1.0),
            ("lock",), ("probe", PANE, True),
            ("paste", PANE),
        ]
        assert [text for _pane, text, _settle in runtime.pastes] == ["hello"]

    def test_the_lock_waits_for_the_probe(self, lodge):
        lodge.boot(("agent", False), ("agent", False), ("agent", True))
        sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        first_lock = lodge.events.index(("lock",))
        ready = lodge.events.index(("probe", PANE, True))
        assert ready < first_lock

    def test_a_husk_is_answered_without_waiting(self, lodge):
        """Nothing is booting, so there is nothing to wait for: the caller
        hears agent-gone at once and can resume."""
        lodge.boot(("none", None))
        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        assert res["status"] == "agent-gone"
        assert lodge.clock.now == 0.0

    def test_a_dead_session_is_answered_without_waiting(self, lodge):
        lodge.boot(("none", None), alive=False)
        res = sessions.deliver_message(NAME, "hello", registry=lodge.reg)
        assert res["status"] == "session-dead"
        assert lodge.clock.now == 0.0


# ---------------------------------------------------------------------------
# resume_session — Telegram and Slack messages to a session that exists
# ---------------------------------------------------------------------------

class TestResumeWaitsForInput:
    def test_pastes_once_after_the_flip_and_the_beat(self, lodge):
        runtime = lodge.boot(("agent", False), ("agent", False), ("agent", True))

        res = sessions.resume_session(NAME, "fix the bug")

        assert res["status"] == "delivered"
        assert lodge.events == [
            ("probe", PANE, False), ("sleep", 0.25),
            ("probe", PANE, False), ("sleep", 0.25),
            ("probe", PANE, True), ("sleep", 1.0),
            ("paste", PANE),
            ("lock",),  # the record update, after the paste
        ]
        assert [text for _pane, text, _settle in runtime.pastes] == ["fix the bug"]

    def test_a_session_ready_at_once_pays_no_wait(self, lodge):
        lodge.boot(("agent", True))
        res = sessions.resume_session(NAME, "fix the bug")
        assert res["status"] == "delivered"
        assert not [e for e in lodge.events if e[0] == "sleep"]
        assert len(_pastes(lodge.events)) == 1

    def test_an_unreadable_terminal_pastes_at_once_and_says_so(self, lodge, capsys):
        lodge.boot(("agent", None))
        res = sessions.resume_session(NAME, "fix the bug")
        assert res["status"] == "delivered"
        assert lodge.events[:2] == [("probe", PANE, None), ("paste", PANE)]
        assert len(capsys.readouterr().err.strip().splitlines()) == 1

    def test_an_agent_that_never_takes_input_gets_nothing(self, lodge):
        runtime = lodge.boot(("agent", False))
        before = lodge.record_text()

        with pytest.raises(sessions.ResumeFailed, match="still booting"):
            sessions.resume_session(NAME, "fix the bug")

        assert runtime.pastes == []
        assert lodge.record_text() == before
        assert ("lock",) not in lodge.events

    def test_a_booting_session_is_waited_for_not_relaunched(self, lodge):
        """Only run-session.sh is up and the conversation id is already
        stamped. Relaunching here pasted `run-session.sh --resume` into the
        pane the agent was still booting in."""
        runtime = lodge.boot(("shim", None), ("agent", False), ("agent", True))

        res = sessions.resume_session(NAME, "fix the bug")

        assert res["status"] == "delivered"
        assert [text for _pane, text, _settle in runtime.pastes] == ["fix the bug"]
        assert runtime.spawns == [] and runtime.in_session_spawns == []

    def test_a_session_still_launching_for_the_whole_wait_gets_nothing(self, lodge):
        runtime = lodge.boot(("shim", None))
        before = lodge.record_text()

        with pytest.raises(sessions.ResumeFailed, match="still booting"):
            sessions.resume_session(NAME, "fix the bug")

        assert runtime.pastes == []
        assert runtime.spawns == [] and runtime.in_session_spawns == []
        assert lodge.record_text() == before


class TestTelegramToABootingSession:
    def test_two_messages_back_to_back_are_two_pastes_and_no_relaunch(
        self, lodge, tmp_path, monkeypatch
    ):
        from bot import core

        monkeypatch.setattr(core, "BOT_LOG_DIR", tmp_path)
        runtime = lodge.boot(
            ("shim", None), ("shim", None), ("agent", False), ("agent", True),
        )

        first = core.message_session(NAME, "are you there?")
        second = core.message_session(NAME, "and one more thing")

        assert first["ok"] is True and second["ok"] is True
        assert [text for _pane, text, _settle in runtime.pastes] == [
            "are you there?", "and one more thing",
        ]
        assert runtime.spawns == [] and runtime.in_session_spawns == []


# ---------------------------------------------------------------------------
# The lodge's /message route: one wait per message
# ---------------------------------------------------------------------------

@contextmanager
def _unlocked(*_args):
    yield


class TestMessageRouteOnABootingAgent:
    def _client(self):
        import server.app as server_app
        from starlette.testclient import TestClient
        return server_app, TestClient(server_app.app, base_url="http://localhost:7777")

    def test_agent_booting_is_409_and_never_resumes(self, monkeypatch):
        server_app, client = self._client()
        booting = {"status": "agent-booting", "session": NAME,
                   "detail": "the agent is still booting"}
        monkeypatch.setattr(server_app, "deliver_message", Mock(return_value=booting))
        resumed = Mock()
        monkeypatch.setattr(server_app, "resume_session", resumed)
        registry = Mock()
        registry._lock = _unlocked
        registry.get.return_value = {"name": NAME, "wolt": "pal", "status": "running"}
        monkeypatch.setattr("sessions.SessionRegistry", Mock(return_value=registry))

        response = client.post(f"/sessions/{NAME}/message", json={"text": "hello"})

        assert response.status_code == 409
        assert response.json() == {"ok": False, **booting}
        resumed.assert_not_called()

    def test_a_session_still_launching_waits_once_and_answers_409(self, lodge, monkeypatch):
        server_app, client = self._client()
        monkeypatch.setattr(server_app, "WOLTS_DIR", lodge.reg.wolts_dir)
        resumed = Mock(return_value={"name": NAME, "status": "revived"})
        monkeypatch.setattr(server_app, "resume_session", resumed)
        runtime = lodge.boot(("shim", None))

        response = client.post(f"/sessions/{NAME}/message", json={"text": "hello"})

        assert response.status_code == 409
        assert response.json()["status"] == "agent-booting"
        resumed.assert_not_called()
        assert runtime.pastes == []
