"""Sessions in lodge.db: the races the old file locks were for, and the import."""

import json
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "container" / "lib"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import lodge_db
import sessions
from conftest import make_session
from session_runtime import RuntimeHandle
from sessions import SessionRegistry


def _race(*targets):
    threads = [threading.Thread(target=t) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def test_a_read_of_an_empty_lodge_finds_nothing_and_creates_nothing(tmp_path):
    reg = SessionRegistry(tmp_path)
    assert reg.list() == [] and reg.records() == []
    assert reg.get("s", check_alive=False) is None
    assert reg.taken_resume_ids() == set()
    assert not (tmp_path / ".space").exists()


def test_a_read_opens_the_file_read_only(tmp_path):
    reg = SessionRegistry(tmp_path)
    make_session(reg, name="s", wolt="pal")
    with reg._reader() as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM sessions")
    assert reg.get("s", check_alive=False)["name"] == "s"


def test_two_writers_of_different_fields_keep_both(tmp_path):
    """799e4b0: the spawner's runtime handle and session-reg's resume id, written together."""
    reg = SessionRegistry(tmp_path)
    make_session(reg, name="s", wolt="pal")
    _race(*(lambda field=field: [reg.update("s", **{field: i}) for i in range(40)]
            for field in ("runtime_n", "harness_n")))
    stored = reg._read("pal", "s")
    assert stored["runtime_n"] == 39 and stored["harness_n"] == 39


def test_a_touch_never_writes_running_over_a_rest(tmp_path):
    """#571 (a): the guard is in the UPDATE, so the loser changes nothing."""
    reg = SessionRegistry(tmp_path)
    make_session(reg, name="s", wolt="pal", last_activity=1)
    touched, first = [], threading.Event()

    def touches():
        for _ in range(40):
            touched.append(reg.touch("s"))
            first.set()

    def rest():
        first.wait()
        reg._write("pal", "s", {**reg._read("pal", "s"), "status": "resting"})

    _race(touches, rest)
    stored = reg._read("pal", "s")
    assert stored["status"] == "resting"
    assert not reg.touch("s")
    assert True not in touched[touched.index(False):] if False in touched else True


def test_a_paste_after_a_rest_wakes_instead_of_pasting(tmp_path, monkeypatch):
    """#571 (b): a rest stops tmux inside its write; the paste claims first, then pastes."""
    reg = SessionRegistry(tmp_path)
    make_session(reg, name="s", wolt="pal", harness_session_id="conv-1")
    pastes = []
    monkeypatch.setattr(sessions, "_tmux_paste", lambda *a, **k: pastes.append(a))
    monkeypatch.setattr(sessions, "resolve_agent_handle",
                        lambda *a, **k: RuntimeHandle(tmux_session_name="s", pane_id="%1"))
    resting, claimed = threading.Event(), []

    def rest():
        with reg.edit("s") as data:
            resting.set()
            threading.Event().wait(0.2)  # tmux stopping while the paste waits
            data["status"] = "resting"

    def paste():
        resting.wait()
        claimed.append(sessions._paste_into_live_agent(reg, "pal", "s", "running", "claude", "hi"))

    _race(rest, paste)
    assert claimed == [False] and pastes == []
    assert reg._read("pal", "s")["status"] == "resting"


def test_two_claimers_of_one_conversation_get_one_each(tmp_path, monkeypatch):
    """3cb6030: harness_session_id is UNIQUE; the second claimer looks again."""
    reg = SessionRegistry(tmp_path)
    for name in ("a", "b"):
        make_session(reg, name=name, wolt="pal", harness="codex")
    gate = threading.Barrier(2)

    def recover(data, taken):
        if not taken:
            gate.wait(timeout=5)  # both see the newest rollout before either writes
        return next(c for c in ("conv-1", "conv-2") if c not in taken)

    monkeypatch.setattr(sessions, "recover_resume_id", recover)
    got = {}

    def claim(name):
        data = reg._read("pal", name)
        got[name] = sessions.claim_resume_id(reg, data, lambda d: sessions.stamp_resume_id(
            reg, "pal", name, d["harness_session_id"]))

    _race(lambda: claim("a"), lambda: claim("b"))
    assert sorted(got.values()) == ["conv-1", "conv-2"]
    assert {reg._read("pal", n)["harness_session_id"] for n in "ab"} == {"conv-1", "conv-2"}
    with pytest.raises(sqlite3.IntegrityError):
        reg.update("a", harness_session_id=got["b"])


def test_an_archived_wolt_drops_out_until_it_comes_back(tmp_path):
    reg = SessionRegistry(tmp_path)
    (tmp_path / "pal").mkdir()
    make_session(reg, name="s", wolt="pal")
    (tmp_path / ".archive").mkdir()
    (tmp_path / "pal").rename(tmp_path / ".archive" / "pal")
    assert reg.get("s", check_alive=False) is None and reg.records() == []
    archive = SessionRegistry(tmp_path / ".archive", db_dir=tmp_path)
    assert [r["name"] for r in archive.records(wolt="pal")] == ["s"]
    (tmp_path / ".archive" / "pal").rename(tmp_path / "pal")
    assert reg.get("s", check_alive=False)["name"] == "s"
    assert reg.forget_wolt("pal") == 1 and reg.records() == []


def _old_session(root, wolt, name, **fields):
    folder = root / wolt / ".state" / "sessions"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(json.dumps({"name": name, "wolt": wolt, **fields}))
    (folder / f"{name}.lock").write_text("")
    return folder


def test_the_import_takes_every_file_once_and_rows_win_after(tmp_path, capsys):
    folder = _old_session(tmp_path, "pal", "new", status="resting", created_at=20,
                          harness_session_id="conv-1")
    _old_session(tmp_path, "pal", "old", status="stopped", created_at=10,
                 harness_session_id="conv-1")
    (folder / "torn.json").write_text("{")
    (folder / "half.tmp").write_text("{}")
    _old_session(tmp_path / ".archive", "nunu", "kept", status="resting", created_at=5)
    (tmp_path / ".state").mkdir()
    (tmp_path / ".state" / "resume-id-recovery.lock").write_text("")

    ran = lodge_db.run_imports(tmp_path, {"sessions": sessions.import_sessions})
    assert ran == {"sessions": {"imported": 2, "skipped": 2}}
    err = capsys.readouterr().err
    assert "old.json" in err and "torn.json" in err
    reg = SessionRegistry(tmp_path)
    assert reg._read("pal", "new")["harness_session_id"] == "conv-1"
    assert reg._read("pal", "old") is None
    assert not folder.exists() and not (tmp_path / ".state" / "resume-id-recovery.lock").exists()
    assert sorted(p.name for p in (tmp_path / "pal" / ".state" / "sessions.imported").iterdir()) == [
        "half.tmp", "new.json", "old.json", "torn.json"]
    assert (tmp_path / ".archive" / "nunu" / ".state" / "sessions.imported" / "kept.json").exists()

    assert lodge_db.run_imports(tmp_path, {"sessions": sessions.import_sessions}) == {}
    # A downgraded lodge wrote files again: the new session comes in, the row already here wins.
    reg.update("new", title="since the upgrade")
    _old_session(tmp_path, "pal", "new", status="running", created_at=20)
    _old_session(tmp_path, "pal", "made-meanwhile", status="resting", created_at=30)
    ran = lodge_db.run_imports(tmp_path, {"sessions": sessions.import_sessions})
    assert ran == {"sessions": {"imported": 1, "skipped": 1}}
    assert reg._read("pal", "new")["title"] == "since the upgrade"
    assert reg._read("pal", "made-meanwhile")["status"] == "resting"


def test_a_failed_import_never_stops_the_boot(tmp_path, monkeypatch):
    from woltspace import adoption

    def broken(conn, wolts_dir):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(sessions, "import_sessions", broken)
    layout = type("Layout", (), {"wolts_dir": tmp_path})()
    assert adoption.import_lodge_state(layout) == {
        "sessions": "OperationalError: disk I/O error"}
