"""lodge_db: the one SQLite file that holds the lodge's changing state."""

import os
import sqlite3
import stat
from contextlib import contextmanager
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "container" / "lib"))

import lodge_db


def test_path_is_under_space(tmp_path):
    assert lodge_db.path(tmp_path) == tmp_path / ".space" / "lodge.db"


def test_connect_creates_the_file_and_sets_the_pragmas(tmp_path):
    conn = lodge_db.connect(tmp_path)
    try:
        assert lodge_db.path(tmp_path).is_file()
        pragma = lambda name: conn.execute(f"PRAGMA {name}").fetchone()[0]
        assert pragma("journal_mode") == "wal"
        assert pragma("synchronous") == 1  # NORMAL
        assert pragma("busy_timeout") == 5000
        assert pragma("foreign_keys") == 1
        assert isinstance(conn.execute("SELECT 1 AS one").fetchone(), sqlite3.Row)
    finally:
        conn.close()


def test_schema_is_created_once_and_each_migration_recorded(tmp_path):
    for _ in range(2):
        conn = lodge_db.connect(tmp_path)
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        applied = lodge_db.applied_migrations(conn)
        conn.close()
        assert {"meta", "sessions"} <= tables
        assert applied == [v for v, _ in lodge_db._MIGRATIONS]


def test_a_migration_that_lands_late_still_runs(tmp_path, monkeypatch):
    base = lodge_db._MIGRATIONS[:1]
    two = (2, ("CREATE TABLE two (x)",))
    three = (3, ("CREATE TABLE three (x)",))
    monkeypatch.setattr(lodge_db, "_MIGRATIONS", base + [three])
    lodge_db.connect(tmp_path).close()
    monkeypatch.setattr(lodge_db, "_MIGRATIONS", base + [two, three])
    conn = lodge_db.connect(tmp_path)
    tables = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert {"two", "three"} <= tables
    assert lodge_db.applied_migrations(conn) == [1, 2, 3]
    conn.close()


def test_readonly_refuses_writes_and_a_missing_file(tmp_path):
    with pytest.raises(sqlite3.OperationalError):
        lodge_db.connect(tmp_path, readonly=True)
    assert not lodge_db.path(tmp_path).exists()
    lodge_db.connect(tmp_path).close()
    conn = lodge_db.connect(tmp_path, readonly=True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO meta VALUES ('k', 'v')")
    finally:
        conn.close()


def test_write_commits_or_rolls_back(tmp_path):
    with lodge_db.write(tmp_path) as conn:
        conn.execute("INSERT INTO meta VALUES ('kept', '1')")
    with pytest.raises(RuntimeError):
        with lodge_db.write(tmp_path) as conn:
            conn.execute("INSERT INTO meta VALUES ('dropped', '1')")
            raise RuntimeError("boom")
    conn = lodge_db.connect(tmp_path)
    keys = {r[0] for r in conn.execute("SELECT key FROM meta")}
    conn.close()
    assert "kept" in keys and "dropped" not in keys


def test_write_serializes_read_modify_write_across_threads(tmp_path):
    with lodge_db.write(tmp_path) as conn:
        conn.execute("INSERT INTO meta VALUES ('n', '0')")

    def bump():
        for _ in range(25):
            with lodge_db.write(tmp_path) as conn:
                n = int(conn.execute("SELECT value FROM meta WHERE key='n'").fetchone()[0])
                conn.execute("UPDATE meta SET value=? WHERE key='n'", (str(n + 1),))

    threads = [threading.Thread(target=bump) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    conn = lodge_db.connect(tmp_path)
    assert conn.execute("SELECT value FROM meta WHERE key='n'").fetchone()[0] == "100"
    conn.close()


def test_a_new_file_is_owner_only_whatever_the_umask(tmp_path):
    old = os.umask(0o022)
    try:
        lodge_db.connect(tmp_path).close()
    finally:
        os.umask(old)
    assert stat.S_IMODE(lodge_db.path(tmp_path).stat().st_mode) == 0o600


def _importer(calls, *retire):
    """One meta row per retired path that is there, OR IGNORE like a real importer."""
    def run(conn, wolts_dir):
        calls.append(1)
        live = [p for p in retire if p.exists()]
        for path in live:
            conn.execute("INSERT OR IGNORE INTO meta VALUES (?, ?)", (
                f"row:{path.name}", path.read_text() if path.is_file() else "dir"))
        return {"imported": len(live)}, live
    return run


def test_files_are_the_gate_and_rows_in_the_db_win(tmp_path):
    source = tmp_path / "a.json"
    source.write_text("old")
    calls = []
    assert lodge_db.run_imports(tmp_path, {"a": _importer(calls, source)}) == {"a": {"imported": 1}}
    # Nothing left: the importer runs, finds nothing, and nothing is recorded.
    assert lodge_db.run_imports(tmp_path, {"a": _importer(calls, source)}) == {}
    # An older release wrote the file again: imported, the row already there kept,
    # and the file retired beside the first one under a free name.
    for n in (2, 3):
        source.write_text(f"stale {n}")
        assert lodge_db.run_imports(tmp_path, {"a": _importer(calls, source)}) == {"a": {"imported": 1}}
        assert (tmp_path / f"a.json.imported.{n}").read_text() == f"stale {n}"
    assert len(calls) == 4 and (tmp_path / "a.json.imported").read_text() == "old"
    conn = lodge_db.connect(tmp_path)
    assert conn.execute("SELECT value FROM meta WHERE key='row:a.json'").fetchone()[0] == "old"
    assert lodge_db.imports(conn)["a"]["imported"] == 1
    conn.close()


def test_sources_are_retired_only_after_the_commit(tmp_path, monkeypatch):
    folder = tmp_path / "sessions"
    folder.mkdir()
    (folder / "s.json").write_text("{}")
    (folder / "s.lock").write_text("")
    single = tmp_path / "grants.json"
    single.write_text("{}")
    (tmp_path / "grants.lock").write_text("")
    lone_lock = tmp_path / "recovery.lock"
    lone_lock.write_text("")
    real = lodge_db.write

    @contextmanager
    def commit_fails(wolts_dir):
        with real(wolts_dir) as conn:
            yield conn
            raise sqlite3.OperationalError("disk full")

    monkeypatch.setattr(lodge_db, "write", commit_fails)
    with pytest.raises(sqlite3.OperationalError):
        lodge_db.run_imports(tmp_path, {"a": _importer([], folder, single, lone_lock)})
    assert (folder / "s.lock").exists() and single.exists() and lone_lock.exists()
    monkeypatch.setattr(lodge_db, "write", real)
    lodge_db.run_imports(tmp_path, {"a": _importer([], folder, single, lone_lock)})
    assert sorted(p.name for p in tmp_path.iterdir() if p.name != ".space") == [
        "grants.json.imported", "sessions.imported"]
    assert [p.name for p in (tmp_path / "sessions.imported").iterdir()] == ["s.json"]


def test_a_retire_that_fails_is_logged_and_the_boot_goes_on(tmp_path, monkeypatch, capsys):
    source = tmp_path / "a.json"
    source.write_text("x")

    def denied(path):
        raise PermissionError("denied")

    monkeypatch.setattr(lodge_db, "_retire", denied)
    assert lodge_db.run_imports(tmp_path, {"a": _importer([], source)}) == {"a": {"imported": 1}}
    assert "could not retire" in capsys.readouterr().err


def test_a_failed_import_writes_nothing_and_runs_again(tmp_path):
    def broken(conn, wolts_dir):
        conn.execute("INSERT INTO meta VALUES ('half', 'x')")
        raise OSError("disk")

    with pytest.raises(OSError):  # a broken importer is a bug: loud, and retried next boot
        lodge_db.run_imports(tmp_path, {"a": broken})
    conn = lodge_db.connect(tmp_path)
    assert lodge_db.imports(conn) == {}
    assert conn.execute("SELECT 1 FROM meta WHERE key='half'").fetchone() is None
    conn.close()


def test_many_first_openers_at_once_all_get_in(tmp_path):
    errors = []

    def open_and_write(root):
        try:
            with lodge_db.write(root) as conn:
                conn.execute("SELECT 1")
        except sqlite3.Error as exc:
            errors.append(exc)

    for n in range(30):
        root = tmp_path / str(n)
        threads = [threading.Thread(target=open_and_write, args=(root,)) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    assert errors == []
