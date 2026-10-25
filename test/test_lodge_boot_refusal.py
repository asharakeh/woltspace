"""A lodge.db this build cannot open stops the boot with one readable line."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "container" / "lib"))

import lodge_db
from sessions import SessionRegistry
from woltspace import adoption
from woltspace.layout import RuntimeLayout, installation_root


def _layout(tmp_path):
    return RuntimeLayout(wolts_dir=tmp_path / "wolts", install_root=installation_root(),
                         host="127.0.0.1", port=18781, isolation="host")


def _old_session(wolts, wolt, name):
    folder = wolts / wolt / ".state" / "sessions"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.json").write_text(
        '{"name": "%s", "wolt": "%s", "status": "resting", "created_at": 10}' % (name, wolt))
    return folder


def _corrupt(wolts):
    db = lodge_db.path(wolts)
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"this is not an sqlite file\n" * 200)


def _too_new(wolts):
    conn = lodge_db.connect(wolts)
    conn.execute("UPDATE meta SET value = '99' WHERE key = 'min_schema'")
    conn.execute("UPDATE meta SET value = '9.9.9' WHERE key = 'written_by'")
    conn.close()


@pytest.mark.parametrize("make_bad, reason", [
    (_corrupt, "file is not a database"),
    (_too_new, "Install that build or newer"),
], ids=["corrupt", "too-new"])
def test_a_bad_lodge_db_refuses_the_boot_and_touches_nothing(tmp_path, capsys, make_bad, reason):
    layout = _layout(tmp_path)
    folder = _old_session(layout.wolts_dir, "alpha", "s1")
    make_bad(layout.wolts_dir)
    db = lodge_db.path(layout.wolts_dir)
    before = db.read_bytes()

    with pytest.raises(SystemExit) as exit_:
        adoption.adopt_runtime_sessions(layout)

    assert exit_.value.code == 1
    err = capsys.readouterr().err
    assert "refusing to start" in err and reason in err
    assert ".space/lodge.db" in err  # names the file to restore or move aside
    assert "Traceback" not in err
    # Nothing repaired, recreated, imported or reported: the file waits for a restore.
    assert db.read_bytes() == before
    assert (folder / "s1.json").exists()
    assert not (folder.parent / "sessions.imported").exists()
    assert not adoption.report_path(layout).exists()


def test_a_new_lodge_without_a_lodge_db_still_boots(tmp_path):
    layout = _layout(tmp_path)
    _old_session(layout.wolts_dir, "alpha", "s1")

    report = adoption.adopt_runtime_sessions(layout)

    assert "import_errors" not in report
    assert lodge_db.path(layout.wolts_dir).exists()
    assert SessionRegistry(layout.wolts_dir)._read("alpha", "s1") is not None
