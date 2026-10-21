"""chat_state: which wolt and session each chat talks to, in lodge.db."""

import sys
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "container" / "lib"))
sys.path.insert(0, str(ROOT / "container"))

import chat_state
import lodge_db


def _rows(wolts_dir):
    with closing(lodge_db.connect(wolts_dir, readonly=True)) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT adapter, chat_id, active_wolt, active_session FROM chat_state"
            " ORDER BY adapter, chat_id")]


def test_a_saved_chat_reads_back_with_its_extra_keys(tmp_path):
    chat_state.put(tmp_path, "telegram", 42,
                   {"active_wolt": "pal", "active_session": "pal-a", "note": "x"})

    assert chat_state.get(tmp_path, "telegram", 42) == {
        "active_wolt": "pal", "active_session": "pal-a", "note": "x"}
    assert _rows(tmp_path) == [{"adapter": "telegram", "chat_id": "42",
                                "active_wolt": "pal", "active_session": "pal-a"}]


def test_an_unknown_chat_is_empty(tmp_path):
    assert chat_state.get(tmp_path, "telegram", 7) == {}


def test_a_save_replaces_the_chat_and_drops_a_cleared_session(tmp_path):
    chat_state.put(tmp_path, "telegram", 42, {"active_wolt": "pal", "active_session": "pal-a"})
    chat_state.put(tmp_path, "telegram", 42, {"active_wolt": "nunu"})

    assert chat_state.get(tmp_path, "telegram", 42) == {"active_wolt": "nunu"}


def test_chats_are_keyed_by_adapter(tmp_path):
    chat_state.put(tmp_path, "telegram", "D1", {"active_wolt": "pal"})
    chat_state.put(tmp_path, "slack", "D1", {"active_wolt": "nunu"})

    assert chat_state.get(tmp_path, "telegram", "D1") == {"active_wolt": "pal"}
    assert chat_state.get(tmp_path, "slack", "D1") == {"active_wolt": "nunu"}


def test_delete_forgets_one_chat(tmp_path):
    chat_state.put(tmp_path, "slack", "D1:1.1", {"active_wolt": "pal"})
    chat_state.put(tmp_path, "slack", "D1:2.2", {"active_wolt": "pal"})

    chat_state.delete(tmp_path, "slack", "D1:1.1")

    assert [r["chat_id"] for r in _rows(tmp_path)] == ["D1:2.2"]


def test_forget_session_clears_it_from_that_adapters_chats_only(tmp_path):
    chat_state.put(tmp_path, "telegram", 1, {"active_wolt": "pal", "active_session": "pal-a"})
    chat_state.put(tmp_path, "telegram", 2, {"active_wolt": "pal", "active_session": "pal-b"})
    chat_state.put(tmp_path, "slack", "D1:1.1", {"active_wolt": "pal", "active_session": "pal-a"})

    assert chat_state.forget_session(tmp_path, "telegram", "pal-a") == 1

    assert chat_state.get(tmp_path, "telegram", 1) == {"active_wolt": "pal"}
    assert chat_state.get(tmp_path, "telegram", 2)["active_session"] == "pal-b"
    assert chat_state.get(tmp_path, "slack", "D1:1.1")["active_session"] == "pal-a"


# --- Telegram ---


def _telegram(monkeypatch, tmp_path):
    # bot.core makes its log dir under the wolts dir at import: keep it here.
    monkeypatch.setenv("WOLTSPACE_WOLTS_DIR", str(tmp_path))
    from bot import telegram_adapter as adapter

    (tmp_path / "pal" / "wolt").mkdir(parents=True)
    (tmp_path / "pal" / "wolt" / "wolt.json").write_text("{}")
    monkeypatch.setattr(adapter, "_WOLTS_DIR", tmp_path)
    return adapter


def test_telegram_chat_state_lives_in_the_lodge_db(monkeypatch, tmp_path):
    adapter = _telegram(monkeypatch, tmp_path)

    adapter._save_chat_state(42, {"active_wolt": "pal", "active_session": "pal-a"})

    assert _rows(tmp_path) == [{"adapter": "telegram", "chat_id": "42",
                                "active_wolt": "pal", "active_session": "pal-a"}]
    loaded = adapter._load_chat_state(42)
    assert (loaded["active_wolt"], loaded["active_session"]) == ("pal", "pal-a")
    assert not (tmp_path / ".space" / "telegram" / "chats").exists()


def test_telegram_chat_on_a_gone_wolt_reads_as_no_choice(monkeypatch, tmp_path):
    adapter = _telegram(monkeypatch, tmp_path)
    adapter._save_chat_state(42, {"active_wolt": "nunu", "active_session": "nunu-a"})

    loaded = adapter._load_chat_state(42)

    assert "active_wolt" not in loaded and "active_session" not in loaded


def test_telegram_forgets_a_killed_session_in_every_chat(monkeypatch, tmp_path):
    adapter = _telegram(monkeypatch, tmp_path)
    adapter._save_chat_state(1, {"active_wolt": "pal", "active_session": "pal-a"})
    adapter._save_chat_state(2, {"active_wolt": "pal", "active_session": "pal-a"})
    adapter._save_chat_state(3, {"active_wolt": "pal", "active_session": "pal-b"})

    adapter._forget_session("pal-a")

    assert [adapter._load_chat_state(c).get("active_session") for c in (1, 2, 3)] == [
        None, None, "pal-b"]


def test_a_lodge_without_migration_3_gains_the_chat_and_app_tables(tmp_path):
    with lodge_db.write(tmp_path) as conn:
        for table in ("chat_state", "pending_messages", "apps_running"):
            conn.execute(f"DROP TABLE {table}")
        conn.execute("DELETE FROM meta WHERE key='migration:3'")

    with closing(lodge_db.connect(tmp_path)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        applied = lodge_db.applied_migrations(conn)

    assert {"sessions", "chat_state", "pending_messages", "apps_running"} <= tables
    assert 3 in applied
