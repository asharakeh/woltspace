"""
Which wolt and session each chat talks to, in lodge.db's chat_state table.

A chat is (adapter, chat_id). `active_wolt` and `active_session` are columns;
any other key the adapter keeps rides along in `record`.
"""

from __future__ import annotations

import json
import time
from contextlib import closing

import lodge_db


def get(wolts_dir, adapter: str, chat_id) -> dict:
    """The chat's state, or {} for a chat never saved."""
    with closing(lodge_db.connect(wolts_dir)) as conn:
        row = conn.execute(
            "SELECT active_wolt, active_session, record FROM chat_state"
            " WHERE adapter=? AND chat_id=?", (adapter, str(chat_id)),
        ).fetchone()
    if row is None:
        return {}
    state = json.loads(row["record"] or "{}")
    for key in ("active_wolt", "active_session"):
        if row[key]:
            state[key] = row[key]
    return state


def put(wolts_dir, adapter: str, chat_id, state: dict) -> None:
    """Replace the chat's state with `state`."""
    extra = {k: v for k, v in state.items() if k not in ("active_wolt", "active_session")}
    with lodge_db.write(wolts_dir) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO chat_state"
            " (adapter, chat_id, active_wolt, active_session, record, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (adapter, str(chat_id), state.get("active_wolt"), state.get("active_session"),
             json.dumps(extra), int(time.time())),
        )


def delete(wolts_dir, adapter: str, chat_id) -> None:
    with lodge_db.write(wolts_dir) as conn:
        conn.execute("DELETE FROM chat_state WHERE adapter=? AND chat_id=?",
                     (adapter, str(chat_id)))


def forget_session(wolts_dir, adapter: str, session: str) -> int:
    """Clear `session` from every chat of `adapter` that talks to it; how many."""
    with lodge_db.write(wolts_dir) as conn:
        return conn.execute(
            "UPDATE chat_state SET active_session=NULL, updated_at=?"
            " WHERE adapter=? AND active_session=?",
            (int(time.time()), adapter, session),
        ).rowcount
