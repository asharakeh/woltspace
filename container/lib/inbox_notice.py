"""Tell the owner when mail of theirs is waiting for an agent that cannot wake.

owner_notice(wolts_dir, wolt, reason) is the waker's port: it is called where a
wake inhibition is set, once per inhibition. It speaks only while the agent has
queued mail from a human, and only through the lodge's own outbound path (POST
/notify with no session: the owner's default channel). One fixed line, never a
message body or a sender. It keeps no state, never retries and never raises.
"""

from __future__ import annotations

import json
import logging
import urllib.request

import inbox
from env_compat import get_env

log = logging.getLogger("inbox_notice")
NOTIFY = "/notify"  # the lodge's own outbound path, on its API

# Why a wake is inhibited, in the owner's words.
REASONS = {
    "not_startable": "it can't be started automatically",
    "stopped": "one of its sessions was stopped, so it stays asleep until rearmed",
    "no_progress": "its last wake didn't pick the mail up",
    "launch_unknown": "an earlier start of it never confirmed and may still come up",
}


def plain(reason: str) -> str:
    return REASONS.get(reason, f"its wake is held ({reason})")


def owner_notice(wolts_dir, wolt: str, reason: str) -> None:
    try:
        rows = inbox.Store(wolts_dir, inbox.LIMITS).summary()
        if not any(r["wolt"] == wolt and r["queued_human"] for r in rows):
            return
        body = json.dumps({"session": "", "message": f"🪵 your mail for {wolt} is waiting, but {wolt} "
                                                       f"can't wake now: {plain(reason)}"}).encode()
        api = get_env("WOLTSPACE_API", "http://localhost:7777")
        req = urllib.request.Request(f"{api}{NOTIFY}", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        # The lodge's own API is local: never through a proxy from the environment.
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as answer:
            answer.read()
    except Exception as exc:
        log.warning("owner notice for %s not sent: %s", wolt, type(exc).__name__)
