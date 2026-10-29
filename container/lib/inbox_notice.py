"""Tell whoever sent mail to an agent that cannot wake.

notice(wolts_dir, wolt, reason, owner=...) is the waker's port, called when a wake
ends with neither a hint nor a start. The owner hears through the lodge's own
outbound path (POST /notify with no session: their default channel) while human
mail is queued, when the waker's reservation says so. Each agent that sent queued
mail gets one notice per message and reason in its own inbox, from the lodge at
agent priority, and its normal hint: the notice's key is the dedup, so a repeat
wake adds nothing. Fixed lines, never a message body. No state of its own, no
retry, never raises.
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


def sender_notices(wolts_dir, wolt: str, reason: str) -> None:
    try:
        store = inbox.Store(wolts_dir, inbox.LIMITS)
        for mail in store.unnoticed_agent_mail(wolt, reason):
            try:
                status = store.admit("lodge", f"stuck:{mail['seq']}:{reason}", mail["sender"],
                                     f"[lodge] your message {mail['key']} to {wolt} is queued, but {wolt} "
                                     f"can't wake now: {plain(reason)}", mailbox=mail["mailbox"])
            except inbox.InboxError as exc:  # the sender's mailbox is gone or full
                log.warning("sender notice for %s not queued: %s", wolt, exc.code)
                continue
            import inbox_wake
            inbox_wake.notify_admitted(wolts_dir, status)
    except Exception as exc:
        log.warning("sender notices for %s not sent: %s", wolt, type(exc).__name__)


def notice(wolts_dir, wolt: str, reason: str, *, owner: bool) -> None:
    if owner:
        owner_notice(wolts_dir, wolt, reason)
    sender_notices(wolts_dir, wolt, reason)
