"""
The inbox's waker: once mail has committed, see that the agent will look at it.

notify_admitted(wolts_dir, status) is the one post-commit port, for Telegram and
for the inbox's own send. It never blocks, raises, claims or acknowledges: it
schedules one coalesced wake per agent on a background thread, so a burst is
one wake. A wake re-reads the agent's real mailbox and sessions under its
lifecycle lock, never the caller's seq or state:

- nothing queued, the mailbox not open, or the wake inhibited: nothing.
- a live session: a fixed, body-free hint through its native input, sent after
  the lock is released (native_adapters.deliver). submitted, pending, unknown,
  unavailable and failed are transport facts; none changes custody, and none
  is retried here. Mail waits for the agent's own fetch and ack.
- no live session: one fresh session, reserved by name first and started with
  the fixed fetch instruction (auto policy only). The owner's explicit stop or
  archive of any of the agent's sessions, whoever started it, marks that record
  (wake_inhibit) and inhibits the wake until rearm clears the marks it sees; so does a reserved session that ended without a first ack
  ("no_progress"). New mail never clears an inhibition. While any launch of
  the agent is unresolved, whoever made it, nothing starts and rearm refuses.

Inbox off: notify_admitted does nothing.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

import inbox
import lifecycle
import sessions

log = logging.getLogger("inbox_wake")
START = ("You have lodge inbox mail. Run `woltspace inbox fetch`, handle the message, then "
         "`woltspace inbox ack <seq> <claim>`; repeat until fetch returns nothing.")
HINT = ("New inbox mail: run `woltspace inbox fetch`, then `woltspace inbox ack <seq> <claim>` "
        "when handled (nonce {nonce}).")
BUSY_RETRIES, BUSY_PAUSE = 5, 2.0
_GUARD = threading.Lock()
_PENDING: dict[tuple[str, str], bool] = {}  # (root, wolt) -> another wake was asked for meanwhile


def notify_admitted(wolts_dir, status) -> None:
    """Called after Store admission committed. Never raises."""
    try:
        if status.state != "acknowledged" and inbox.enabled(wolts_dir):
            _schedule(str(wolts_dir), status.to)
    except Exception:
        log.exception("inbox wake not scheduled")


def reconcile(wolts_dir) -> None:
    """At boot: mail admitted just before a crash never got its wake."""
    if inbox.enabled(wolts_dir):
        for wolt in inbox.Store(wolts_dir, inbox.LIMITS).queued_wolts():
            _schedule(str(wolts_dir), wolt)


def rearm(wolts_dir, wolt: str) -> dict:
    """The operator's explicit clear of an inhibited wake. Refused while any of
    the agent's launches is unresolved; mail and policy are re-checked by the
    wake it schedules."""
    with lifecycle.agent_lock(wolts_dir, wolt):
        store = inbox.Store(wolts_dir, inbox.LIMITS)
        facts = store.wake_facts(wolt)
        if facts is None:
            raise inbox.Refused("no_mailbox")
        registry = sessions.SessionRegistry(wolts_dir)
        for record in registry.records(wolt=wolt):  # any unresolved launch of the agent refuses it
            sessions.refuse_unresolved(record)
        for stopped in registry.records(wolt=wolt):  # exactly the stops seen now; a later one counts
            if stopped.get("wake_inhibit"):
                with registry.edit(stopped["name"], wolt=wolt) as current:
                    current.pop("wake_inhibit", None)
        store.set_wake(wolt, {})
    _schedule(str(wolts_dir), wolt)
    return {"wolt": wolt, "rearmed": True}


def _schedule(root: str, wolt: str) -> None:
    key = (root, wolt)
    with _GUARD:
        if key in _PENDING:
            _PENDING[key] = True
            return
        _PENDING[key] = False
    threading.Thread(target=_worker, args=key, daemon=True, name=f"inbox-wake-{wolt}").start()


def _worker(root: str, wolt: str) -> None:
    key, busy = (root, wolt), 0
    while True:
        try:
            _wake(root, wolt)
        except lifecycle.LifecycleBusy:
            busy += 1
            if busy < BUSY_RETRIES:
                time.sleep(BUSY_PAUSE)
                continue
            log.warning("inbox wake for %s skipped: lifecycle busy", wolt)
        except Exception:
            log.exception("inbox wake for %s failed; the mail stays queued", wolt)
        with _GUARD:
            if not _PENDING[key]:
                del _PENDING[key]
                return
            _PENDING[key], busy = False, 0


def _wake(root: str, wolt: str) -> None:
    store, registry = inbox.Store(root, inbox.LIMITS), sessions.SessionRegistry(root)
    with lifecycle.agent_lock(root, wolt):
        facts = store.wake_facts(wolt)
        if not facts or not facts["open"] or not facts["queued"] or facts["wake"].get("inhibited"):
            return
        live = sessions.resolve_active_session(wolt, registry)
        if live is None:
            _start(store, registry, wolt, facts)
            return
        record = registry.get(live, wolt=wolt, check_alive=False)
    status, code = _deliver(record, HINT.format(nonce=uuid.uuid4().hex[:8]))
    log.info("inbox hint for %s via %s: %s (%s)", wolt, live, status, code)


def _start(store, registry, wolt: str, facts: dict) -> None:
    """No live session: respect an explicit stop, judge the earlier reservation,
    then reserve and start one."""
    wake, reserved = facts["wake"], facts["wake"].get("reserved")
    records = registry.records(wolt=wolt)
    if any(r.get("launching") for r in records):
        return  # an unresolved launch of this agent, whoever made it, may still start: unknown
    if any(r.get("wake_inhibit") for r in records):  # an owner's stop
        store.set_wake(wolt, {**wake, "inhibited": "stopped"})
        return
    if reserved:
        record = registry.get(reserved["session"], wolt=wolt, check_alive=False) or {}
        if record.get("status") in ("running", sessions.STOPPING):
            return  # still settling: kept as it is
        if facts["acks"] <= reserved.get("acks", 0):
            store.set_wake(wolt, {**wake, "inhibited": "no_progress"})
            return
    name = sessions.session_name(wolt)
    store.set_wake(wolt, {"reserved": {"session": name, "acks": 0, "at": int(time.time())}})
    try:
        sessions.start_session(wolt=wolt, prompt=START, name=name, require_auto=True)
    except (PermissionError, ValueError, sessions.HarnessNotInstalled) as exc:
        store.set_wake(wolt, {"inhibited": "not_startable", "detail": str(exc)[:200]})


def _deliver(record: dict | None, hint: str) -> tuple[str, str]:
    try:
        import native_adapters
    except ImportError:
        return "unavailable", "no_adapters"
    return native_adapters.deliver(record or {}, hint)
