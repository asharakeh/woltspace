"""
The inbox's waker: once mail has committed, see that the agent will look at it.

notify_admitted(wolts_dir, status) is the one post-commit port, for Telegram and
for the inbox's own send. It never blocks, raises, claims or acknowledges: it
schedules one coalesced wake per agent on a background thread, so a burst is
one wake. A wake re-reads the agent's real mailbox and sessions under its
lifecycle lock, never the caller's seq or state:

- nothing queued, the mailbox not open, or the wake inhibited: nothing.
- a live session: a fixed, body-free hint through its native input, sent after
  the lock is released (native_adapters.deliver), even while the wake is
  inhibited: an inhibition only ever stops a start. submitted, pending, unknown,
  unavailable and failed are transport facts; none changes custody, and none
  is retried here. Mail waits for the agent's own fetch and ack.
- no live session: the wolt's newest resting session is resumed without a
  prompt (the post-publication pickup and its backend's ready call hint it);
  with none, one fresh session, reserved by name first and started with the
  fixed fetch instruction. Either runs in the wolt's own recorded mode. The owner's explicit stop or
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


def ready(wolts_dir, token: str, session: str, attempt: str) -> bool:
    """A native backend announced its attempt ready (native_adapters.announce_ready). Only the
    session's own reader, for its current, published, running attempt, schedules a pickup:
    one hint if this attempt never had one. False for anything stale or not its own."""
    if not inbox.enabled(wolts_dir):
        return False
    owner = inbox.Store(wolts_dir, inbox.LIMITS).reader_session(token)
    record = sessions.SessionRegistry(wolts_dir).get(session, check_alive=False) or {}
    if (owner is None or owner[0] != session or record.get("wolt") != owner[1]
            or record.get("status") != "running" or record.get("launching") or record.get("attempt") != attempt):
        return False
    _schedule(str(wolts_dir), owner[1], once=True)
    return True


def schedule_pickup(wolts_dir, wolt: str) -> None:
    """A resume that found the agent already running: its backend was ready before, so no
    ready call will come. One pickup hint for the attempt if it never had one."""
    if wolt and inbox.enabled(wolts_dir):
        _schedule(str(wolts_dir), wolt, once=True)


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


def _schedule(root: str, wolt: str, once: bool = False) -> None:
    """One worker per agent; what arrives meanwhile is one more pass ("all" outranks "once")."""
    key = (root, wolt)
    with _GUARD:
        if key in _PENDING:
            _PENDING[key] = "all" if not once or _PENDING[key] == "all" else "once"
            return
        _PENDING[key] = None
    threading.Thread(target=_worker, args=(root, wolt, once), daemon=True, name=f"inbox-wake-{wolt}").start()


def _worker(root: str, wolt: str, once: bool = False) -> None:
    key, busy = (root, wolt), 0
    while True:
        try:
            _wake(root, wolt, once=once)
        except lifecycle.LifecycleBusy:
            busy += 1
            if busy < BUSY_RETRIES:
                time.sleep(BUSY_PAUSE)
                continue
            log.warning("inbox wake for %s skipped: lifecycle busy", wolt)
        except Exception:
            log.exception("inbox wake for %s failed; the mail stays queued", wolt)
        with _GUARD:
            again = _PENDING[key]
            if again is None:
                del _PENDING[key]
                return
            _PENDING[key], busy, once = None, 0, again == "once"


def _wake(root: str, wolt: str, *, once: bool = False) -> None:
    """once: hint a live session only if its current attempt has had none yet."""
    store, registry = inbox.Store(root, inbox.LIMITS), sessions.SessionRegistry(root)
    with lifecycle.agent_lock(root, wolt):
        facts = store.wake_facts(wolt)
        if not facts or not facts["open"] or not facts["queued"]:
            return
        live = sessions.resolve_active_session(wolt, registry)
        # An inhibition only ever stops a start, never a live session's hint. The owner's own
        # mail may retry a start that only a policy refused: it starts in the wolt's own mode.
        inhibited = facts["wake"].get("inhibited")
        if inhibited == "not_startable" and facts["human"]:
            inhibited = None
        why, resume = (None, None) if live else ((inhibited, None) if inhibited else _start(store, registry, wolt, facts))
        owner = bool(why) and _reserve_notice(store, wolt, why) is not None
        if live:
            record = registry.get(live, wolt=wolt, check_alive=False) or {}
            hinted = {"session": live, "attempt": record.get("attempt")}
            if once and facts["wake"].get("hinted") == hinted:
                return
    if resume:  # outside the lock: resume relaunches under its own lock and waits after it
        try:
            sessions.resume_session(resume, "")  # no prompt: nothing is pasted; the pickup hints
        except Exception as exc:  # the reservation lets the next wake judge it
            log.warning("inbox wake could not resume %s: %s", resume, exc)
    if not live:
        if why:  # neither a hint nor a start: outside the lock and any Store write
            _notice(root, wolt, why, owner)
        return
    status, code = _deliver(record, HINT.format(nonce=uuid.uuid4().hex[:8]))
    log.info("inbox hint for %s via %s: %s (%s)", wolt, live, status, code)
    if status == "submitted" or (status, code) == ("pending", "placed"):  # only a hint that reached the engine
        with lifecycle.agent_lock(root, wolt):
            facts = store.wake_facts(wolt)
            if facts:
                store.set_wake(wolt, {**facts["wake"], "hinted": hinted})


def _start(store, registry, wolt: str, facts: dict) -> tuple[str | None, str | None]:
    """No live session: respect an explicit stop, judge the earlier reservation, then
    reserve the wolt's newest resting session to resume, or start one, in the wolt's own
    mode. Returns (why nothing was started, the session to resume after the lock);
    why is launch_unknown or the inhibition it set just now (the owner is told)."""
    wake, reserved = facts["wake"], facts["wake"].get("reserved")
    records = registry.records(wolt=wolt)
    if any(r.get("launching") for r in records):
        return "launch_unknown", None  # an unresolved launch of this agent, whoever made it, may still start
    if any(r.get("wake_inhibit") for r in records):  # an owner's stop
        return _inhibit(store, wolt, wake, "stopped"), None
    if reserved:
        record = registry.get(reserved["session"], wolt=wolt, check_alive=False) or {}
        if record.get("status") in ("running", sessions.STOPPING):
            return None, None  # still settling: kept as it is
        if facts["acks"] <= reserved.get("acks", 0):
            return _inhibit(store, wolt, wake, "no_progress"), None
    keep = {"noticed": wake["noticed"]} if "noticed" in wake else {}  # the owner was told about this mail
    resting = [r for r in records if r.get("status") == "resting" and sessions.stored_resume_id(r)]
    if resting:  # its own conversation, in its own mode: resumed after the lock, without a prompt
        name = max(resting, key=lambda r: r.get("last_activity") or 0)["name"]
        store.set_wake(wolt, {**keep, "reserved": {"session": name, "acks": 0, "at": int(time.time())}})
        acks = store.wake_facts(wolt)["acks"]  # what it acked before: progress means a new ack
        store.set_wake(wolt, {**keep, "reserved": {"session": name, "acks": acks, "at": int(time.time())}})
        return None, name
    name = sessions.session_name(wolt)
    store.set_wake(wolt, {**keep, "reserved": {"session": name, "acks": 0, "at": int(time.time())}})
    try:  # any mail starts the wolt in its own recorded mode, as Telegram did before the inbox
        sessions.start_session(wolt=wolt, prompt=START, name=name)
    except (PermissionError, ValueError, sessions.HarnessNotInstalled) as exc:
        return _inhibit(store, wolt, {**keep, "detail": str(exc)[:200]}, "not_startable"), None
    return None, None


def _reserve_notice(store, wolt: str, reason: str) -> str | None:
    """One owner notice per newest queued human message and reason, reserved under the
    lock before it is sent: a repeat wake, a resend or a ready call adds none; new human
    mail or a changed reason gets one. Recorded as attempted, never retried. None: the
    owner is not told this time (the senders' notices are inbox_notice's own)."""
    facts = store.wake_facts(wolt)
    noticed = {"seq": (facts or {}).get("human_seq"), "reason": reason}
    if not facts or noticed["seq"] is None or facts["wake"].get("noticed") == noticed:
        return None
    store.set_wake(wolt, {**facts["wake"], "noticed": noticed})
    return reason


def _inhibit(store, wolt: str, wake: dict, reason: str) -> str:
    store.set_wake(wolt, {**wake, "inhibited": reason})
    return reason


def _notice(root, wolt: str, reason: str, owner: bool) -> None:
    """Mail cannot wake the wolt: inbox_notice tells the owner (owner: once per newest
    human message and reason, reserved above) and the agents whose mail waits. Never raises."""
    try:
        import inbox_notice
        inbox_notice.notice(root, wolt, reason, owner=owner)
    except Exception:
        log.exception("inbox owner notice for %s failed", wolt)


def _deliver(record: dict | None, hint: str) -> tuple[str, str]:
    try:
        import native_adapters
    except ImportError:
        return "unavailable", "no_adapters"
    return native_adapters.deliver(record or {}, hint)
