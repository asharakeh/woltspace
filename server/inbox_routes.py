"""The lodge inbox over HTTP (container/lib/inbox.py): send, fetch, ack, release, status.

Off (404 inbox_disabled) unless woltspace.json enables the inbox. The caller is
the reader whose token arrives in the X-Woltspace-Inbox-Token header; nothing
in the body names a sender or a priority, and a body with any other field is
refused. Errors are fixed codes; no body or token is ever logged or echoed.
"""

import dataclasses
import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

import inbox
import inbox_wake
import lifecycle

from .config import WOLTS_DIR

router = APIRouter(prefix="/inbox")
TOKEN_HEADER = "X-Woltspace-Inbox-Token"
_FIELDS = {"send": {"to", "key", "text"}, "fetch": set(), "ack": {"seq", "claim"},
           "release": {"seq", "claim"}, "status": {"key"}}
_HTTP = {"inbox_disabled": 404, "unsupported": 404, "invalid": 400, "reader_invalid": 401,
         "store_busy": 503, "store_failed": 503, "lifecycle_busy": 409, "launch_unknown": 409}


def _error(code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=_HTTP.get(code, 409))


@router.post("/rearm")
async def inbox_rearm(request: Request):
    """The owner's explicit rearm of an agent's inhibited wake (inbox_wake.rearm)."""
    if not inbox.enabled(WOLTS_DIR):
        return _error("inbox_disabled")
    try:
        body = json.loads(await request.body() or b"{}")
        wolt = body["wolt"]
        assert set(body) == {"wolt"} and isinstance(wolt, str)
    except (ValueError, KeyError, TypeError, AssertionError):
        return _error("invalid")
    try:
        return {"ok": True, "result": await run_in_threadpool(inbox_wake.rearm, WOLTS_DIR, wolt)}
    except (inbox.InboxError, lifecycle.LifecycleBusy, lifecycle.LifecycleUnknown) as exc:
        return _error(exc.code)


@router.post("/{verb}")
async def inbox_call(verb: str, request: Request):
    if verb not in _FIELDS:
        return _error("unsupported")
    if not inbox.enabled(WOLTS_DIR):
        return _error("inbox_disabled")
    try:
        body = json.loads(await request.body() or b"{}")
    except ValueError:
        return _error("invalid")
    if not isinstance(body, dict) or not set(body) <= _FIELDS[verb]:
        return _error("invalid")
    token, store = request.headers.get(TOKEN_HEADER, ""), inbox.Store(WOLTS_DIR, inbox.LIMITS)
    call = {
        "send": lambda: store.send(token, body.get("to"), body.get("key"), body.get("text")),
        "fetch": lambda: store.fetch(token),
        "ack": lambda: store.ack(token, body.get("seq"), body.get("claim")),
        "release": lambda: store.release(token, body.get("seq"), body.get("claim")),
        "status": lambda: store.status(token, body.get("key")),
    }[verb]
    try:
        result = await run_in_threadpool(call)
    except inbox.InboxError as exc:
        return _error(exc.code)
    if verb == "send":  # committed: wake the recipient (never blocks or raises)
        await run_in_threadpool(inbox_wake.notify_admitted, WOLTS_DIR, result)
    return {"ok": True, "result": dataclasses.asdict(result) if dataclasses.is_dataclass(result) else result}
