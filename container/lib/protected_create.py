"""Protected create for an isolated lodge: the ordinary side asks, the host owner approves.

The broker keeps the reservation, the approval and the one stable principal ID. This side only
scaffolds after approval, launches separately, and reports each step; a socket, a request ID or
the displayed code never approve anything.
"""
import os
from pathlib import Path

from woltspace import dummy_broker

MARKER = Path(".state") / "create-request"  # written first; evidence for the owner, never authority


def enabled() -> bool:
    return os.environ.get("WOLTSPACE_FEATURE_ISOLATION") == "true"


def _call(request: dict) -> dict:
    return dummy_broker.call(request, dummy_broker.SOCKET.with_name(dummy_broker.CREATE))


def _report(request_id: str, stage: str) -> dict:
    return _call({"op": "create-report", "request": request_id, "stage": stage})


def _claim(request_id: str, stage: str) -> dict | None:
    """None when this caller now owns the step; otherwise the state another caller left."""
    reply = _report(request_id, stage)
    return None if reply.get("result") == "ok" else _call({"op": "create-status", "request": request_id})


def create(request_id: str, terms: dict, wolts_dir: Path | None, scaffold, launch=None) -> dict:
    """Advance one create request as far as its approval allows. Replays are safe."""
    if wolts_dir is None:
        import wolts
        wolts_dir = wolts.WOLTS_DIR
    reply = _call({"op": "create-request", "request": request_id, "terms": terms})
    if reply.get("result") != "ok" or reply["status"] not in {"approved", "scaffolded", "launch-failed"}:
        return reply  # pending, claimed, ambiguous, launched, retired or a refusal: recorded state only
    if reply["status"] == "approved":
        if lost := _claim(request_id, "scaffolding"):  # claimed before the folder is even looked at
            return lost
        folder = wolts_dir / terms["name"]
        if folder.exists() or folder.is_symlink():
            # Nothing in the ordinary writable tree proves which request made a folder, a partial
            # scaffold of this one included: leave it untouched for protected owner reconciliation.
            return _report(request_id, "ambiguous") | {"status": "ambiguous"}
        try:
            scaffold(f"{request_id} {reply['id']}\n")
        except Exception:
            _report(request_id, "ambiguous")  # a partial folder waits for the owner
            raise
        reply = _report(request_id, "scaffolded")
        if reply.get("result") != "ok":
            return reply
    if launch is None:
        return reply
    if lost := _claim(request_id, "launching"):
        return lost
    try:
        session = launch()
    except Exception:
        _report(request_id, "launch-failed")  # the same principal stays for a retry
        raise
    return _report(request_id, "launched") | {"session": session}
