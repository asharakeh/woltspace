"""Claude Code asyncRewake listener (SessionStart and Stop): wake an idle session with a body-free inbox hint.

Claude runs this in the background at session start and after every turn. The
newest listener records itself as the attempt's ready data, waits for the
hint file, claims it with one rename and exits 2: Claude then wakes the model
with stderr as a system notification. With `--busy` it is the UserPromptSubmit
hook: a turn running marks the attempt busy, and no hint is claimed until the
Stop listener clears it. A newer listener, a retired attempt or a gone parent
ends an older one quietly (exit 0). Never reads mail.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from native_adapters import HINT, HOOK_TIMEOUT, KINDS, LISTENER, RETIRED, is_busy, write_ready, write_state  # noqa: E402

directory, attempt = Path(sys.argv[1]), sys.argv[2]
event = json.load(sys.stdin)
if sys.argv[3:] == ["--busy"]:  # a human turn starts
    write_state(directory, True)
    sys.exit(0)
me, parent, armed = str(os.getpid()), os.getppid(), time.time()
(directory / f".{LISTENER}.{me}").write_text(me)
os.replace(directory / f".{LISTENER}.{me}", directory / LISTENER)  # supersede first: the old one stays gated
if event.get("hook_event_name") == "Stop":  # a hint from before this turn (none is placed while busy): the
    (directory / HINT).unlink(missing_ok=True)  # turn_end wake below hints again if mail is still queued
    write_state(directory, False)  # only a turn's end says idle: a start may already run its opening prompt
if not write_ready(directory, {"kind": KINDS["claude"], "attempt": attempt, "pid": int(me), "armed_at": armed,
                               "session_id": event.get("session_id")},
                   announce="turn_end" if event.get("hook_event_name") == "Stop" else "ready"):
    sys.exit(0)
while time.time() < armed + HOOK_TIMEOUT - 60:  # leave before Claude's own timeout ends us
    if (directory / RETIRED).exists() or os.getppid() != parent or (directory / LISTENER).read_text() != me:
        sys.exit(0)
    if is_busy(directory):
        time.sleep(0.2)
        continue
    try:
        os.rename(directory / HINT, directory / f".claimed.{me}")
    except FileNotFoundError:
        time.sleep(0.2)
        continue
    text = (directory / f".claimed.{me}").read_text().strip()
    os.unlink(directory / f".claimed.{me}")
    write_state(directory, True)  # this wake is a turn; its Stop clears it
    print(text, file=sys.stderr)
    sys.exit(2)
