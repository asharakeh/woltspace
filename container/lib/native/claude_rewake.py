"""Claude Code asyncRewake listener (SessionStart and Stop): wake an idle session with a body-free inbox hint.

Claude runs this in the background at session start and after every turn. The
newest listener records itself as the attempt's ready data, waits for the
hint file, claims it with one rename and exits 2: Claude then wakes the model
with stderr as a system notification. A newer listener, a retired attempt or
a gone parent ends an older one quietly (exit 0). Never reads mail.
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from native_adapters import HINT, HOOK_TIMEOUT, KINDS, LISTENER, RETIRED, write_ready  # noqa: E402

directory, attempt = Path(sys.argv[1]), sys.argv[2]
event = json.load(sys.stdin)
me, parent, armed = str(os.getpid()), os.getppid(), time.time()
(directory / f".{LISTENER}.{me}").write_text(me)
os.replace(directory / f".{LISTENER}.{me}", directory / LISTENER)
if not write_ready(directory, {"kind": KINDS["claude"], "attempt": attempt, "pid": int(me), "armed_at": armed,
                               "session_id": event.get("session_id")}):
    sys.exit(0)
while time.time() < armed + HOOK_TIMEOUT - 60:  # leave before Claude's own timeout ends us
    if (directory / RETIRED).exists() or os.getppid() != parent or (directory / LISTENER).read_text() != me:
        sys.exit(0)
    try:
        os.rename(directory / HINT, directory / f".claimed.{me}")
    except FileNotFoundError:
        time.sleep(0.2)
        continue
    text = (directory / f".claimed.{me}").read_text().strip()
    os.unlink(directory / f".claimed.{me}")
    print(text, file=sys.stderr)
    sys.exit(2)
