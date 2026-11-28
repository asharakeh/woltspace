"""Run by a fenced sibling's own shell tool: every route to another launch's notice must fail.

Root writes `probe-target` (that launch's action dir and engine pid, the helper, the lodge port) into
this worker's home first.
The result line is "fenced", or "open" and what opened; it is also left in this home for the harness.
"""
import os
from pathlib import Path
import socket
import subprocess

home = Path(os.environ["HOME"])
action, pid, notice, port = (home / "probe-target").read_text().split()
opened = []


def attempt(name, action):
    try:
        action()
        opened.append(name)
    except OSError:
        pass


attempt("request", lambda: os.close(os.open(f"{action}/request", os.O_WRONLY | os.O_NONBLOCK)))
attempt("reply", lambda: os.close(os.open(f"{action}/reply", os.O_RDONLY | os.O_NONBLOCK)))
attempt("listing", lambda: os.listdir(action))
# Same uid lists /proc/<pid>/fd names without ptrace; following any entry, cwd or root needs it.
attempt("fd", lambda: os.readlink(f"/proc/{pid}/fd/0"))
for entry in ("cwd", "root"):
    attempt(entry, lambda entry=entry: os.listdir(f"/proc/{pid}/{entry}"))
attempt("stdin", lambda: os.close(os.open(f"/proc/{pid}/fd/0", os.O_WRONLY)))
attempt("environ", lambda: open(f"/proc/{pid}/environ", "rb").close())
attempt("signal", lambda: os.kill(int(pid), 0))
attempt("unix", lambda: socket.socket(socket.AF_UNIX).close())  # tmux, launcher and broker sockets
attempt("lodge", lambda: socket.create_connection(("127.0.0.1", int(port)), 1).close())
other = Path(action).parent / "home"
helper = subprocess.run([notice], env={**os.environ, "HOME": str(other)},
                        capture_output=True, timeout=40)
if helper.stdout != b"unavailable\n":
    opened.append("helper")
result = "open " + ",".join(opened) if opened else "fenced"
(home / "probe-result").write_text(result + "\n")
print(result)
