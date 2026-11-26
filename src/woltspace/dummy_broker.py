"""Protected dummy broker: owner-only admin over a local socket. No provider or public API.

The broker runs as the service uid. Only uid 0 in the container (reached from the host through
`docker exec -u 0`, i.e. the host's Docker authority) may administer it; the kernel reports the
caller (SO_PEERCRED). Policy lives on a dedicated volume and is re-read on every request.
"""
import json
import os
import re
import secrets
import socket
import stat
import struct
import sys
from pathlib import Path

POLICY_DIR = Path("/var/lib/woltspace-secrets")
SOCKET = Path("/run/woltspace-broker/admin.sock")
ACTION, ADMIN_UID, MAX_REQUEST = "dummy.ping", 0, 512
FIELDS = {"enroll": ("wolt",), "register": ("action",), "grant": ("wolt", "action"),
          "revoke": ("wolt", "action"), "run": ("wolt", "action")}
NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")
FILES = {"policy.json": 0o600, "action.key": 0o400, "audit.log": 0o600}


def action(store: Path) -> dict:
    if not store.read_text():
        raise ValueError("dummy store unavailable")
    return {"result": "accepted"}


def _read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a FIFO never blocks
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != FILES[path.name] or info.st_size > 8192):
            raise ValueError("unsafe broker file")
        return os.read(fd, 8192)  # 64 longest names twice fit
    finally:
        os.close(fd)


def _write(path: Path, data: bytes) -> None:
    """Atomic durable replace; a stale temp file from an unclean stop is dropped first."""
    tmp = path.with_name(path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, FILES[path.name])
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def load(policy_dir: Path) -> dict:
    """Validate the directory and the fixed schema; anything else fails closed."""
    info = policy_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe broker policy directory")
    if {p.name for p in policy_dir.iterdir()} - set(FILES) - {n + ".tmp" for n in FILES}:
        raise ValueError("unexpected broker policy contents")
    raw = _read(policy_dir / "policy.json")
    policy = json.loads(raw) if raw is not None else {"version": 1, "wolts": [], "grants": []}
    if not (isinstance(policy, dict) and set(policy) == {"version", "wolts", "grants"}
            and policy["version"] == 1 and isinstance(policy["wolts"], list)
            and isinstance(policy["grants"], list) and len(policy["wolts"]) <= 64
            and all(isinstance(w, str) and NAME.fullmatch(w) for w in policy["wolts"] + policy["grants"])
            and set(policy["grants"]) <= set(policy["wolts"])):
        raise ValueError("malformed broker policy")
    key = _read(policy_dir / "action.key")
    if key is not None and not re.fullmatch(rb"[0-9a-f]{64}", key):
        raise ValueError("malformed broker key")
    policy["registered"] = key is not None
    return policy


def apply(policy_dir: Path, request) -> str:
    op = request.get("op") if isinstance(request, dict) else None
    if not isinstance(op, str) or op not in FIELDS or set(request) != {"op", *FIELDS[op]}:
        return "invalid"
    wolt, name = request.get("wolt", "a"), request.get("action", ACTION)
    if not (isinstance(wolt, str) and NAME.fullmatch(wolt) and isinstance(name, str)):
        return "invalid"
    if name != ACTION:
        return "unknown-action"
    policy = load(policy_dir)
    if op == "register":  # the synthetic secret is born here and never leaves the broker
        _write(policy_dir / "action.key", secrets.token_hex(32).encode())
        return "ok"
    if op == "enroll" and wolt not in policy["wolts"] and len(policy["wolts"]) >= 64:
        return "full"
    if op == "enroll":
        policy["wolts"] = sorted({*policy["wolts"], wolt})
    elif wolt not in policy["wolts"]:
        return "unknown-wolt"
    elif op == "run":
        return "ok" if wolt in policy["grants"] and load(policy_dir)["registered"] else "not-granted"
    elif op == "grant" and not policy["registered"]:
        return "not-registered"
    else:
        policy["grants"] = sorted({*policy["grants"], wolt} - ({wolt} if op == "revoke" else set()))
    _write(policy_dir / "policy.json", json.dumps(
        {"version": 1, "wolts": policy["wolts"], "grants": policy["grants"]}).encode())
    return "ok"


def answer(conn: socket.socket, policy_dir: Path) -> None:
    _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    caller, request, result = ("host-admin" if uid == ADMIN_UID else "worker"), None, "invalid"
    conn.settimeout(2)
    try:
        raw = b""
        while b"\n" not in raw and len(raw) <= MAX_REQUEST and (chunk := conn.recv(MAX_REQUEST + 1)):
            raw += chunk
        if len(raw) <= MAX_REQUEST:
            request = json.loads(raw)
        result = "denied" if caller != "host-admin" else apply(policy_dir, request) if request else result
    except (ValueError, UnicodeDecodeError, TimeoutError):
        pass  # a silent or slow caller is malformed too
    except OSError:
        result = "error"
    op = request.get("op") if isinstance(request, dict) else None
    op = op if isinstance(op, str) and op in FIELDS else "other"
    name = ACTION if isinstance(request, dict) and request.get("action") == ACTION else "other"
    line = json.dumps({"caller": caller, "op": op, "action": name, "result": result}) + "\n"
    fd = os.open(policy_dir / "audit.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, line.encode())  # caller category, op, action and result only
    finally:
        os.close(fd)
    conn.sendall(json.dumps({"result": result}).encode() + b"\n")


def listen(path: Path = SOCKET) -> socket.socket:
    if path.is_socket():
        path.unlink()  # left by an unclean stop; the directory is the service's own
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(4)
    return server


def admin(argv: list[str], path: Path = SOCKET) -> int:
    fields = FIELDS.get(argv[0], ()) if argv else ()
    if not fields or len(argv) != 1 + len(fields):
        print("usage: woltspace secrets enroll WOLT | register ACTION | grant|revoke|run WOLT ACTION",
              file=sys.stderr)
        return 2
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(path))
            client.sendall(json.dumps({"op": argv[0], **dict(zip(fields, argv[1:]))}).encode() + b"\n")
            reply = json.loads(client.makefile("rb").readline(256))
    except (OSError, ValueError):
        reply = {"result": "unavailable"}
    print(json.dumps(reply))
    return 0 if reply == {"result": "ok"} else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["admin"]:
        sys.exit(admin(sys.argv[2:]))
    store, policy_dir, path = map(Path, sys.argv[1:4])  # fixed by the root startup owner
    try:
        action(store)
        load(policy_dir)
        server = listen(path)
        print(json.dumps({"result": "accepted"}), flush=True)
    except (OSError, ValueError):
        sys.exit(1)  # never print the store or exception text
    while True:
        conn = server.accept()[0]
        with conn:
            try:
                answer(conn, policy_dir)
            except OSError:
                pass  # no reply when the audit cannot be written
