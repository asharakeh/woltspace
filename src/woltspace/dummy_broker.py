"""Protected identity broker, stage 1: owner-only registry admin and one dummy action.

The broker runs as the service uid. Only uid 0 in the container (reached from the host through
`docker exec -u 0`, i.e. the host's Docker authority) may administer it; the kernel reports the
caller (SO_PEERCRED). A protected SQLite registry on the dedicated volume holds principals with
opaque stable IDs, typed resources, grants and a redacted audit. Lookups use an in-memory snapshot;
one writer thread commits every mutation together with its audit row. Stored grants start inactive
on every broker start until the owner grants them again, so restored or old media revives nothing.
Intake stays the serial admin socket: the writer and the lookup are separate, not yet concurrent.
"""
import json
import os
import queue
import re
import secrets
import socket
import sqlite3
import stat
import struct
import sys
import threading
from pathlib import Path

POLICY_DIR = Path("/var/lib/woltspace-secrets")
SOCKET = Path("/run/woltspace-broker/admin.sock")
ACTION, ADMIN_UID, MAX_REQUEST, CAPACITY, PENDING, GROUP = "dummy.ping", 0, 512, 64, 16, 8
ACTIONS = {ACTION: ("secret", "dummy", "ping")}  # allowlisted action -> (resource type, resource, operation)
FIELDS = {"enroll": ("wolt",), "rename": ("wolt", "to"), "retire": ("wolt",), "register": ("action",),
          "grant": ("wolt", "action"), "revoke": ("wolt", "action"), "run": ("wolt", "action")}
NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")
FILES = {"registry.db": 0o600, "registry.db-journal": 0o600, "action.key": 0o400}
SCHEMA = """
CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT UNIQUE, retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE resources (id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL UNIQUE);
CREATE TABLE grants (principal TEXT NOT NULL REFERENCES principals, resource TEXT NOT NULL REFERENCES resources,
                     operation TEXT NOT NULL, PRIMARY KEY (principal, resource, operation));
CREATE TABLE audit (seq INTEGER PRIMARY KEY, caller TEXT NOT NULL, op TEXT NOT NULL, principal TEXT,
                    action TEXT NOT NULL, result TEXT NOT NULL);
PRAGMA user_version = 1;
"""


def action(store: Path) -> dict:
    if not store.read_text():
        raise ValueError("dummy store unavailable")
    return {"result": "accepted"}


def _open(path: Path, flags: int = os.O_RDONLY) -> int:
    """Open without following a link or blocking on a FIFO; the descriptor must be our private file."""
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, FILES[path.name])
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != FILES[path.name]):
        os.close(fd)
        raise ValueError("unsafe broker file")
    return fd


def _key(policy_dir: Path) -> None:
    """The dummy custody: a key file apart from the registry, checked but never returned."""
    fd = _open(policy_dir / "action.key")
    try:
        if not re.fullmatch(rb"[0-9a-f]{64}", os.read(fd, 65)):
            raise ValueError("malformed broker key")
    finally:
        os.close(fd)


def _write_key(policy_dir: Path) -> None:
    """Custody initialization, once per volume at startup: atomic and durable, never a rotation.

    A stale temp file from an unclean stop is dropped first."""
    path = policy_dir / "action.key"
    tmp = path.with_name("action.key.tmp")
    tmp.unlink(missing_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "wb") as stream:
        stream.write(secrets.token_hex(32).encode())  # the synthetic secret is born here
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    dfd = os.open(policy_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def open_registry(policy_dir: Path) -> sqlite3.Connection:
    """Open or create the protected registry; any other or older layout fails closed, untouched."""
    info = policy_dir.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe broker policy directory")
    names = {p.name for p in policy_dir.iterdir()}
    if names - set(FILES) - {"action.key.tmp"} or ("registry.db" not in names and names - {"action.key.tmp"}):
        raise ValueError("incompatible broker volume")
    path = policy_dir / "registry.db"
    fd = _open(path, os.O_RDWR | os.O_CREAT)
    try:
        header = os.read(fd, 100)
    finally:
        os.close(fd)
    if header and (header[:16] != b"SQLite format 3\x00" or header[18:20] != b"\x01\x01"):
        raise ValueError("incompatible broker registry")  # not SQLite, or WAL: refused before any open
    if "registry.db-journal" in names:
        os.close(_open(policy_dir / "registry.db-journal"))  # a hot journal is recovered only if ours
    db = sqlite3.connect(f"file:{path}?mode=rw", uri=True, isolation_level=None, check_same_thread=False)
    try:
        db.execute("PRAGMA synchronous = FULL")  # connection settings only; nothing is written yet
        db.execute("PRAGMA foreign_keys = ON")
        empty = db.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0
        if empty and names <= {"registry.db"} and db.execute("PRAGMA user_version").fetchone()[0] == 0:
            db.execute("PRAGMA journal_mode = DELETE")
            db.executescript(f"BEGIN IMMEDIATE; {SCHEMA} COMMIT;")  # first start, or one cut short
        if db.execute("PRAGMA user_version").fetchone()[0] != 1 or contract(db) != contract(EXPECTED):
            raise ValueError("incompatible broker registry")
        if db.execute("SELECT count(*) FROM principals WHERE name IS NOT NULL").fetchone()[0] > CAPACITY:
            raise ValueError("malformed broker registry")
    except (sqlite3.Error, ValueError):
        db.close()
        raise ValueError("incompatible broker registry")
    return db


def contract(db: sqlite3.Connection) -> list:
    return db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").fetchall()


EXPECTED = sqlite3.connect(":memory:", check_same_thread=False)
EXPECTED.executescript(SCHEMA)


class Authz:
    """In-memory snapshot for lookups. Narrowing applies before a change is durable, widening after."""

    def __init__(self, db: sqlite3.Connection, policy_dir: Path):
        self.lock, self.policy_dir, self.active = threading.Lock(), policy_dir, set()  # every start: none
        self.names = dict(db.execute("SELECT name, id FROM principals WHERE name IS NOT NULL"))
        self.stored = {(pid, f"{resource}.{operation}") for pid, resource, operation in db.execute(
            "SELECT principal, resources.name, operation FROM grants JOIN resources ON resources.id = resource")}

    def admit(self, wolt: str, name: str) -> str:
        with self.lock:  # one decision point, ordered with narrowing
            pid = self.names.get(wolt)
            if pid is None:
                return "unknown-wolt"
            if (pid, name) not in self.active:  # a retained row alone confers no access
                return "inactive" if (pid, name) in self.stored else "not-granted"
        try:  # the dummy action runs outside the lock: it checks the custody and returns no secret
            _key(self.policy_dir)
        except (OSError, ValueError):
            return "storage-error"
        return "ok"

    def narrow(self, op: str, wolt: str, name: str) -> None:
        """Early narrowing by the name as the snapshot knows it; the commit repeats it by id."""
        with self.lock:
            pid = self.names.get(wolt)
            if pid is not None:
                self.drop(op, pid, wolt, name)

    # drop and widen run with self.lock held: by narrow, or by the writer for a whole committed batch.
    def drop(self, op: str, pid: str, wolt: str | None = None, name: str | None = None) -> None:
        if op == "retire":
            self.names = {n: i for n, i in self.names.items() if i != pid}
        elif op == "rename" and self.names.get(wolt) == pid:
            del self.names[wolt]
        for grants in (self.active, self.stored):
            grants -= {g for g in grants if g[0] == pid and (op == "retire" or op == "revoke" and g[1] == name)}

    def widen(self, names: dict, grant: tuple | None = None) -> None:
        self.names.update(names)
        self.active |= {grant} if grant else set()


class Writer:
    """The one registry writer: bounded pending work, queued mutations grouped into one commit."""

    def __init__(self, db: sqlite3.Connection, authz: Authz):
        self.db, self.authz, self.queue = db, authz, queue.Queue(PENDING)
        threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, work) -> dict:
        """`work(db)` returns (reply, change applied to the snapshot after commit) in its own savepoint."""
        slot = [threading.Event(), {"result": "storage-error"}]
        try:
            self.queue.put_nowait((work, slot))
        except queue.Full:
            return {"result": "busy"}
        slot[0].wait()
        return slot[1]

    def commit(self) -> None:
        self.db.execute("COMMIT")

    def _loop(self) -> None:
        while True:
            batch = [self.queue.get()]
            while len(batch) < GROUP and not self.queue.empty():
                batch.append(self.queue.get_nowait())
            results, changes = [], []
            try:
                self.db.execute("BEGIN IMMEDIATE")
                for work, _ in batch:
                    self.db.execute("SAVEPOINT one")
                    try:
                        result, change = work(self.db)
                    except Exception:  # this mutation and its audit row go together or not at all
                        self.db.execute("ROLLBACK TO one")
                        result, change = {"result": "storage-error"}, None
                    self.db.execute("RELEASE one")
                    results.append(result)
                    changes += [change] if change else []
                self.commit()
            except Exception:  # the writer outlives any failed batch
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                results, changes = [{"result": "storage-error"}] * len(batch), []  # early narrowing stays
            with self.authz.lock:  # the committed batch becomes visible to admission all at once
                for change in changes:  # in queue order; wider access is published only after the commit
                    change(self.authz)
            for (_, slot), result in zip(batch, results):  # replies only after publication
                slot[1] = result
                slot[0].set()


def audit(db, caller: str, op: str, principal, name: str, result: str, change=None) -> tuple:
    db.execute("INSERT INTO audit (caller, op, principal, action, result) VALUES (?, ?, ?, ?, ?)",
               (caller, op, principal, name, result))
    return {"result": result}, change


def mutate(db, op: str, wolt: str, name: str, to: str) -> tuple:
    """One policy mutation and its audit row, validated against the durable registry."""
    row = db.execute("SELECT id FROM principals WHERE name = ?", (wolt,)).fetchone()
    pid, change, label = row[0] if row else None, None, name if "action" in FIELDS[op] else "other"
    resource = ACTIONS[name][:2]
    rid = db.execute("SELECT id FROM resources WHERE type = ? AND name = ?", resource).fetchone()
    if op == "enroll" and pid is None:
        if db.execute("SELECT count(*) FROM principals WHERE name IS NOT NULL").fetchone()[0] >= CAPACITY:
            return audit(db, "host-admin", op, None, label, "full")
        pid = "p-" + secrets.token_hex(16)  # opaque, never derived from or reused for a name
        db.execute("INSERT INTO principals (id, name) VALUES (?, ?)", (pid, wolt))
        change = lambda authz: authz.widen({wolt: pid})
    elif op == "register":
        if rid is None:
            db.execute("INSERT INTO resources VALUES (?, ?, ?)", ("r-" + secrets.token_hex(16), *resource))
    elif op == "enroll":
        pass
    elif pid is None:
        return audit(db, "host-admin", op, None, label, "unknown-wolt")
    elif op == "rename":
        if db.execute("SELECT 1 FROM principals WHERE name = ?", (to,)).fetchone():  # keep the old name
            return audit(db, "host-admin", op, pid, label, "exists", lambda authz: authz.widen({wolt: pid}))
        db.execute("UPDATE principals SET name = ? WHERE id = ?", (to, pid))
        change = lambda authz: (authz.drop(op, pid, wolt), authz.widen({to: pid}))
    elif op == "retire":
        db.execute("DELETE FROM grants WHERE principal = ?", (pid,))
        db.execute("UPDATE principals SET name = NULL, retired = 1 WHERE id = ?", (pid,))
        change = lambda authz: authz.drop(op, pid)
    elif rid is None:
        return audit(db, "host-admin", op, pid, label, "not-registered")
    elif op == "grant":
        db.execute("INSERT OR IGNORE INTO grants VALUES (?, ?, ?)", (pid, rid[0], ACTIONS[name][2]))
        change = lambda authz: authz.widen({}, (pid, name))
    else:
        db.execute("DELETE FROM grants WHERE principal = ? AND resource = ? AND operation = ?",
                   (pid, rid[0], ACTIONS[name][2]))
        change = lambda authz: authz.drop(op, pid, wolt, name)  # by id, in order after any queued grant
    reply, _ = audit(db, "host-admin", op, pid, label, "ok")
    return ({**reply, "id": pid} if op == "enroll" else reply), change


class Broker:
    def __init__(self, policy_dir: Path):
        self.policy_dir, db = policy_dir, open_registry(policy_dir)
        if not (policy_dir / "action.key").exists() and not (policy_dir / "action.key").is_symlink():
            _write_key(policy_dir)
        _key(policy_dir)  # existing custody must be ours and well formed before readiness
        self.authz = Authz(db, policy_dir)
        self.writer = Writer(db, self.authz)

    def apply(self, request) -> dict:
        op = request.get("op") if isinstance(request, dict) else None
        if not isinstance(op, str) or op not in FIELDS or set(request) != {"op", *FIELDS[op]}:
            return {"result": "invalid"}
        wolt, to, name = request.get("wolt", "a"), request.get("to", "a"), request.get("action", ACTION)
        if not all(isinstance(v, str) and NAME.fullmatch(v) for v in (wolt, to)) or not isinstance(name, str):
            return {"result": "invalid"}
        if name not in ACTIONS:
            return self.record("host-admin", op, "unknown-action")
        if op == "run":
            return self.record("host-admin", op, self.authz.admit(wolt, name), wolt)
        if op in {"revoke", "retire", "rename"}:
            self.authz.narrow(op, wolt, name)  # before it is durable or acknowledged
        return self.writer.submit(lambda db: mutate(db, op, wolt, name, to))

    def record(self, caller: str, op: str, result: str, wolt: str | None = None) -> dict:
        pid = self.authz.names.get(wolt) if wolt else None
        name = ACTION if op in {"register", "grant", "revoke", "run"} and result != "unknown-action" else "other"
        return self.writer.submit(lambda db: audit(db, caller, op, pid, name, result))  # none unaudited

    def answer(self, conn: socket.socket) -> None:
        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        caller, request = ("host-admin" if uid == ADMIN_UID else "worker"), None
        conn.settimeout(2)
        try:
            raw = b""
            while b"\n" not in raw and len(raw) <= MAX_REQUEST and (chunk := conn.recv(MAX_REQUEST + 1)):
                raw += chunk
            if len(raw) <= MAX_REQUEST and raw.endswith(b"\n") and raw.count(b"\n") == 1:  # one framed object
                request = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, UnicodeDecodeError, TimeoutError):
            pass  # a silent or slow caller is malformed too
        op = request.get("op") if isinstance(request, dict) else None
        op = op if isinstance(op, str) and op in FIELDS else "other"
        if caller != "host-admin":
            reply = self.record(caller, op, "denied")
        else:
            reply = self.apply(request)
            if reply == {"result": "invalid"}:
                reply = self.record(caller, op, "invalid")
        conn.sendall(json.dumps(reply).encode() + b"\n")


def _unique(pairs: list) -> dict:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate request key")
    return dict(pairs)


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
        print("usage: woltspace secrets enroll|retire WOLT | rename WOLT NEW | register ACTION"
              " | grant|revoke|run WOLT ACTION", file=sys.stderr)
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
    return 0 if isinstance(reply, dict) and reply.get("result") == "ok" else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["admin"]:
        sys.exit(admin(sys.argv[2:]))
    store, policy_dir, path = map(Path, sys.argv[1:4])  # fixed by the root startup owner
    try:
        action(store)
        broker = Broker(policy_dir)
        server = listen(path)
        print(json.dumps({"result": "accepted"}), flush=True)
    except (OSError, ValueError):
        sys.exit(1)  # never print the store or exception text
    while True:
        conn = server.accept()[0]
        with conn:
            try:
                broker.answer(conn)
            except OSError:
                pass
