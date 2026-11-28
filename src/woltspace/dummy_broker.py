"""Protected identity broker, stage 1: owner-only registry admin and one dummy action.

The broker runs as the service uid. Only uid 0 in the container (reached from the host through
`docker exec -u 0`, i.e. the host's Docker authority) may administer it; the kernel reports the
caller (SO_PEERCRED). A protected SQLite registry on the dedicated volume holds principals with
opaque stable IDs, typed resources, grants and a redacted audit. Lookups use an in-memory snapshot;
one writer thread commits every mutation together with its audit row. Stored grants start inactive
on every broker start until the owner grants them again, so restored or old media revives nothing.
Intake stays the serial admin socket: the writer and the lookup are separate, not yet concurrent.
"""
from array import array
from collections import deque
from concurrent.futures import Future
import hashlib
import http.client
import json
import os
import pwd
import queue
import re
import secrets
import select
import socket
import sqlite3
import ssl
import stat
import struct
import sys
import threading
import time
from pathlib import Path
from typing import NamedTuple

POLICY_DIR = Path("/var/lib/woltspace-secrets")
SOCKET = Path("/run/woltspace-broker/admin.sock")  # 0600 in a 0711 directory: only the service and root
LAUNCH = "launch.sock"
TELEGRAM, NOTICE = "telegram.notice", "Woltspace broker notice."
PROVIDER, CAFILE, SEND_SECONDS = ("api.telegram.org", 443), "/etc/ssl/certs/ca-certificates.crt", 15  # fixed
TOKEN, CHAT = re.compile(r"([1-9][0-9]{0,18}):[A-Za-z0-9_-]{30,64}"), re.compile(r"[1-9][0-9]{0,18}")
CREATE = "create.sock"  # 0666 beside it: the ordinary create route, nothing else
ACTION, ADMIN_UID, MAX_REQUEST, CAPACITY, PENDING, GROUP = "dummy.ping", 0, 512, 64, 16, 8
WORKERS, WAITING, PER_WOLT, BINDINGS = 2, 6, 3, 128
DUMMY_DELAY = 0.5
ACTIONS = {ACTION: ("secret", "dummy", "ping"), TELEGRAM: ("effect", "telegram", "notice")}  # allowlisted action -> (resource type, resource, operation)
FIELDS = {"enroll": ("wolt",), "rename": ("wolt", "to"), "retire": ("wolt",), "register": ("action",),
          "arm": ("action",), "provision": ("action", "chat", "token"), "grant": ("wolt", "action"), "revoke": ("wolt", "action"), "run": ("wolt", "action")}
NAME = re.compile(r"[a-z][a-z0-9-]{0,39}")
SESSION = re.compile(r"[a-z][a-z0-9-]{0,127}")
ATTEMPT = re.compile(r"[0-9a-f]{12}")
ATTEMPT_TTL = 15
DENIAL_WINDOW, DENIALS = 60.0, 32  # audited refusals per caller class and operation per window
PRINCIPAL = re.compile(r"p-[0-9a-f]{32}")
# Protected create: the ordinary node may only ask and report; the owner reviews and approves exact terms.
ORDINARY = {"create-request": ("request", "terms"), "create-status": ("request",), "create-report": ("request", "stage")}
OWNER = {"review": ("code",), "approve": ("code", "terms"), "reconcile": ("code",), "reject": ("code",)}
TERMS = ("name", "type", "harness", "model", "display", "policy", "role", "description")
CHECKS = {"request": re.compile(r"[0-9a-f]{32}"), "code": re.compile(r"c-[0-9a-f]{8}"),
          "stage": re.compile(r"scaffolding|scaffolded|ambiguous|launching|launched|launch-failed"),
          "terms": re.compile(r"[0-9a-f]{12}"), "session": SESSION,
          "conversation": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")}
# Each step is claimed once ("-ing"), so concurrent retries never scaffold or launch twice. A claim left
# by a crash is uncertain: only the owner's reconcile clears it, so a first launch is never silently repeated.
REPORTS = {"scaffolding": {"approved"}, "scaffolded": {"scaffolding"}, "ambiguous": {"approved", "scaffolding"},
           "launching": {"scaffolded", "launch-failed"}, "launched": {"launching"}, "launch-failed": {"launching"}}
RECONCILE = {"ambiguous": "approved", "scaffolding": "approved", "launching": "launch-failed"}
FILES = {"registry.db": 0o600, "registry.db-journal": 0o600, "action.key": 0o400}
TABLES = """
CREATE TABLE principals (id TEXT PRIMARY KEY, name TEXT UNIQUE, retired INTEGER NOT NULL DEFAULT 0);
CREATE TABLE resources (id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL UNIQUE);
CREATE TABLE grants (principal TEXT NOT NULL REFERENCES principals, resource TEXT NOT NULL REFERENCES resources,
                     operation TEXT NOT NULL, PRIMARY KEY (principal, resource, operation));
CREATE TABLE audit (seq INTEGER PRIMARY KEY, caller TEXT NOT NULL, op TEXT NOT NULL, principal TEXT,
                    action TEXT NOT NULL, result TEXT NOT NULL);
"""
CREATES = """CREATE TABLE creates (request TEXT PRIMARY KEY, code TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                      terms TEXT NOT NULL, status TEXT NOT NULL, principal TEXT REFERENCES principals);
"""
# v3: the exact first session a successful create launched, recorded with its "launched" transition. The column
# is added the same way on a fresh and on a migrated volume, so their schemas compare equal.
SESSION_COLUMN = "ALTER TABLE creates ADD COLUMN session TEXT; ALTER TABLE creates ADD COLUMN conversation TEXT;"
SCHEMA = f"{TABLES}{CREATES}{SESSION_COLUMN}PRAGMA user_version = 3;\n"


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
        if db.execute("PRAGMA user_version").fetchone()[0] == 1 and contract(db) == contract(EXPECTED_V1):
            db.executescript(f"BEGIN IMMEDIATE; {CREATES} {SESSION_COLUMN} PRAGMA user_version = 3; COMMIT;")
        if db.execute("PRAGMA user_version").fetchone()[0] == 2 and contract(db) == contract(EXPECTED_V2):
            db.executescript(f"BEGIN IMMEDIATE; {SESSION_COLUMN} PRAGMA user_version = 3; COMMIT;")  # rows kept
        if db.execute("PRAGMA user_version").fetchone()[0] != 3 or contract(db) != contract(EXPECTED):
            raise ValueError("incompatible broker registry")
        if db.execute("SELECT count(*) FROM principals WHERE name IS NOT NULL").fetchone()[0] > CAPACITY:
            raise ValueError("malformed broker registry")
    except (sqlite3.Error, ValueError):
        db.close()
        raise ValueError("incompatible broker registry")
    return db


def contract(db: sqlite3.Connection) -> list:
    return db.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").fetchall()


EXPECTED, EXPECTED_V1, EXPECTED_V2 = (sqlite3.connect(":memory:", check_same_thread=False) for _ in range(3))
EXPECTED.executescript(SCHEMA)
EXPECTED_V1.executescript(TABLES)
EXPECTED_V2.executescript(f"{TABLES}{CREATES}")


class Authz:
    """In-memory snapshot for lookups. Narrowing applies before a change is durable, widening after."""

    def __init__(self, db: sqlite3.Connection, policy_dir: Path):
        self.lock, self.policy_dir, self.active = threading.Lock(), policy_dir, set()  # every start: none
        self.bindings = {}  # session -> current WorkerBinding; never persisted
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
            self.bindings = {s: b for s, b in self.bindings.items() if b.principal != pid}
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


def mutate(db, op: str, wolt: str, name: str, to: str, resource=None, key=None) -> tuple:
    """One policy mutation and its audit row, validated against the durable registry."""
    row = db.execute("SELECT id FROM principals WHERE name = ?", (wolt,)).fetchone()
    pid, change, label = row[0] if row else None, None, name if "action" in FIELDS[op] else "other"
    resource, key = resource or ACTIONS[name][:2], key or name  # telegram: the provisioned bot and chat
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
        if db.execute("SELECT 1 FROM creates WHERE principal = ? AND status NOT IN ('launched', 'retired')",
                      (pid,)).fetchone():  # an unfinished create still scaffolds or launches under this name
            return audit(db, "host-admin", op, pid, label, "creating", lambda authz: authz.widen({wolt: pid}))
        db.execute("UPDATE principals SET name = ? WHERE id = ?", (to, pid))
        change = lambda authz: (authz.drop(op, pid, wolt), authz.widen({to: pid}))
    elif op == "retire":
        db.execute("DELETE FROM grants WHERE principal = ?", (pid,))
        db.execute("UPDATE principals SET name = NULL, retired = 1 WHERE id = ?", (pid,))
        db.execute("UPDATE creates SET status = 'retired' WHERE principal = ?", (pid,))  # the name is free again
        change = lambda authz: authz.drop(op, pid)
    elif rid is None:
        return audit(db, "host-admin", op, pid, label, "not-registered")
    elif op == "grant":
        db.execute("INSERT OR IGNORE INTO grants VALUES (?, ?, ?)", (pid, rid[0], ACTIONS[name][2]))
        change = lambda authz: authz.widen({}, (pid, key))
    else:
        db.execute("DELETE FROM grants WHERE principal = ? AND resource = ? AND operation = ?",
                   (pid, rid[0], ACTIONS[name][2]))
        change = lambda authz: authz.drop(op, pid, wolt, key)  # by id, in order after any queued grant
    reply, _ = audit(db, "host-admin", op, pid, label, "ok")
    return ({**reply, "id": pid} if op == "enroll" else reply), change


def lifecycle(db, caller: str, request: dict, denials=None) -> tuple:
    """Create reservation states: pending -> approved (one stable ID) -> scaffolded -> launched or launch-failed."""
    op, column = request["op"], "request" if "request" in request else "code"
    row = db.execute(f"SELECT request, code, terms, status, principal, session, conversation FROM creates WHERE {column} = ?",
                     (request[column],)).fetchone()

    def done(result, row=row, change=None, **extra):
        state = {"status": row[3], "code": row[1], **({"id": row[4]} if row[4] else {}),
                 **({"first_session": row[5], "first_conversation": row[6]} if row[5] else {})} if row else {}
        logged = denials.admit(caller, op, result) if denials else result  # refusals stay bounded
        if logged is None:
            return {"result": result}, None
        reply, change = audit(db, caller, op, row[4] if row else None, "other", logged, change)
        return ({**reply, **state, **extra} if result == "ok" else {"result": result}), change

    if op == "create-request":
        terms = json.dumps(request["terms"], sort_keys=True)
        if row:  # a replay returns its recorded state; other terms under the same ID are refused
            return done("ok") if row[2] == terms else done("conflict")
        name = request["terms"]["name"]
        if db.execute("SELECT 1 FROM principals WHERE name = ? UNION SELECT 1 FROM creates WHERE name = ?"
                      " AND status = 'pending'", (name, name)).fetchone():
            return done("name-held")
        row = (request["request"], "c-" + secrets.token_hex(4), terms, "pending", None, None, None)
        db.execute("INSERT INTO creates (request, code, name, terms, status, principal) VALUES (?, ?, ?, ?, ?, ?)",
                   (*row[:2], name, *row[2:5]))
        return done("ok", row)
    if row is None:
        return done("unknown-request")
    if op == "review":
        return done("ok", terms=json.loads(row[2]), fingerprint=hashlib.sha256(row[2].encode()).hexdigest()[:12])
    if op == "approve" and row[3] == "pending":
        name = json.loads(row[2])["name"]
        if request["terms"] != hashlib.sha256(row[2].encode()).hexdigest()[:12]:
            return done("terms-changed")  # the owner approves exactly what they reviewed
        if db.execute("SELECT 1 FROM principals WHERE name = ?", (name,)).fetchone():
            return done("name-held")
        if db.execute("SELECT count(*) FROM principals WHERE name IS NOT NULL").fetchone()[0] >= CAPACITY:
            return done("full")
        pid = "p-" + secrets.token_hex(16)  # persisted once, before any scaffold
        db.execute("INSERT INTO principals (id, name) VALUES (?, ?)", (pid, name))
        db.execute("UPDATE creates SET status = 'approved', principal = ? WHERE request = ?", (pid, row[0]))
        return done("ok", (*row[:3], "approved", pid, None, None), lambda authz: authz.widen({name: pid}))
    if op in {"create-status", "approve"}:  # an approve replay reports the recorded state
        return done("ok")
    target, allowed = {"reconcile": (RECONCILE.get(row[3]), set(RECONCILE)), "reject": ("rejected", {"pending"})}.get(
        op) or (request["stage"], REPORTS[request["stage"]])  # a rejected request frees its name
    if row[3] not in allowed:
        return done("refused")
    session, conversation = ((request.get("session"), request.get("conversation")) if target == "launched"
                             else row[5:7])
    if target == "launched" and not (session and conversation):
        return done("refused")  # a successful first launch is recorded with its exact session and conversation
    db.execute("UPDATE creates SET status = ?, session = ?, conversation = ? WHERE request = ?",
               (target, session, conversation, row[0]))
    return done("ok", (*row[:3], target, row[4], session, conversation))


def call(request: dict, path: Path | None = None) -> dict:
    """One framed request on the broker socket; the kernel tells the broker who is asking."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(5)
            client.connect(str(path or SOCKET))
            client.sendall(json.dumps(request).encode() + b"\n")
            reply = json.loads(client.makefile("rb").readline(2048))
    except (OSError, ValueError):
        reply = None
    return reply if isinstance(reply, dict) else {"result": "unavailable"}


class WorkerBinding(NamedTuple):
    principal: str
    session: str
    instance: str


class Dispatcher:
    """Trusted launcher interface. The transport must supply the binding for its channel."""

    def __init__(self, authz: Authz, writer: Writer, effect=False):
        self.authz, self.writer = authz, writer
        self.ready = threading.Condition(authz.lock)
        self.waiting = {}  # one FIFO per principal, in ready-wolt rotation order
        self.running = set()
        self.started = False
        self.effect = effect
        self.credential = self.operation = None  # (token, bot, chat, grant key): volatile, owner-provisioned
        self.effect_pending = False
        self.arming = False

    def bind(self, principal: str, session: str) -> WorkerBinding | None:
        """Called only by the trusted launcher, with the enrolled stable ID."""
        with self.ready:
            binding = self.prepare_binding(principal, session)
            if binding is not None:
                self.authz.bindings[session] = binding
            return binding

    def prepare_binding(self, principal: str, session: str) -> WorkerBinding | None:
        """Validate under the authorization lock without publishing a replacement."""
        current = self.authz.bindings.get(session)
        if principal not in self.authz.names.values():
            return None
        if current is None and len(self.authz.bindings) >= BINDINGS:
            return None
        if current is not None and current.principal != principal:
            return None
        return WorkerBinding(principal, session, secrets.token_hex(16))

    def end(self, binding: WorkerBinding) -> None:
        with self.ready:
            if self.authz.bindings.get(binding.session) == binding:
                del self.authz.bindings[binding.session]

    def submit(self, binding: WorkerBinding, name: str, alive=None) -> Future:
        future = Future()
        future.set_running_or_notify_cancel()  # the adapter owns completion
        with self.ready:
            if self.authz.bindings.get(binding.session) != binding:
                future.set_result("denied")
            elif name not in ACTIONS:
                future.set_result("unknown-action")
            elif (len(self.waiting.get(binding.principal, ())) >= PER_WOLT
                  or sum(map(len, self.waiting.values())) >= WAITING):
                future.set_result("busy")
            else:
                self.waiting.setdefault(binding.principal, deque()).append((binding, name, future, alive, self.operation))
                if not self.started:
                    self.started = True
                    for _ in range(WORKERS):
                        threading.Thread(target=self._work, daemon=True).start()
                self.ready.notify()
        return future

    def _work(self) -> None:
        while True:
            with self.ready:
                self.ready.wait_for(lambda: self.waiting.keys() - self.running)
                principal = next(pid for pid in self.waiting if pid not in self.running)
                queue_for_wolt = self.waiting.pop(principal)
                binding, name, future, alive, requested = queue_for_wolt.popleft()
                if queue_for_wolt:
                    self.waiting[principal] = queue_for_wolt
                self.running.add(principal)
            try:
                result = self._dispatch(binding, alive) if name == ACTION else self._telegram(binding, alive, requested)
            finally:
                with self.ready:
                    self.running.remove(principal)
                    self.ready.notify()
            future.set_result(result)

    def _dispatch(self, binding: WorkerBinding, alive) -> str:
        # At most two pool threads submit audit work. The serial owner route
        # has writer capacity even if every dispatch queue is full.
        def intent(db):
            row = db.execute(
                "INSERT INTO audit (caller, op, principal, action, result) VALUES (?, ?, ?, ?, ?)",
                ("worker", "dispatch", binding.principal, ACTION, "pending"),
            )
            return {"result": "ok", "seq": row.lastrowid}, None

        reply = self.writer.submit(intent)
        if reply["result"] != "ok":
            return reply["result"]
        with self.ready:
            admitted = (self.authz.bindings.get(binding.session) == binding
                        and (binding.principal, ACTION) in self.authz.active
                        and (alive is None or alive()))
        result = self._dummy() if admitted else "denied"

        def outcome(db):
            db.execute("UPDATE audit SET result = ? WHERE seq = ?", (result, reply["seq"]))
            return {"result": "ok"}, None

        return result if self.writer.submit(outcome)["result"] == "ok" else "unknown"

    def arm(self):
        with self.ready:
            if not self.effect:
                return {"result": "disabled"}
            if self.credential is None:
                return {"result": "not-provisioned"}
            if self.operation is not None or self.effect_pending or self.arming:
                return {"result": "busy"}
            self.arming = True
        operation = "arm-" + secrets.token_hex(16)
        reply = self.writer.submit(lambda db: audit(db, "host-admin", operation, None, TELEGRAM, "armed"))
        with self.ready:
            self.arming = False
            if reply == {"result": "armed"}:
                self.operation = operation
                return {"result": "ok", "id": operation}
        return reply

    def provision(self, chat, token):
        """Owner-only. The token stays in this process; the registry gets only the bot and chat digest."""
        match = TOKEN.fullmatch(token) if isinstance(token, str) else None
        if not (match and isinstance(chat, str) and CHAT.fullmatch(chat)):
            return {"result": "invalid"}
        with self.ready:
            if not self.effect:
                return {"result": "disabled"}
            if self.operation is not None or self.effect_pending or self.arming:
                return {"result": "busy"}
        digest = hashlib.sha256(f"{match[1]}:{chat}".encode()).hexdigest()[:32]
        resource = ("effect", f"telegram-{digest}")  # a new bot or chat is a new resource: grant again

        def register(db):
            db.execute("INSERT OR IGNORE INTO resources VALUES (?, ?, ?)", ("r-" + secrets.token_hex(16), *resource))
            return audit(db, "host-admin", "provision", None, TELEGRAM, "ok")

        reply = self.writer.submit(register)
        with self.ready:
            if reply == {"result": "ok"}:
                self.credential = (token, int(match[1]), int(chat), resource[1])
        return reply

    def resource(self, name):
        """The resource and grant key an owner mutation names; None until telegram is provisioned."""
        with self.ready:
            if name != TELEGRAM:
                return ACTIONS[name][:2], name
            return (("effect", self.credential[3]), f"{self.credential[3]}.notice") if self.credential else None

    def _telegram(self, binding, alive, requested):
        def admitted(credential):
            return (credential is not None  # provision is refused while an arm or a send is outstanding
                    and self.authz.bindings.get(binding.session) == binding
                    and (binding.principal, f"{credential[3]}.notice") in self.authz.active
                    and (alive is None or alive()))

        with self.ready:
            credential = self.credential
            if not admitted(credential):
                return "denied"
            if requested is None or requested != self.operation:
                return "unavailable"
            operation, self.operation = self.operation, None
            self.effect_pending = True

        def update(db, result, previous):
            changed = db.execute(
                "UPDATE audit SET principal = ?, result = ? WHERE op = ? AND action = ? AND result = ?",
                (binding.principal, result, operation, TELEGRAM, previous),
            )
            return {"result": "ok" if changed.rowcount == 1 else "storage-error"}, None

        try:
            reply = self.writer.submit(lambda db: update(db, "pending", "armed"))
            if reply["result"] != "ok":
                return reply["result"]
            with self.ready:
                go = admitted(credential)
            result = notify(credential) if go else "denied"
            if self.writer.submit(lambda db: update(db, result, "pending"))["result"] == "ok":
                return result
            return "unknown"
        finally:
            with self.ready:
                self.effect_pending = False

    def _dummy(self) -> str:
        # One fixed adapter with a bounded delay. No caller-selected timeout,
        # destination or input. Admission and storage locks are released here.
        time.sleep(DUMMY_DELAY)
        try:
            _key(self.authz.policy_dir)
        except (OSError, ValueError):
            return "storage-error"
        return "ok"


def notify(credential) -> str:
    """The one fixed provider request. "ok" only for a complete, verified reply naming our bot and chat."""
    token, bot, chat, _ = credential
    held, deadline = [], time.monotonic() + SEND_SECONDS

    class Connection(http.client.HTTPSConnection):
        def connect(self):  # the wall clock holds the TLS socket itself, before the handshake and after
            http.client.HTTPConnection.connect(self)  # a response with Connection: close takes it over
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host, do_handshake_on_connect=False)
            held.append(self.sock)
            if time.monotonic() >= deadline:
                raise TimeoutError
            self.sock.do_handshake()

    def expire():  # one wall clock for the whole exchange, however slowly the peer answers
        for sock in held:
            try:
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    connection, timer = None, threading.Timer(SEND_SECONDS, expire)
    timer.start()
    try:  # from here on every failure, the TLS setup included, is ambiguous and recorded: nothing is retried
        connection = Connection(*PROVIDER, timeout=10, context=ssl.create_default_context(cafile=CAFILE))
        connection.request("POST", f"/bot{token}/sendMessage", json.dumps({"chat_id": chat, "text": NOTICE}),
                           {"Content-Type": "application/json"})
        response = connection.getresponse()
        # Content-Length only: http.client takes EOF for a chunked trailer's last CRLF, and close-delimited
        # bodies cannot tell a cut from an end. The provider answers with a length.
        framed = not response.chunked and response.length is not None
        status, data = response.status, response.read(65537)
        if 400 <= status < 500:
            return "rejected"  # refused by the provider: not sent, and the arm stays spent
        if not (framed and len(data) <= 65536 and response.isclosed()):
            return "unknown"  # truncated, oversized or unfinished: a JSON prefix is no acceptance
        reply = json.loads(data, object_pairs_hook=_unique) if status == 200 else None
        message = reply["result"] if reply["ok"] is True else None  # a top-level ok other than true is no acceptance
        sender, target = message["from"], message["chat"]
        exact = (type(sender["id"]) is int and sender["id"] == bot and sender.get("is_bot") is True
                 and type(target["id"]) is int and target["id"] == chat)
    except Exception:
        return "unknown"
    finally:
        timer.cancel()
        if connection is not None:
            connection.close()
    return "ok" if exact else "mismatch"


class WorkerChannels:
    """A root-authorized launcher transfers one end of an unnamed socketpair."""

    def __init__(self, dispatch: Dispatcher):
        self.dispatch = dispatch
        self.lock = threading.Lock()
        self.channels = {}
        self.inodes = set()
        # Reserve replacement capacity while previously admitted calls finish.
        self.readers = threading.BoundedSemaphore(BINDINGS + WORKERS)

    def decision(self, principal: str | None, result: str, change=None) -> dict:
        def record(db):
            stored = db.execute("SELECT id FROM principals WHERE id = ?", (principal,)).fetchone()
            return audit(db, "host-admin", "attach", stored[0] if stored else None, "other", result, change)

        return self.dispatch.writer.submit(record)

    def attach(self, principal: str, session: str, descriptor: int) -> dict:
        if not self.readers.acquire(blocking=False):
            return self.decision(principal, "busy")
        channel = None
        handed_off = False
        duplicate = None
        try:
            duplicate = os.dup(descriptor)
            channel = socket.socket(fileno=duplicate)
            duplicate = None
            if (channel.family != socket.AF_UNIX or channel.type != socket.SOCK_SEQPACKET
                    or channel.getsockname() or channel.getpeername()):
                return self.decision(principal, "invalid")
            channel.setblocking(True)
            inode = os.fstat(channel.fileno()).st_ino
            with self.lock:
                if inode in self.inodes:
                    return self.decision(principal, "invalid")
                with self.dispatch.ready:
                    binding = self.dispatch.prepare_binding(principal, session)
                if binding is None:
                    return self.decision(principal, "denied")

                # Reserve the reader before writing the success audit. A reader
                # cannot send a hello until the durable decision is published.
                gate = threading.Event()

                def serve_if_committed():
                    gate.wait()
                    if handed_off:
                        self._serve(channel, binding, inode)

                reader = threading.Thread(target=serve_if_committed, daemon=True)
                try:
                    reader.start()
                except RuntimeError:
                    return self.decision(principal, "busy")
                try:
                    def publish(authz):
                        authz.bindings[session] = binding

                    reply = self.decision(principal, "ok", publish)
                    if reply != {"result": "ok"}:
                        return reply
                    previous = self.channels.get(session)
                    self.channels[session] = channel
                    self.inodes.add(inode)
                    handed_off = True
                    if previous is not None:
                        try:
                            previous.shutdown(socket.SHUT_RDWR)
                        except OSError:  # the old worker may already have closed its end
                            pass
                    return reply
                finally:
                    gate.set()
        except OSError:
            return self.decision(principal, "invalid")
        finally:
            if not handed_off:
                if channel is not None:
                    channel.close()
                if duplicate is not None:
                    os.close(duplicate)
                self.readers.release()

    def _serve(self, channel: socket.socket, binding: WorkerBinding, inode: int) -> None:
        closed = select.poll()
        closed.register(channel, select.POLLHUP | select.POLLRDHUP | select.POLLERR)
        try:
            self._send(channel, {"result": "ok", "principal": binding.principal, "instance": binding.instance})
            while raw := channel.recv(MAX_REQUEST + 1):
                self._send(channel, {"result": self._request(binding, raw, lambda: not closed.poll(0))})
        except OSError:
            pass  # clean exit or explicit replacement
        finally:
            with self.lock:
                if self.channels.get(binding.session) is channel:
                    del self.channels[binding.session]
                self.dispatch.end(binding)
                self.inodes.remove(inode)
                channel.close()
            self.readers.release()

    @staticmethod
    def _send(channel: socket.socket, reply: dict) -> None:
        channel.send(json.dumps(reply).encode(), socket.MSG_DONTWAIT)

    def _request(self, binding: WorkerBinding, raw: bytes, alive) -> str:
        if len(raw) > MAX_REQUEST:
            return "invalid"
        try:
            request = json.loads(raw, object_pairs_hook=_unique)
        except (ValueError, RecursionError):
            return "invalid"
        if (not isinstance(request, dict) or request.keys() != {"principal", "instance", "action"}
                or not isinstance(request["action"], str)):
            return "invalid"
        if request["principal"] != binding.principal or request["instance"] != binding.instance:
            return "denied"
        return self.dispatch.submit(binding, request["action"], alive).result()


def _receive_admin(conn: socket.socket, owner: bool, descriptors: list[int]):
    """Keep the existing framed JSON route; only an owner may pass a descriptor."""
    raw = b""
    word = array("i").itemsize
    while b"\n" not in raw and len(raw) <= MAX_REQUEST:
        if owner:
            chunk, ancillary, flags, _ = conn.recvmsg(
                MAX_REQUEST + 1, socket.CMSG_SPACE(2 * word), socket.MSG_CMSG_CLOEXEC,
            )
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    delivered = array("i")
                    delivered.frombytes(data[:len(data) - len(data) % word])
                    descriptors.extend(delivered)
            if flags & socket.MSG_CTRUNC or (len(descriptors) > 1 and b"\n" not in chunk):
                return None
        else:
            chunk = conn.recv(MAX_REQUEST + 1)
        if not chunk:
            break
        raw += chunk
    if len(raw) <= MAX_REQUEST and raw.endswith(b"\n") and raw.count(b"\n") == 1:
        return json.loads(raw, object_pairs_hook=_unique)
    return None


class DenialBudget:
    """Bound what a non-owner caller can add to the audit by being refused. Each caller class and
    operation gets DENIALS audited refusals per window, then one "suppressed" row marks the window
    and further refusals in it are still refused but not recorded. Owner actions are never limited."""

    def __init__(self):
        self.lock, self.windows = threading.Lock(), {}  # keys come from fixed caller and op labels

    def admit(self, caller: str, op: str, result: str) -> str | None:
        if caller == "host-admin" or result == "ok":  # every refusal of a non-owner counts
            return result
        with self.lock:
            now = time.monotonic()
            start, used = self.windows.get((caller, op), (now, 0))
            if now - start >= DENIAL_WINDOW:
                start, used = now, 0
            self.windows[(caller, op)] = start, used + 1
        return result if used < DENIALS else "suppressed" if used == DENIALS else None


class LaunchAttempts:
    """Bounded ephemeral selectors. Access to these methods is checked by the transport."""

    def __init__(self, authz, channels, denials=None):
        self.authz, self.channels, self.denials = authz, channels, denials or DenialBudget()
        self.lock = threading.Lock()
        self.pending = {}
        self.seen = {}  # reject repeated registration during the selector lifetime

    def decision(self, caller, op, result, principal=None):
        logged = self.denials.admit(caller, op, result)
        if logged is None:
            return {"result": result}

        def record(db):
            stored = db.execute("SELECT id FROM principals WHERE id = ?", (principal,)).fetchone()
            reply, _ = audit(db, caller, op, stored[0] if stored else None, "other", logged)
            return {"result": result} if logged == "suppressed" else reply, None
        return self.channels.dispatch.writer.submit(record)

    def open(self, wolt, session, attempt, conversation=None):
        with self.lock:
            now = time.monotonic()
            self.pending = {key: value for key, value in self.pending.items() if value[2] > now}
            self.seen = {key: deadline for key, deadline in self.seen.items() if deadline > now}
            with self.authz.lock:
                principal = self.authz.names.get(wolt)
                bound = self.authz.bindings.get(session)
            current = self.pending.get(session)
            selector = session, attempt
            if (principal is None or (current and current[0] != principal)
                    or (bound and bound.principal != principal)):
                reply = self.decision("node", "launch-open", "denied", principal)
                if (conversation is not None and reply == {"result": "denied"}
                        and selector not in self.seen and (not current or current[1] != attempt)):
                    return {"result": "not-opened"}
                return reply
            if selector in self.seen:
                return self.decision("node", "launch-open", "denied", principal)
            if len(self.seen) >= BINDINGS:
                return self.decision("node", "launch-open", "busy", principal)
            reply = self.decision("node", "launch-open", "ok", principal)
            if reply != {"result": "ok"}:
                return reply
            deadline = now + ATTEMPT_TTL
            self.seen[selector] = deadline
            self.pending[session] = principal, attempt, deadline, conversation
            return reply

    def redeem(self, session, attempt):
        with self.lock:
            current = self.pending.get(session)
            if not current or current[1] != attempt:
                return self.decision("host-admin", "launch-redeem", "denied"), None
            del self.pending[session]
            principal, _, expires, conversation = current
            if expires <= time.monotonic():
                return self.decision("host-admin", "launch-redeem", "denied", principal), None
            try:
                issuer, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            except OSError:
                return self.decision("host-admin", "launch-redeem", "unavailable", principal), None
            try:
                with issuer:
                    result = self.channels.attach(principal, session, issuer.fileno())
                if result == {"result": "ok"}:
                    if conversation is not None:
                        result = {**result, "principal": principal, "conversation": conversation}
                    return result, worker
            except BaseException:
                worker.close()
                raise
            worker.close()
            return result, None

    def cancel(self, session, attempt, proof=False):
        with self.lock:
            current = self.pending.get(session)
            principal = None
            if current and current[1] == attempt:
                principal = current[0]
                del self.pending[session]  # a failed audit does not reopen cancelled authority
            reply = self.decision("node", "launch-cancel", "ok", principal)
            if proof and reply == {"result": "ok"} and principal is not None:
                return {"result": "cancelled-before-redeem"}
            return reply


class Broker:
    def __init__(self, policy_dir: Path, node_uid: int | None = None, effect=False):
        self.node_uid = node_uid
        self.policy_dir, db = policy_dir, open_registry(policy_dir)
        if not (policy_dir / "action.key").exists() and not (policy_dir / "action.key").is_symlink():
            _write_key(policy_dir)
        _key(policy_dir)  # existing custody must be ours and well formed before readiness
        try:
            db.execute("UPDATE audit SET result = 'unknown' WHERE (op = 'dispatch' OR action = 'telegram.notice') AND result = 'pending'")
        except sqlite3.Error as exc:
            db.close()
            raise ValueError("broker recovery failed") from exc
        self.authz = Authz(db, policy_dir)
        self.writer = Writer(db, self.authz)
        self.dispatch = Dispatcher(self.authz, self.writer, effect)
        self.worker_channels = WorkerChannels(self.dispatch)
        self.denials = DenialBudget()
        self.launch_attempts = LaunchAttempts(self.authz, self.worker_channels, self.denials)

    def apply(self, request) -> dict:
        op = request.get("op") if isinstance(request, dict) else None
        if not isinstance(op, str) or op not in FIELDS or set(request) != {"op", *FIELDS[op]}:
            return {"result": "invalid"}
        wolt, to, name = request.get("wolt", "a"), request.get("to", "a"), request.get("action", ACTION)
        if not all(isinstance(v, str) and NAME.fullmatch(v) for v in (wolt, to)) or not isinstance(name, str):
            return {"result": "invalid"}
        if name not in ACTIONS:
            return self.record("host-admin", op, "unknown-action")
        if op in {"arm", "provision"}:
            if name != TELEGRAM:
                return {"result": "unknown-action"}
            return self.dispatch.arm() if op == "arm" else self.dispatch.provision(request["chat"], request["token"])
        if op == "run" and name == TELEGRAM:
            return {"result": "denied"}
        if op == "run":
            return self.record("host-admin", op, self.authz.admit(wolt, name), wolt)
        bound = self.dispatch.resource(name) if op in {"register", "grant", "revoke"} else (None, None)
        if bound is None:
            return {"result": "not-provisioned"}
        if op in {"revoke", "retire", "rename"}:
            self.authz.narrow(op, wolt, bound[1] or name)  # before it is durable or acknowledged
        return self.writer.submit(lambda db: mutate(db, op, wolt, name, to, *bound))

    def record(self, caller: str, op: str, result: str, wolt: str | None = None) -> dict:
        with self.authz.lock:
            pid = self.authz.names.get(wolt) if wolt else None
        name = ACTION if op in {"register", "grant", "revoke", "run"} and result != "unknown-action" else "other"
        logged = self.denials.admit(caller, op, result)  # every refusal is recorded up to the budget
        if logged is None:
            return {"result": result}
        reply = self.writer.submit(lambda db: audit(db, caller, op, pid, name, logged))  # none unaudited
        return {"result": result} if reply == {"result": "suppressed"} else reply

    def answer(self, conn: socket.socket, route: str = "admin") -> None:
        _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        owner = uid == ADMIN_UID
        caller, request, descriptors = ("host-admin" if owner else "worker"), None, []
        endpoint = None
        conn.settimeout(2)
        try:
            try:
                request = _receive_admin(conn, owner, descriptors)
            except (ValueError, RecursionError, TimeoutError):
                pass  # a silent or slow caller is malformed too
            op = request.get("op") if isinstance(request, dict) else None
            op = op if isinstance(op, str) else None
            if route == "launch":
                reply = (self.launch_control(request) if uid == self.node_uid and not descriptors
                         else self.launch_attempts.decision("worker", "launch-control", "denied"))
            elif route == "admin" and op == "launch-redeem":
                selector = self.launch_selector(request)
                if not owner:
                    reply = self.launch_attempts.decision("worker", "launch-redeem", "denied")
                elif not selector or descriptors:
                    reply = self.launch_attempts.decision(caller, "launch-redeem", "invalid")
                else:
                    reply, endpoint = self.launch_attempts.redeem(*selector)
            elif route == "create":  # any caller, ordinary create steps only; approval stays on the admin route
                reply = (self.create("worker", request) if op in ORDINARY and not descriptors
                         else self.record("worker", "other", "denied"))
            elif op in OWNER and owner and not descriptors:
                reply = self.create(caller, request)
            elif not owner:
                reply = self.record(caller, op if isinstance(op, str) and op in FIELDS else "other", "denied")
            elif op == "attach":
                reply = self.attach(request, descriptors)
            else:
                reply = self.apply(request) if not descriptors else {"result": "invalid"}
                if reply == {"result": "invalid"}:
                    reply = self.record(caller, op if isinstance(op, str) and op in FIELDS else "other", "invalid")
        finally:
            for descriptor in descriptors:
                os.close(descriptor)
        raw = json.dumps(reply).encode() + b"\n"
        if endpoint is None:
            conn.sendall(raw)
        else:
            with endpoint:
                count = conn.sendmsg([raw], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [endpoint.fileno()]))])
                if count != len(raw):
                    raise OSError("short launch response")

    @staticmethod
    def launch_selector(request, *extra):
        if not isinstance(request, dict) or request.keys() != {"op", "session", "attempt", *extra}:
            return None
        session, attempt = request["session"], request["attempt"]
        if (isinstance(session, str) and SESSION.fullmatch(session)
                and isinstance(attempt, str) and ATTEMPT.fullmatch(attempt)):
            return session, attempt
        return None

    def launch_control(self, request):
        op = request.get("op") if isinstance(request, dict) else None
        if op == "launch-open":
            fields = ("wolt",)
            conversation = request.get("conversation")
            if "conversation" in request:
                if not isinstance(conversation, str) or not CHECKS["conversation"].fullmatch(conversation):
                    return self.launch_attempts.decision("node", op, "invalid")
                fields += ("conversation",)
            selector = self.launch_selector(request, *fields)
            wolt = request.get("wolt")
            if selector and isinstance(wolt, str) and NAME.fullmatch(wolt):
                return self.launch_attempts.open(wolt, *selector, conversation=conversation)
        elif op == "launch-cancel":
            proof = request.get("proof") is True
            selector = self.launch_selector(request, *(("proof",) if proof else ()))
            if selector:
                return self.launch_attempts.cancel(*selector, proof=proof)
        label = op if op in ("launch-open", "launch-cancel") else "launch-control"
        return self.launch_attempts.decision("node", label, "invalid")

    def create(self, caller: str, request: dict) -> dict:
        fields = (OWNER if caller == "host-admin" else ORDINARY)[request["op"]]

        def valid(field, value):
            if field == "terms" and caller == "worker":  # the exact normalized create parameters
                return (isinstance(value, dict) and value.keys() == set(TERMS) and all(
                    isinstance(v, str) and len(v) <= 120 and v.isprintable() for v in value.values())
                    and bool(NAME.fullmatch(value["name"]) and NAME.fullmatch(value["type"])))
            return isinstance(value, str) and bool(CHECKS[field].fullmatch(value))

        if request["op"] == "create-report" and "session" in request:  # the launched first session and its
            fields = (*fields, "session", "conversation")  # immutable conversation id (a name can be reused)
        if request.keys() != {"op", *fields} or not all(valid(f, request[f]) for f in fields):
            return self.record(caller, request["op"], "invalid")
        return self.writer.submit(lambda db: lifecycle(db, caller, request, self.denials))

    def attach(self, request: dict, descriptors: list[int]) -> dict:
        principal = request.get("principal")
        if not isinstance(principal, str) or not PRINCIPAL.fullmatch(principal):
            principal = None
        session = request.get("session")
        if (request.keys() != {"op", "principal", "session"} or len(descriptors) != 1
                or principal is None or not isinstance(session, str) or not SESSION.fullmatch(session)):
            return self.worker_channels.decision(principal, "invalid")
        return self.worker_channels.attach(principal, session, descriptors[0])


def _unique(pairs: list) -> dict:
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate request key")
    return dict(pairs)


def listen(path: Path = SOCKET, mode: int = 0o600) -> socket.socket:
    if path.is_socket():
        path.unlink()  # left by an unclean stop; the directory is the service's own
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    os.chmod(path, mode)
    server.listen(4)
    return server


def serve(broker: "Broker", server: socket.socket, route: str = "admin") -> None:
    while True:
        try:
            conn = server.accept()[0]
        except OSError:
            return  # a closed listener; the startup owner sees the broker end
        with conn:
            try:
                broker.answer(conn, route)
            except OSError:
                pass


def admin(argv: list[str], path: Path | None = None) -> int:
    fields = {**FIELDS, **OWNER}.get(argv[0], ()) if argv else ()
    if argv[:1] == ["provision"]:  # chat and token from stdin only, never argv or the environment
        argv = argv + sys.stdin.read(256).split()
    if not fields or len(argv) != 1 + len(fields):
        print("usage: woltspace secrets enroll|retire WOLT | rename WOLT NEW | register ACTION"
              " | arm ACTION | provision ACTION <CHAT TOKEN | grant|revoke|run WOLT ACTION"
              " | review|reconcile|reject CODE | approve CODE FINGERPRINT", file=sys.stderr)
        return 2
    reply = call({"op": argv[0], **dict(zip(fields, argv[1:]))}, path)
    print(json.dumps(reply))
    return 0 if isinstance(reply, dict) and reply.get("result") == "ok" else 1


if __name__ == "__main__":
    if sys.argv[1:2] == ["admin"]:
        sys.exit(admin(sys.argv[2:]))
    store, policy_dir, path = map(Path, sys.argv[1:4])  # fixed by the root startup owner
    try:
        action(store)
        effect = sys.argv[4:] == ["telegram"]
        if effect:  # the provisioned token lives only in this process: no core file, no same-uid ptrace
            import ctypes
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) or ctypes.CDLL(None).prctl(3, 0, 0, 0, 0):
                raise OSError("broker must be non-dumpable")  # PR_SET_DUMPABLE 0, then PR_GET_DUMPABLE
        broker = Broker(policy_dir, pwd.getpwnam("node").pw_uid, effect)
        server, ordinary = listen(path), listen(path.with_name(CREATE), 0o666)
        launch = listen(path.with_name(LAUNCH), 0o666)
        print(json.dumps({"result": "accepted"}), flush=True)
    except (OSError, ValueError):
        sys.exit(1)  # never print the store or exception text
    threading.Thread(target=serve, args=(broker, ordinary, "create"), daemon=True).start()
    threading.Thread(target=serve, args=(broker, launch, "launch"), daemon=True).start()
    serve(broker, server)
