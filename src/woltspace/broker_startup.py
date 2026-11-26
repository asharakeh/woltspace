"""Opt-in trusted Docker startup owner; the ordinary node supervisor stays separate."""
import grp
import json
import os
import pwd
import secrets
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import dummy_broker

SERVICE = 990
CONFIG = Path("/etc/woltspace/broker-dummy")
STORE = Path("/var/lib/woltspace-broker/store")
SUDO_PATHS = (Path("/usr/bin/sudo"), Path("/etc/sudoers.d/node"))
READY_SECONDS, DRAIN_SECONDS, BROKER_SECONDS = 5.0, 5.0, 1.0


def protected(path: Path) -> None:
    """Validate the resolved object and every path component, including symlink locations."""
    for target in (path.absolute(), path.resolve(strict=True)):
        for part in (target, *target.parents):
            info = part.lstat()
            if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                raise ValueError("unsafe broker launch path")


def preflight() -> None:
    uid, gid = int(os.environ.get("HOST_UID") or "1000"), int(os.environ.get("HOST_GID") or "1000")
    if uid <= 0 or gid <= 0 or SERVICE in (uid, gid) or os.environ.get("WOLTSPACE_DIR"):
        raise ValueError("unsafe broker startup identity or install override")
    if any(p.pw_uid == SERVICE for p in pwd.getpwall()) or any(g.gr_gid == SERVICE for g in grp.getgrall()):
        raise ValueError("broker identity collision")
    if any(g.gr_name in {"root", "sudo", "wheel", "admin", "docker"} and
           (g.gr_gid == gid or "node" in g.gr_mem) for g in grp.getgrall()):
        raise ValueError("privileged node group")
    for path in (CONFIG, Path(__file__), Path(dummy_broker.__file__), Path(sys.executable)):
        protected(path)
    if not CONFIG.is_file() or CONFIG.read_text() != "dummy\n":
        raise ValueError("missing or unsafe dummy configuration")
    if any(path.exists() for path in SUDO_PATHS):
        raise ValueError("broker startup requires the no-sudo image")


def owned(info) -> bool:
    return (info.st_uid, info.st_gid) in {(0, 0), (SERVICE, SERVICE)}


def fresh_store() -> None:
    protected(STORE.parent.parent)
    STORE.parent.mkdir(mode=0o700, exist_ok=True)
    info = STORE.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or not owned(info):
        raise ValueError("unsafe stale dummy directory")
    if {path.name for path in STORE.parent.iterdir()} - {STORE.name}:
        raise ValueError("unexpected dummy directory contents")
    if STORE.exists() or STORE.is_symlink():
        info = STORE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not owned(info):
            raise ValueError("unsafe stale dummy store")
        STORE.unlink()  # only this validated exact file; never read/adopt the old credential
    fd = os.open(STORE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o400)
        stream.write(secrets.token_hex(16))
        os.fchown(stream.fileno(), SERVICE, SERVICE)
    os.chown(STORE.parent, SERVICE, SERVICE)


def prepare_policy() -> None:
    """The opt-in policy volume: a real mount, root-owned and empty on first use, then service-only."""
    path, run = dummy_broker.POLICY_DIR, dummy_broker.SOCKET.parent
    protected(path.parent)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not os.path.ismount(path):
        raise ValueError("broker policy volume missing")
    if (info.st_uid, info.st_gid) == (0, 0) and not any(path.iterdir()):
        os.chown(path, SERVICE, SERVICE)
        os.chmod(path, 0o700)
    info = path.lstat()
    if (info.st_uid, info.st_gid) != (SERVICE, SERVICE) or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("unsafe broker policy volume")
    protected(run.parent)
    run.mkdir(mode=0o700, exist_ok=True)
    info = run.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or not owned(info):
        raise ValueError("unsafe broker socket directory")
    os.chown(run, SERVICE, SERVICE)


def supervise(node_argv: list[str]) -> int:
    children = []
    stopping = False

    def stop(signum, frame):
        nonlocal stopping
        stopping = True

    previous = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    created = served = False
    try:
        fresh_store()
        created = True
        prepare_policy()
        served = True

        broker = subprocess.Popen([sys.executable, "-I", "-S", dummy_broker.__file__, str(STORE),
                                   str(dummy_broker.POLICY_DIR), str(dummy_broker.SOCKET)],
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/",
            user=SERVICE, group=SERVICE, extra_groups=[],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        children.append(broker)
        assert broker.stdout is not None
        deadline = time.monotonic() + READY_SECONDS
        ready = b""
        while b"\n" not in ready:
            if stopping or broker.poll() is not None or time.monotonic() >= deadline:
                return 1
            if select.select([broker.stdout], [], [], min(.05, deadline - time.monotonic()))[0]:
                chunk = os.read(broker.stdout.fileno(), 128)
                if not chunk:
                    return 1
                ready += chunk
                if len(ready) > 128:
                    return 1
        if stopping or json.loads(ready) != {"result": "accepted"} or broker.poll() is not None:
            return 1
        node = subprocess.Popen(node_argv, close_fds=True)
        children.append(node)
        while not stopping and node.poll() is None and broker.poll() is None:
            time.sleep(.05)
        if stopping:
            return 0
        return 1 if broker.poll() is not None else node.returncode
    finally:
        # Reverse creation order: preserve node's connector drain before stopping its broker.
        cleanup_failed = False
        for child in reversed(children):
            try:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=DRAIN_SECONDS if child is children[-1] and len(children) == 2 else BROKER_SECONDS)
                    except subprocess.TimeoutExpired:
                        child.kill()
                child.wait(timeout=BROKER_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_failed = True  # still attempt the other owned child; never claim successful cleanup
            if child.stdout:
                child.stdout.close()
        if created:
            try:
                STORE.unlink(missing_ok=True)
                STORE.parent.rmdir()  # unexpected contents refuse; no recursive deletion
                if served:  # only the socket directory this start validated
                    dummy_broker.SOCKET.unlink(missing_ok=True)
                    dummy_broker.SOCKET.parent.rmdir()
            except OSError:
                cleanup_failed = True
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if cleanup_failed:
            raise RuntimeError("broker startup cleanup failed")
