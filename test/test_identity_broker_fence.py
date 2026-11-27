"""Private inherited-channel fixture driven by a synthetic issuer on Linux."""

from contextlib import ExitStack, contextmanager
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory

LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_DUMPABLE = 4
PR_GET_DUMPABLE = 3
APPROVED = "dummy.ping"


def prctl(operation, value=0):
    status = LIBC.prctl(operation, value, 0, 0, 0)
    if status < 0:
        raise OSError(ctypes.get_errno(), "process protection failed")
    return status


def wire(channel, payload):
    channel.sendall(json.dumps(payload).encode("ascii"))


def receive(channel):
    raw = channel.recv(4096)
    if not raw:
        raise EOFError("private mock channel closed")
    return json.loads(raw)


def link_visible(path):
    try:
        os.readlink(path)
    except PermissionError:
        return False
    return True


def worker(socket_fd, protected):
    if protected:
        prctl(PR_SET_DUMPABLE)
    with socket.socket(fileno=socket_fd) as channel:
        wire(channel, {"ready": True, "uid": os.geteuid()})
        issued = receive(channel)
        for line in sys.stdin:
            directive = json.loads(line)
            if "check_paths" in directive:
                wire(channel, [link_visible(path) for path in directive["check_paths"]])
                continue
            request = {key: issued[key] for key in ("wolt", "session", "instance")}
            request.update(directive.get("claim", {}))
            request["proof"] = directive.get("proof", issued["proof"])
            request["action"] = directive.get("action", APPROVED)
            wire(channel, request)


class MockIssuer:
    def __init__(self):
        self.enrolled = {"alpha": "wolt-a", "beta": "wolt-b"}
        self.grants = {"wolt-a": {APPROVED}, "wolt-b": set()}
        self.sessions = {}
        self.calls = 0

    def issue(self, name, session, channel):
        registered = self.enrolled[name]
        state = self.sessions.setdefault(session, {"wolt": registered, "history": []})
        if state["wolt"] != registered:
            raise PermissionError("cannot reassign an existing conversation")
        issued = {
            "wolt": registered,
            "session": session,
            "instance": secrets.token_hex(12),
            "proof": secrets.token_hex(24),
        }
        channel.settimeout(5)
        wire(channel, issued)
        state["active"] = issued
        return issued["instance"]

    def authorize(self, request):
        state = self.sessions.get(request["session"])
        session = state["active"] if state is not None else None
        if (
            session is None
            or session["wolt"] != request["wolt"]
            or session["instance"] != request["instance"]
            or not hmac.compare_digest(session["proof"], request["proof"])
            or request["action"] not in self.grants[session["wolt"]]
        ):
            return {"result": "denied"}
        state["history"].append("dummy action accepted")
        self.calls += 1
        return {"result": "accepted"}


@contextmanager
def launch(directory, *, protected=True):
    directory.mkdir(mode=0o700)
    for name in ("home", "config", "data", "wolts"):
        (directory / name).mkdir(mode=0o700)
    env = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HOME": str(directory / "home"),
        "XDG_CONFIG_HOME": str(directory / "config"),
        "XDG_DATA_HOME": str(directory / "data"),
        "WOLTSPACE_WOLTS_DIR": str(directory / "wolts"),
    }
    broker_socket, endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with broker_socket, endpoint:
        endpoint_fd = endpoint.fileno()
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", __file__, "--worker", str(endpoint_fd), str(int(protected))],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=directory,
            env=env,
            pass_fds=(endpoint_fd,),
            text=True,
        )
        endpoint.close()
        broker_socket.settimeout(5)
        try:
            ready = receive(broker_socket)
            assert ready == {"ready": True, "uid": os.geteuid()}
            yield process, broker_socket, endpoint_fd
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def instruct(instance, **directive):
    process, channel, _ = instance
    process.stdin.write(json.dumps(directive) + "\n")
    process.stdin.flush()
    return receive(channel)


def action(broker, instance, **directive):
    return broker.authorize(instruct(instance, **directive))["result"]


def prove_identity_and_resume(tmp_path):
    assert os.geteuid() != 0
    previous_dumpability = prctl(PR_GET_DUMPABLE)
    prctl(PR_SET_DUMPABLE)
    broker = MockIssuer()
    conversation = "conversation-a"
    try:
        with ExitStack() as children:
            first = children.enter_context(launch(tmp_path / "first"))
            peer = children.enter_context(launch(tmp_path / "peer"))
            control = children.enter_context(launch(tmp_path / "control", protected=False))
            old_instance = broker.issue("alpha", conversation, first[1])
            broker.issue("beta", "conversation-b", peer[1])
            broker.issue("beta", "control", control[1])
            assert action(broker, first) == "accepted"
            history = tuple(broker.sessions[conversation]["history"])
            assert history == ("dummy action accepted",)
            assert action(broker, peer) == "denied"
            assert action(broker, first, action="ungranted-action") == "denied"

            claim = {"wolt": "wolt-a", "session": conversation, "instance": old_instance}
            assert action(broker, peer, claim=claim) == "denied"
            name_hash = hashlib.sha256(b"alpha").hexdigest()
            assert action(broker, peer, claim=claim, proof=name_hash) == "denied"
            try:
                broker.issue("beta", conversation, peer[1])
            except PermissionError:
                pass
            else:
                raise AssertionError("conversation was reassigned")

            first_descriptor = f"/proc/{first[0].pid}/fd/{first[2]}"
            controller_descriptor = f"/proc/{os.getpid()}/fd/{first[1].fileno()}"
            control_descriptor = f"/proc/{control[0].pid}/fd/{control[2]}"
            assert instruct(peer, check_paths=[control_descriptor, first_descriptor, controller_descriptor]) == [True, False, False]

            resumed = children.enter_context(launch(tmp_path / "resumed"))
            new_instance = broker.issue("alpha", conversation, resumed[1])
            assert new_instance != old_instance
            assert broker.sessions[conversation]["wolt"] == "wolt-a"
            assert tuple(broker.sessions[conversation]["history"]) == history
            assert action(broker, first) == "denied"
            assert action(broker, first, claim={"instance": new_instance}) == "denied"
            assert action(broker, resumed) == "accepted"
            assert broker.calls == 2
        assert all(item[0].poll() is not None for item in (first, peer, control, resumed))
    finally:
        prctl(PR_SET_DUMPABLE, previous_dumpability)


def test_identity_and_resume(tmp_path):
    if sys.platform != "linux":
        import pytest
        pytest.skip("Linux process dumpability and procfs are required")
    assert tmp_path.resolve().is_relative_to(Path(os.environ["TMPDIR"]).resolve())
    completed = subprocess.run(
        [sys.executable, "-I", "-S", __file__],
        env={"PATH": "/usr/bin:/bin", "TMPDIR": str(tmp_path)},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (completed.returncode, completed.stdout, completed.stderr) == (0, "PASS mock private-channel\n", "")
    assert list(tmp_path.iterdir()) == []


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        worker(int(sys.argv[2]), sys.argv[3] == "1")
    elif len(sys.argv) == 1:
        with TemporaryDirectory(prefix="identity-fence-") as scratch:
            prove_identity_and_resume(Path(scratch))
        print("PASS mock private-channel")
    else:
        sys.exit(2)
