"""Synthetic root launcher and ordinary worker for the fork-only Docker proof."""

from array import array
from contextlib import ExitStack, contextmanager
import ctypes
import json
import os
import pwd
import re
import selectors
import signal
import socket
import sqlite3
import subprocess
import sys
import time

ADMIN = "/run/woltspace-broker/admin.sock"
REGISTRY = "/var/lib/woltspace-secrets/registry.db"
ACTION = "dummy.ping"
ENV = {"PATH": "/usr/bin:/bin"}


def admin(op, *, descriptor=None, **fields):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(ADMIN)
        payload = json.dumps({"op": op, **fields}).encode() + b"\n"
        if descriptor is None:
            client.sendall(payload)
        else:
            client.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [descriptor]))])
        return json.loads(client.makefile("rb").readline(256))


def owner(op, wolt):
    assert admin(op, wolt=wolt, action=ACTION) == {"result": "ok"}


def principal(wolt):
    reply = admin("enroll", wolt=wolt)
    assert reply["result"] == "ok" and re.fullmatch(r"p-[0-9a-f]{32}", reply["id"])
    return reply["id"]


def worker(descriptor):
    uid = os.geteuid()
    assert uid not in {0, 990}
    assert ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE
    with socket.socket(fileno=descriptor) as channel:
        channel.settimeout(5)
        print(f"ready {uid}", flush=True)
        hello = json.loads(channel.recv(512))
        assert hello["result"] == "ok"
        print(json.dumps({"principal": hello["principal"], "instance": hello["instance"]}), flush=True)
        for line in sys.stdin:
            override = json.loads(line)
            request = {"principal": hello["principal"], "instance": hello["instance"], "action": ACTION}
            try:
                channel.send(json.dumps({**request, **override}).encode())
                raw = channel.recv(512)
            except (BrokenPipeError, ConnectionResetError):
                raw = b""
            print(json.loads(raw)["result"] if raw else "closed", flush=True)


def read_line(process, timeout=5):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(timeout), "worker response deadline"
    return process.stdout.readline(512).decode().strip()


@contextmanager
def launch(wolt, session):
    node = pwd.getpwnam("node")
    assert node.pw_uid not in {0, 990}
    if os.geteuid() == 0:
        credentials = {"user": node.pw_uid, "group": node.pw_gid, "extra_groups": []}
    else:
        assert os.geteuid() == node.pw_uid
        credentials = {}
    endpoint, worker_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    with endpoint, worker_channel:
        descriptor = worker_channel.fileno()
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", __file__, "worker", str(descriptor)],
            pass_fds=(descriptor,), **credentials,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=ENV, bufsize=0,
        )
        worker_channel.close()
        try:
            assert read_line(process) == f"ready {node.pw_uid}"
            assert admin("attach", principal=wolt, session=session, descriptor=endpoint.fileno()) == {"result": "ok"}
            endpoint.close()
            identity = json.loads(read_line(process))
            assert identity["principal"] == wolt and re.fullmatch(r"[0-9a-f]{32}", identity["instance"])
            yield process, identity
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()


def send(launch_info, **claims):
    process, _ = launch_info
    process.stdin.write(json.dumps(claims).encode() + b"\n")
    return time.perf_counter()


def ask(launch_info, **claims):
    send(launch_info, **claims)
    return read_line(launch_info[0])


def count(wolt, result):
    with sqlite3.connect(f"file:{REGISTRY}?mode=ro", uri=True, timeout=1) as db:
        return db.execute(
            "SELECT count(*) FROM audit WHERE op = 'dispatch' AND principal = ? AND result = ?",
            (wolt, result),
        ).fetchone()[0]


def wait_pending(wolt):
    deadline = time.monotonic() + 3
    while not count(wolt, "pending"):
        assert time.monotonic() < deadline, "intent deadline"
        time.sleep(0.005)


def exercise():
    alpha, beta, gamma = map(principal, ("wolt-a", "wolt-b", "wolt-c"))
    owner("grant", "wolt-c")
    with ExitStack() as stack:
        a = stack.enter_context(launch(alpha, "conversation-a"))
        b = stack.enter_context(launch(beta, "conversation-b"))
        assert ask(a, principal=beta) == "denied"
        assert ask(a, instance=b[1]["instance"]) == "denied"
        assert ask(b) == "denied" and ask(a) == "ok"
        replacement = stack.enter_context(launch(alpha, "conversation-a"))
        assert replacement[1]["instance"] != a[1]["instance"]
        assert ask(a) == "closed"
        assert ask(replacement, instance=a[1]["instance"]) == "denied"
        assert ask(replacement) == "ok"
    owner("grant", "wolt-b")
    with ExitStack() as stack:
        # Multiple inherited channels simulate separate sessions of the same principal.
        alphas = [stack.enter_context(launch(alpha, f"a-{i}")) for i in range(5)]
        betas = [stack.enter_context(launch(beta, f"b-{i}")) for i in range(5)]
        c = stack.enter_context(launch(gamma, "c"))
        initial_alpha_ok = count(alpha, "ok")
        started = time.perf_counter()
        starts = {alphas[0][0]: send(alphas[0]), betas[0][0]: send(betas[0])}
        wait_pending(alpha)
        wait_pending(beta)
        latencies, results = [], []

        def collect(process):
            result = read_line(process)
            results.append(result)
            latencies.append((time.perf_counter() - starts.pop(process)) * 1000)
            return result

        with ExitStack() as selectors_open:
            groups = (alphas[1:], betas[1:])
            selectors_ready = [selectors_open.enter_context(selectors.DefaultSelector()) for _ in groups]
            for group, selector in zip(groups, selectors_ready):
                for instance in group:
                    process = instance[0]
                    starts[process] = send(instance)
                    selector.register(process.stdout, selectors.EVENT_READ, process)
            for selector in selectors_ready:
                ready = selector.select(3)
                assert len(ready) == 1 and collect(ready[0][0].data) == "busy"
            starts[c[0]] = send(c)
            assert collect(c[0]) == "busy"
        revoke_started = time.perf_counter()
        owner("revoke", "wolt-a")
        revoke_ms = (time.perf_counter() - revoke_started) * 1000
        assert collect(alphas[0][0]) == "ok"
        # A fresh gamma request must progress before beta's last queued response.
        starts[c[0]] = send(c)
        order = []
        with selectors.DefaultSelector() as responses:
            for process in starts:
                responses.register(process.stdout, selectors.EVENT_READ, process)
            while starts:
                ready = responses.select(5)
                assert ready, "dispatch completion deadline"
                for key, _ in ready:
                    process = key.data
                    order.append(process)
                    responses.unregister(key.fileobj)
                    outcome = collect(process)
                    if process == c[0]:
                        assert outcome == "ok"
        remaining_betas = {process for process, _ in betas}
        assert order.index(c[0]) < max(i for i, process in enumerate(order) if process in remaining_betas)
        assert count(alpha, "ok") == initial_alpha_ok + 1
        assert sorted(results) == ["busy"] * 3 + ["denied"] * 3 + ["ok"] * 6
        latencies.sort()
        print("dispatch submissions=12 ok=6 denied=3 busy=3 "
              f"requests_per_second={12 / (time.perf_counter() - started):.2f} "
              f"p50_ms={latencies[5]:.3f} p95_ms={latencies[11]:.3f} "
              f"p99_ms={latencies[11]:.3f} revoke_ms={revoke_ms:.3f}")


def crash(pid):
    assert os.geteuid() == 0
    with open(f"/proc/{pid}/status", encoding="utf-8") as status:
        assert re.search(r"^Uid:\s+990\s+990\s+990\s+990$", status.read(), re.M)
    with open(f"/proc/{pid}/cmdline", "rb") as cmdline:
        args = cmdline.read().split(b"\x00")
    assert args[1:3] == [b"-I", b"-S"] and args[3].endswith(b"/dummy_broker.py")
    beta = principal("wolt-b")
    with launch(beta, "crash") as b:
        assert count(beta, "unknown") == 0
        send(b)
        wait_pending(beta)
        os.kill(pid, signal.SIGKILL)


def recover():
    beta = principal("wolt-b")
    assert count(beta, "unknown") == 1 and count(beta, "pending") == 0
    with launch(beta, "crash") as b:
        assert ask(b) == "denied"  # Stage 1 grants are inactive at restart
        owner("grant", "wolt-b")
        assert ask(b) == "ok"
    assert count(beta, "unknown") == 1
    print("PASS unknown-no-replay")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "worker":
        worker(int(sys.argv[2]))
    elif len(sys.argv) == 2 and sys.argv[1] == "exercise":
        assert os.geteuid() == 0
        exercise()
    elif len(sys.argv) == 3 and sys.argv[1] == "crash":
        crash(int(sys.argv[2]))
    elif len(sys.argv) == 2 and sys.argv[1] == "recover":
        assert os.geteuid() == 0
        recover()
    else:
        sys.exit(2)
