"""Use the shipping admin attach and worker packet routes in an owned container; probe the node's fences."""
from array import array
import json
import os
import socket
import sqlite3
import sys
from pathlib import Path

from woltspace import dummy_broker as broker


if sys.argv[1] == "audit":
    with sqlite3.connect(f"file:{broker.POLICY_DIR}/registry.db?mode=ro", uri=True) as db:
        print(json.dumps(db.execute("SELECT * FROM audit ORDER BY seq").fetchall()))
    raise SystemExit

if sys.argv[1] == "node":  # run as the shared node uid: no route to the token, the grant or the result
    print("node-discovery", flush=True)
    assert os.getuid() != 0 and not broker.SOCKET.with_name("effect.sock").exists()
    def cmdline(pid):
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return b""  # exited meanwhile

    pid, = [p for p in os.listdir("/proc") if p.isdigit() and b"dummy_broker.py" in cmdline(p)]
    process_files = [f"/proc/{pid}/{entry}" for entry in ("environ", "mem", "maps")]
    protected_files = ["/etc/hosts", "/etc/ssl/certs/ca-certificates.crt", f"{broker.POLICY_DIR}/registry.db"]
    for stage, paths, mode in (("node-process", process_files, "rb"), ("node-files", protected_files, "ab")):
        print(stage, flush=True)
        for path in paths:
            try:
                open(path, mode).close()
                raise SystemExit(1)
            except PermissionError:
                pass
    print("node-directory", flush=True)
    try:
        broker.SOCKET.parent.joinpath("probe").touch()
        raise SystemExit(1)
    except PermissionError:
        pass
    print("node-sockets", flush=True)
    assert broker.call({"op": "provision", "action": broker.TELEGRAM, "chat": "43", "token": "1:" + "x" * 30}) == {
        "result": "unavailable"}  # the admin socket refuses the connect itself
    for route in (broker.CREATE, broker.LAUNCH):
        reply = broker.call({"op": "provision", "action": broker.TELEGRAM, "chat": "43", "token": "1:" + "x" * 30},
                            broker.SOCKET.with_name(route))
        assert reply["result"] in {"denied", "invalid"}
    print("node-fenced")
    raise SystemExit


def attach(name, session):
    pid = broker.call({"op": "enroll", "wolt": name})["id"]
    endpoint, worker = socket.socketpair(type=socket.SOCK_SEQPACKET)
    with endpoint, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as admin:
        admin.settimeout(3)
        admin.connect(str(broker.SOCKET))
        message = dict(op="attach", principal=pid, session=session)
        admin.sendmsg([json.dumps(message).encode() + b"\n"],
                      [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", [endpoint.fileno()]))])
        assert json.loads(admin.makefile("rb").readline(256)) == {"result": "ok"}
    worker.settimeout(25)
    hello = json.loads(worker.recv(256))
    assert hello["result"] == "ok" and hello["principal"] == pid
    return worker, {key: hello[key] for key in ("principal", "instance")}


def send(channel, hello, **fields):
    channel.send(json.dumps({**hello, "action": broker.TELEGRAM, **fields}).encode())


def result(channel):
    return json.loads(channel.recv(256))["result"]


mode = sys.argv[1]
a, first = attach("alpha", "a")
b, second = attach("alpha" if mode == "crash" else "beta", "b")
os.setgroups([])
os.setgid(991)
os.setuid(991)
if mode == "crash":
    send(a, first)
    send(b, second)
    raise SystemExit(result(a) != "ok" or result(b) != "unavailable")
send(a, first, instance=second["instance"])
assert result(a) == "denied"
send(a, first, action="telegram.other")
assert result(a) == "unknown-action"
send(a, first, chat="43")
assert result(a) == "invalid"
send(b, second)
assert result(b) == "denied"  # the sibling has no grant
send(a, first, action=broker.ACTION)
assert result(a) == "ok"
send(a, first)
assert result(a) == mode, mode
