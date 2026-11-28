"""Use the shipping admin attach and worker packet routes in an owned container."""
from array import array
import json
import os
import socket
import sqlite3
import sys

from woltspace import dummy_broker as broker


if sys.argv[1] == "audit":
    with sqlite3.connect(f"file:{broker.POLICY_DIR}/registry.db?mode=ro", uri=True) as db:
        print(json.dumps(db.execute("SELECT * FROM audit ORDER BY seq").fetchall()))
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
send(b, second)
assert result(b) == "denied"
send(a, first, action=broker.ACTION)
assert result(a) == "ok"
send(a, first)
assert result(a) == mode
