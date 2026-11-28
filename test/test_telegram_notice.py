"""The fixed notice entry: packaged helper -> this launch's pipes -> supervisor relay -> bound channel."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import threading

import pytest

from woltspace import dummy_broker, protected_stock as supervisor

HELPER = Path(__file__).resolve().parents[1] / "container" / "telegram-notice"
HELLO = {"principal": "p-" + "a" * 32, "instance": "b" * 32}


class Broker:
    """The broker's end of the bound channel, answering from a script."""

    def __init__(self, answers, delay=0.0):
        self.ours, self.theirs = socket.socketpair(type=socket.SOCK_SEQPACKET)
        self.answers, self.delay, self.requests = list(answers), delay, []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while (raw := self.ours.recv(512)):
            self.requests.append(json.loads(raw))
            threading.Event().wait(self.delay)
            self.ours.send(json.dumps({"result": self.answers.pop(0) if self.answers else "unavailable"}).encode())


@pytest.fixture
def launch(tmp_path, monkeypatch):
    """A launch's state dir with the real endpoint (ownership mocked: tests are not root) and a live relay."""
    owners = []
    monkeypatch.setattr(supervisor.os, "chown", lambda path, uid, gid: owners.append((Path(path).name, uid, gid)))
    state = tmp_path / "state"
    (state / "home").mkdir(parents=True)
    stopped, relays = threading.Event(), []

    def start(broker, timeout=25):
        action, pipes = supervisor.notice_endpoint(state)
        channel = supervisor.Channel(broker.theirs, HELLO)
        relay = threading.Thread(target=supervisor.relay_notices, args=(*pipes, channel, stopped), daemon=True)
        relay.start()
        relays.append((relay, action, pipes))
        return action, channel

    yield start, state, owners
    stopped.set()
    for relay, action, pipes in relays:
        relay.join(5)
        if action.exists():
            supervisor.remove_endpoint(action, pipes)


def helper(state, *args):
    done = subprocess.run([sys.executable, "-I", str(HELPER), *args], capture_output=True, timeout=40,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(state / "home")})
    return done.stdout.decode().strip(), done.returncode


@pytest.mark.parametrize("answer,word,code", [("ok", "ok", 0), ("denied", "denied", 3),
                                              ("unavailable", "unavailable", 4), ("unknown", "unknown", 5),
                                              ("busy", "refused", 6), ("invalid", "refused", 6)])
def test_helper_asks_once_through_the_bound_channel(launch, answer, word, code):
    start, state, owners = launch
    broker = Broker([answer])
    action, _ = start(broker)
    assert {p.name: oct(stat.S_IMODE(p.stat().st_mode)) for p in action.iterdir()} == {
        "request": "0o620", "reply": "0o640"}
    assert stat.S_IMODE(action.stat().st_mode) == 0o750 and all(stat.S_ISFIFO(p.stat().st_mode) for p in action.iterdir())
    assert owners == [("action", 0, 991), ("request", 0, 991), ("reply", 0, 991)]
    assert helper(state) == (word, code)
    assert broker.requests == [{**HELLO, "action": dummy_broker.TELEGRAM}]  # fixed: no message, chat or action input


def test_concurrent_helpers_are_serialized_and_stale_words_are_dropped(launch):
    start, state, _ = launch
    broker = Broker(["ok", "unavailable"], delay=0.3)
    action, _ = start(broker)
    fd = os.open(action / "reply", os.O_WRONLY | os.O_NONBLOCK)
    os.write(fd, b"ok\n")  # an abandoned earlier answer must not be read as a later request's
    os.close(fd)
    with ThreadPoolExecutor(2) as pool:
        words = sorted(pool.map(lambda _: helper(state)[0], range(2)))
    assert words == ["ok", "unavailable"] and len(broker.requests) == 2


def test_no_endpoint_no_args_and_a_lost_channel(launch, tmp_path):
    start, state, _ = launch
    assert helper(state) == ("unavailable", 4)  # no protected launch: nothing to ask
    broker = Broker(["ok"])
    action, channel = start(broker)
    assert helper(state, "--message", "x") == ("", 2) and broker.requests == []
    broker.ours.close()  # the broker end goes away after the request is sent: the answer is unknown, then spent
    assert helper(state) == ("unknown", 5)
    assert helper(state) == ("unavailable", 4) and channel.broken


def test_endpoint_is_rebuilt_and_removed_per_launch(launch):
    start, state, _ = launch
    action, pipes = supervisor.notice_endpoint(state)  # an earlier launch, never relayed
    stale = os.open(action / "request", os.O_WRONLY | os.O_NONBLOCK)  # a descriptor held past its launch
    first = (action / "request").stat().st_ino
    supervisor.remove_endpoint(action, pipes)
    assert not action.exists()
    broker = Broker(["ok"])
    again, _ = start(broker)  # the next launch: fresh pipes at the same place
    assert again == action and (action / "request").stat().st_ino != first
    with pytest.raises(BrokenPipeError):  # the old pipe has no reader left: the write itself is refused
        os.write(stale, b"n")
    os.close(stale)
    assert broker.requests == [] and helper(state) == ("ok", 0) and len(broker.requests) == 1
