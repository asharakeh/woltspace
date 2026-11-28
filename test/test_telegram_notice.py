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
import time

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
            try:
                self.ours.send(json.dumps({"result": self.answers.pop(0) if self.answers else "unavailable"}).encode())
            except OSError:
                return  # the supervisor shut the channel down meanwhile


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


def test_each_layer_filters_the_reply_vocabulary_on_its_own(launch, tmp_path):
    """The relay writes only fixed words; the helper also refuses any other line it is handed."""
    start, state, _ = launch
    action, _ = start(Broker(["busy"]))
    fd = os.open(action / "request", os.O_WRONLY)
    reply = os.open(action / "reply", os.O_RDONLY)
    try:
        os.write(fd, b"not-a-tag\nabcdef01\n")  # an untagged line is ignored, a tag is answered
        assert os.read(reply, 64) == b"abcdef01 refused\n"  # the relay itself, before any helper filter
    finally:
        os.close(fd)
        os.close(reply)
    other = tmp_path / "other"
    (other / "home").mkdir(parents=True)
    (other / "action").mkdir()
    for name in ("request", "reply"):
        os.mkfifo(other / "action" / name)
    request = os.open(other / "action" / "request", os.O_RDWR | os.O_NONBLOCK)
    answer = os.open(other / "action" / "reply", os.O_RDWR | os.O_NONBLOCK)

    def forged():  # a reply side that does not keep to the vocabulary
        import select
        select.select([request], [], [], 10)
        tag = os.read(request, 9).strip()
        os.write(answer, b"ffffffff ok\n" + tag + b" sent-anyway\n")  # another tag's word, then ours

    thread = threading.Thread(target=forged, daemon=True)
    thread.start()
    try:
        assert helper(other) == ("refused", 6)
    finally:
        thread.join(5)
        os.close(request)
        os.close(answer)


def test_an_interrupted_call_never_hands_its_answer_to_the_next(launch):
    """The first helper is killed while its request is in flight; the next one must read only its own word."""
    start, state, _ = launch
    broker = Broker(["ok", "unavailable"], delay=1.5)
    start(broker)
    first = subprocess.Popen([sys.executable, "-I", str(HELPER)], env={"PATH": "/usr/bin:/bin",
                             "HOME": str(state / "home")}, stdout=subprocess.PIPE)
    deadline = time.monotonic() + 10
    while not broker.requests:  # the first request has reached the broker, its answer not yet back
        assert time.monotonic() < deadline
        time.sleep(.01)
    first.kill()
    first.wait()
    first.stdout.close()
    assert helper(state) == ("unavailable", 4)  # its own answer, never the late "ok"
    assert len(broker.requests) == 2


def test_a_held_lock_is_refused_before_anything_is_asked(launch):
    start, state, _ = launch
    broker = Broker(["ok"])
    action, _ = start(broker)
    import fcntl
    holder = os.open(action / "request", os.O_WRONLY | os.O_NONBLOCK)  # a paused call that never finishes
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        started = time.monotonic()
        assert helper(state) == ("unavailable", 4) and broker.requests == []  # bounded, and nothing written
        assert time.monotonic() - started < 8
    finally:
        os.close(holder)
    assert helper(state) == ("ok", 0)


def test_stop_interrupts_a_stalled_notice_and_admits_nothing_buffered(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor.os, "chown", lambda *_: None)
    (tmp_path / "home").mkdir()
    action, pipes = supervisor.notice_endpoint(tmp_path)
    broker, finished = Broker(["ok", "ok"], delay=20), threading.Event()  # the connector never answers in time
    bound = supervisor.Channel(broker.theirs, HELLO)
    relay = threading.Thread(target=supervisor.relay_notices, args=(*pipes, bound, finished), daemon=True)
    relay.start()
    call = subprocess.Popen([sys.executable, "-I", str(HELPER)], stdout=subprocess.PIPE,
                            env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path / "home")})
    deadline = time.monotonic() + 10
    while not broker.requests:
        assert time.monotonic() < deadline
        time.sleep(.01)
    queued = os.open(action / "request", os.O_WRONLY | os.O_NONBLOCK)
    os.write(queued, b"abcdef01\n")  # buffered behind the stalled one
    os.close(queued)
    started = time.monotonic()
    supervisor.retire(finished, bound, relay, action, pipes)
    assert time.monotonic() - started < 3 and not relay.is_alive() and not action.exists()
    assert call.communicate(timeout=10)[0] == b"unknown\n"  # submitted: ambiguous, never another call's word
    assert len(broker.requests) == 1 and bound.broken
