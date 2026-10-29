"""The owner hears when mail of theirs waits for an agent that cannot wake
(inbox_notice.py, and the waker that calls it): a real store, a real HTTP
/notify on loopback that records what it is sent."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from inbox_support import limits, reader, wolt

import inbox
import inbox_notice
import inbox_wake

BODY = "DUMMY_BODY_MARKER"


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    wolt(tmp_path, "pal")
    monkeypatch.setattr(inbox, "LIMITS", limits())
    sent, answer = [], {"status": 200}

    class Notify(BaseHTTPRequestHandler):
        def do_POST(self):
            sent.append((self.path, json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(answer["status"])
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Notify)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("WOLTSPACE_API", f"http://127.0.0.1:{server.server_address[1]}")
    yield type("Lodge", (), {"root": tmp_path, "store": inbox.Store(tmp_path, limits()), "sent": sent,
                             "answer": answer, "server": server})
    server.shutdown()


def test_queued_human_mail_gets_one_body_free_notice_on_the_default_channel(lodge):
    lodge.store.admit("connector:telegram", "telegram:1", "pal", BODY, human=True)
    inbox_notice.owner_notice(lodge.root, "pal", "not_startable")
    [(path, body)] = lodge.sent
    # The lodge's endpoint never runs here: WOLTSPACE_API is this file's loopback stand-in.
    assert (path, body["session"]) == (inbox_notice.NOTIFY, "")
    assert body["message"] == ("🪵 your mail for pal is waiting, but pal can't wake now: "
                               "it can't be started automatically")
    assert set(body) == {"session", "message"} and BODY not in json.dumps(body)


def test_agent_mail_alone_tells_the_owner_nothing(lodge):
    wolt(lodge.root, "nunu")
    lodge.store.send(reader(lodge.store, "s1", "nunu"), "pal", "k1", BODY)
    inbox_notice.owner_notice(lodge.root, "pal", "stopped")
    assert lodge.sent == []


@pytest.mark.parametrize("failure", ["error", "down"])
def test_a_notice_that_cannot_be_sent_never_raises(lodge, failure):
    lodge.store.admit("connector:telegram", "telegram:1", "pal", BODY, human=True)
    if failure == "error":
        lodge.answer["status"] = 503
    else:
        lodge.server.shutdown()
        lodge.server.server_close()
    inbox_notice.owner_notice(lodge.root, "pal", "no_progress")
    assert len(lodge.sent) == (1 if failure == "error" else 0)


def test_each_human_message_to_a_wolt_that_cannot_wake_gets_its_own_notice(lodge):
    lodge.store.admit("connector:telegram", "telegram:1", "pal", BODY, human=True)
    lodge.store.set_wake("pal", {"inhibited": "no_progress"})  # held even for human mail, older than it
    for n in (1, 2):
        if n == 2:
            lodge.store.admit("connector:telegram", "telegram:2", "pal", BODY, human=True)
        inbox_wake._wake(str(lodge.root), "pal")  # the wake each admission schedules
        assert len(lodge.sent) == n
    assert all(body["message"].endswith("its last wake didn't pick the mail up") for _, body in lodge.sent)
