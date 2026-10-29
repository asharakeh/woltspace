"""The owner hears when mail of theirs waits for an agent that cannot wake
(inbox_notice.py, and the waker that calls it): a real store, a real HTTP
/notify on loopback that records what it is sent."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from inbox_support import limits, reader, rows, wolt

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


@pytest.fixture
def agents(lodge, monkeypatch):
    """nunu, a running agent, has mail queued for pal; the senders' wakes are recorded."""
    wolt(lodge.root, "nunu")
    lodge.nunu = reader(lodge.store, "s1", "nunu")
    lodge.store.send(lodge.nunu, "pal", "k1", BODY)
    lodge.woken = []
    monkeypatch.setattr(inbox_wake, "notify_admitted", lambda root, status: lodge.woken.append(status))
    return lodge


def lodge_mail(lodge, to):
    """What the lodge itself queued for an agent: sender, priority, text."""
    return [(r[0], r[1], r[2].decode()) for r in rows(
        lodge.root, "SELECT m.sender, m.priority, m.body FROM inbox_messages m JOIN inbox_mailboxes b"
                    " ON b.id = m.mailbox WHERE b.wolt = ? AND m.sender = 'provider:lodge' ORDER BY m.seq", to)]


def test_each_agent_sender_gets_one_notice_per_message_and_reason_in_its_own_inbox(agents):
    original = rows(agents.root, "SELECT * FROM inbox_messages WHERE key = 'k1'")
    for reason in ("no_progress", "no_progress", "stopped"):  # a repeat wake, then a changed reason
        inbox_notice.notice(agents.root, "pal", reason, owner=False)
    assert lodge_mail(agents, "nunu") == [
        ("provider:lodge", inbox.AGENT, "[lodge] your message k1 to pal is queued, but pal can't wake now: "
                                        "its last wake didn't pick the mail up"),
        ("provider:lodge", inbox.AGENT, "[lodge] your message k1 to pal is queued, but pal can't wake now: "
                                        "one of its sessions was stopped, so it stays asleep until rearmed")]
    assert [s.to for s in agents.woken] == ["nunu", "nunu"] and agents.sent == []  # no owner notice asked
    assert rows(agents.root, "SELECT * FROM inbox_messages WHERE key = 'k1'") == original  # untouched


def test_a_recreated_sender_is_not_told_about_its_predecessor_s_mail(agents):
    agents.store.set_state("nunu", "closed")  # its mail to pal stays queued there; nunu is retired
    wolt(agents.root, "nunu")
    reader(agents.store, "s2", "nunu")  # a new nunu, a new mailbox
    inbox_notice.notice(agents.root, "pal", "no_progress", owner=False)
    assert lodge_mail(agents, "nunu") == [] and agents.woken == []


def test_the_owner_and_the_lodge_s_own_notices_are_never_told_to_an_agent(agents):
    agents.store.admit("connector:telegram", "telegram:1", "pal", BODY, human=True)
    inbox_notice.notice(agents.root, "pal", "no_progress", owner=True)
    assert len(agents.sent) == 1 and len(lodge_mail(agents, "nunu")) == 1  # owner by /notify, nunu by mail
    assert [m["key"] for m in agents.store.unnoticed_agent_mail("pal", "stopped")] == ["k1"]  # not the owner's
    assert agents.store.unnoticed_agent_mail("nunu", "no_progress") == []  # nor the lodge's own notice
    inbox_notice.notice(agents.root, "nunu", "no_progress", owner=False)  # nunu stuck with the notice queued
    assert lodge_mail(agents, "pal") == [] and len(agents.woken) == 1
