"""`woltspace session send` with the lodge inbox on: mail for the target's wolt,
never a paste. The real CLI against the inbox routes on loopback, and the lodge's
paste routes on the real app. Dummy roots, the wake recorded at its port."""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from inbox_support import limits, lose_confirmation, reader, rows, wolt

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import inbox  # noqa: E402
import inbox_wake  # noqa: E402
import server.app as server_app  # noqa: E402
from server import inbox_routes  # noqa: E402


def enable(root):
    (Path(root) / "woltspace.json").write_text(json.dumps({"inbox": {"enabled": True}}))


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    """The inbox routes on loopback; any other path is recorded, never served."""
    monkeypatch.setattr(inbox_routes, "WOLTS_DIR", tmp_path)
    enable(tmp_path)
    wolt(tmp_path, "nunu")
    woken, strays = [], []
    monkeypatch.setattr(inbox_wake, "notify_admitted", lambda root, status: woken.append(status))
    app = FastAPI()
    app.include_router(inbox_routes.router)

    @app.api_route("/{path:path}", methods=["GET", "POST"])
    async def stray(path: str, request: Request):
        strays.append(path)
        return {"ok": True, "status": "delivered", "session": path}

    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline and thread.is_alive()
        time.sleep(0.02)
    store = inbox.Store(tmp_path, limits())
    yield {"api": f"http://127.0.0.1:{srv.servers[0].sockets[0].getsockname()[1]}", "root": tmp_path,
           "token": reader(store, "pal-a-b-a1b2c3"), "woken": woken, "strays": strays}
    srv.should_exit = True
    thread.join(5)


def cli(lodge, *args, text="hello nunu"):
    env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("TMPDIR", "/tmp"),
           "WOLTSPACE_API": lodge["api"], "WOLTSPACE_INBOX_TOKEN": lodge["token"],
           "WOLTSPACE_WOLT_NAME": "pal", "WOLTSPACE_WOLT_SESSION": "pal-a-b-a1b2c3"}
    return subprocess.run([sys.executable, str(ROOT / "container" / "bin" / "woltspace"), *args],
                          input=text, env=env, capture_output=True, text=True, timeout=30)


def send(lodge, target):
    return cli(lodge, "session", "send", target)


def mail(root):
    return rows(root, "SELECT m.seq, b.wolt, m.priority, m.sender_name, m.body FROM inbox_messages m"
                      " JOIN inbox_mailboxes b ON b.id = m.mailbox ORDER BY m.seq")


def test_a_wolt_with_no_session_gets_mail_and_its_wake(lodge):
    done = send(lodge, "nunu")
    [(seq, to, priority, sender, body)] = mail(lodge["root"])
    assert (done.returncode, done.stdout) == (0, f"queued → nunu (seq {seq})\n")
    assert (to, priority, sender) == ("nunu", inbox.AGENT, "pal")
    assert body.decode().startswith("[message from pal, session=pal-a-b-a1b2c3]\nhello nunu\n")
    assert "woltspace session send pal-a-b-a1b2c3 <<'WOLTSPACE_IWCL_" in body.decode()
    [status] = lodge["woken"]
    assert (status.seq, status.to, status.priority, status.state) == (seq, "nunu", inbox.AGENT, "queued")
    assert lodge["strays"] == []


def test_a_session_target_is_mail_for_its_wolt(lodge):
    assert send(lodge, "nunu-gritty-log-840ad8").returncode == 0
    assert [r[1] for r in mail(lodge["root"])] == ["nunu"]
    assert lodge["strays"] == []


def test_a_refusal_is_not_queued_and_falls_back_to_nothing(lodge):
    done = send(lodge, "ghost")
    assert (done.returncode, done.stderr) == (1, "not queued (no_mailbox)\n")
    assert mail(lodge["root"]) == [] and lodge["woken"] == [] and lodge["strays"] == []


def test_an_unknown_outcome_names_its_key_and_is_never_resent(lodge, monkeypatch):
    lose_confirmation(monkeypatch, 1)  # the send commits; its caller sees store_failed
    done = send(lodge, "nunu")
    key = done.stderr.split("check key ")[1].split()[0]
    assert done.returncode == 1 and done.stderr.startswith("not queued (store_failed); check key iwcl-")
    assert f"`woltspace inbox status --key {key}`" in done.stderr
    assert len(mail(lodge["root"])) == 1 and lodge["strays"] == []
    assert json.loads(cli(lodge, "inbox", "status", "--key", key).stdout)["state"] == "queued"


@pytest.fixture
def paste(tmp_path, monkeypatch):
    """The real app's paste routes, delivery recorded; a live session for pal."""
    monkeypatch.setattr(server_app, "WOLTS_DIR", tmp_path)
    pasted = []
    monkeypatch.setattr(server_app, "deliver_message",
                        lambda name, text, **kw: pasted.append(name) or {"status": "delivered", "session": name})
    monkeypatch.setattr(server_app, "resolve_active_session", lambda wolt, registry=None: "pal-a-b-a1b2c3")
    monkeypatch.setattr(server_app, "_touch_origin", lambda sender: None)
    return TestClient(server_app.app, base_url="http://localhost:7777"), tmp_path, pasted


@pytest.mark.parametrize("path", ["/sessions/pal-a-b-a1b2c3/message", "/wolts/pal/message"])
@pytest.mark.parametrize("on", [True, False])
def test_the_paste_routes_refuse_while_the_inbox_is_on(paste, path, on):
    client, root, pasted = paste
    if on:
        enable(root)
    answer = client.post(path, json={"text": "hi", "from_wolt": "nunu"})
    if on:
        assert (answer.status_code, answer.json()["status"]) == (409, "inbox")
        assert "start a new session" in answer.json()["error"] and pasted == []
    else:
        assert (answer.status_code, answer.json()["status"]) == (200, "delivered")
        assert pasted == ["pal-a-b-a1b2c3"]
