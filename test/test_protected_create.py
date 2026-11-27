"""Stage 3a protected create: real broker sockets and registry; only the admin uid is mocked to this test's uid."""
import asyncio
import json
import os
import runpy
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

import protected_create
import wolts
from woltspace import dummy_broker as broker

RID, OTHER = "a" * 32, "b" * 32
TERMS = {"name": "wolt-a", "type": "beaver", "harness": "", "model": "", "display": "Wolt A", "policy": "", "role": "",
         "description": ""}
CLI = Path(__file__).parent.parent / "container" / "bin" / "create-creature-wolt"


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())
    with tempfile.TemporaryDirectory(prefix="pc-") as run:  # a short Unix socket path
        store = tmp_path / "policy"
        store.mkdir(mode=0o700)
        b = broker.Broker(store)
        monkeypatch.setattr(broker, "SOCKET", Path(run) / "admin.sock")
        servers = [broker.listen(broker.SOCKET), broker.listen(broker.SOCKET.with_name(broker.CREATE), 0o666)]
        for server, route in zip(servers, ("admin", "create")):
            threading.Thread(target=broker.serve, args=(b, server, route), daemon=True).start()
        (tmp_path / "wolts").mkdir()
        yield SimpleNamespace(broker=b, store=store, wolts=tmp_path / "wolts")
        for server in servers:
            server.close()


def ordinary(**request):
    return broker.call(request, broker.SOCKET.with_name(broker.CREATE))


def owner(**request):
    return broker.call(request)


def request_and_approve(rid=RID, **terms):
    code = ordinary(op="create-request", request=rid, terms={**TERMS, **terms})["code"]
    fingerprint = owner(op="review", code=code)["fingerprint"]
    return owner(op="approve", code=code, terms=fingerprint)


def audit(store):
    with sqlite3.connect(store / "registry.db") as db:
        return db.execute("SELECT caller, op, principal, action, result FROM audit").fetchall()


def test_only_the_host_owner_approves_the_exact_reviewed_terms(lodge, monkeypatch, capsys):
    first = ordinary(op="create-request", request=RID, terms=TERMS)
    assert first["result"] == "ok" and first["status"] == "pending" and "id" not in first
    assert ordinary(op="create-request", request=RID, terms=TERMS) == first  # a replay is the same reservation
    assert ordinary(op="create-request", request=RID, terms={**TERMS, "model": "other"}) == {"result": "conflict"}
    held = ordinary(op="create-request", request=OTHER, terms={**TERMS, "name": "wolt-h"})
    assert ordinary(op="create-request", request=OTHER, terms=TERMS) == {"result": "conflict"}
    assert ordinary(op="create-request", request="c" * 32, terms=TERMS) == {"result": "name-held"}
    assert owner(op="reject", code=held["code"])["status"] == "rejected"  # frees wolt-h, refuses the request
    late = ordinary(op="create-request", request="d" * 32, terms={**TERMS, "name": "wolt-h"})
    assert late["status"] == "pending" and owner(op="enroll", wolt="wolt-h")["result"] == "ok"  # direct owner enroll
    review = owner(op="review", code=late["code"])
    assert owner(op="approve", code=late["code"], terms=review["fingerprint"]) == {"result": "name-held"}
    for bad in ({**TERMS, "extra": ""}, {**TERMS, "name": "../x"}, {**TERMS, "role": "x\n"}, "wolt-a"):
        assert ordinary(op="create-request", request="e" * 32, terms=bad) == {"result": "invalid"}
    code = first["code"]
    assert ordinary(op="approve", code=code, terms="0" * 12) == {"result": "denied"}  # the create socket never approves
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid() + 1)
    assert owner(op="approve", code=code, terms="0" * 12) == {"result": "denied"}  # nor any other uid on the admin one
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())
    assert ordinary(op="create-status", request=RID)["status"] == "pending"
    assert broker.admin(["review", code]) == 0  # the real host client
    review = json.loads(capsys.readouterr().out)
    assert review["terms"] == TERMS and review["status"] == "pending"
    assert owner(op="approve", code=code, terms="0" * 12) == {"result": "terms-changed"}
    assert broker.admin(["approve", code, review["fingerprint"]]) == 0
    approved = json.loads(capsys.readouterr().out)
    assert broker.PRINCIPAL.fullmatch(approved["id"]) and approved["status"] == "approved"
    assert owner(op="approve", code=code, terms=review["fingerprint"]) == approved  # one durable ID
    assert ordinary(op="create-status", request=RID) == approved
    assert owner(op="enroll", wolt="wolt-a")["id"] == approved["id"]
    assert owner(op="run", wolt="wolt-a", action=broker.ACTION) == {"result": "not-granted"}
    rows = audit(lodge.store)
    assert ("host-admin", "approve", approved["id"], "other", "ok") in rows
    assert ("worker", "other", None, "other", "denied") in rows
    assert "wolt-a" not in str(rows) and RID not in str(rows) and code not in str(rows)  # ids only


def test_partial_scaffold_waits_for_the_owner_and_a_failed_launch_keeps_its_principal(lodge):
    calls = []

    def scaffold(name, fail=False):
        def run(linkage):
            calls.append("scaffold")
            (lodge.wolts / name / ".state").mkdir(parents=True)
            (lodge.wolts / name / protected_create.MARKER).write_text(linkage)
            if fail:
                raise OSError("interrupted scaffold")
        return run

    def launch(fail=False):
        calls.append("launch")
        if fail:
            raise RuntimeError("engine did not start")
        return {"name": "wolt-a-session"}

    def create(rid=RID, terms=TERMS, scaffold_fail=False, launch_fail=False):
        return protected_create.create(rid, terms, lodge.wolts, scaffold(terms["name"], scaffold_fail),
                                       lambda: launch(launch_fail))

    assert create()["status"] == "pending" and calls == [] and not any(lodge.wolts.iterdir())  # unapproved
    pid = request_and_approve()["id"]
    with pytest.raises(OSError):
        create(scaffold_fail=True)
    partial = (lodge.wolts / "wolt-a" / protected_create.MARKER).read_text()
    assert create()["status"] == "ambiguous"  # even its own marker is not trusted linkage
    assert (lodge.wolts / "wolt-a" / protected_create.MARKER).read_text() == partial  # untouched
    code = ordinary(op="create-status", request=RID)["code"]
    assert owner(op="reconcile", code=code)["status"] == "approved"
    (lodge.wolts / "wolt-a").rename(lodge.wolts / "owner-checked")  # the owner's own resolution
    with pytest.raises(RuntimeError):
        create(launch_fail=True)
    assert ordinary(op="create-status", request=RID) | {"code": None} == {
        "result": "ok", "status": "launch-failed", "code": None, "id": pid}
    assert create() | {"code": None} == {"result": "ok", "status": "launched", "code": None, "id": pid,
                                          "session": {"name": "wolt-a-session"}}
    assert create()["status"] == "launched" and calls == ["scaffold", "scaffold", "launch", "launch"]
    # A folder this request did not start is ambiguous: reported and left for the owner.
    other = {**TERMS, "name": "wolt-b"}
    (lodge.wolts / "wolt-b" / ".state").mkdir(parents=True)
    (lodge.wolts / "wolt-b" / protected_create.MARKER).write_text(f"{OTHER} p-planted\n")
    code = request_and_approve(OTHER, name="wolt-b")["code"]
    for _ in range(2):
        assert create(OTHER, other)["status"] == "ambiguous" and calls[-1] == "launch"
    assert (lodge.wolts / "wolt-b" / protected_create.MARKER).read_text() == f"{OTHER} p-planted\n"
    assert ordinary(op="create-report", request=OTHER, stage="scaffolded") == {"result": "refused"}
    assert owner(op="reconcile", code=code)["status"] == "approved"
    (lodge.wolts / "wolt-b").rename(lodge.wolts / "owner-kept")
    assert create(OTHER, other)["status"] == "launched"


def test_concurrent_retries_launch_once_and_an_uncertain_launch_waits_for_the_owner(lodge):
    request_and_approve()
    entered, release, calls, first = threading.Event(), threading.Event(), [], []

    def scaffold(linkage):
        calls.append("scaffold")
        (lodge.wolts / "wolt-a").mkdir()

    def launch():
        calls.append("launch")
        entered.set()
        release.wait(5)
        return {"name": "session"}

    def create(rid=RID, terms=TERMS):  # the API and the CLI both enter here
        return protected_create.create(rid, terms, lodge.wolts, scaffold, launch)

    worker = threading.Thread(target=lambda: first.append(create()))
    worker.start()
    assert entered.wait(5)
    assert create()["status"] == "launching" and calls == ["scaffold", "launch"]  # no second launch
    release.set()
    worker.join(5)
    assert first[0]["status"] == "launched" and create()["status"] == "launched" and len(calls) == 2
    # A caller that died after claiming its first launch leaves it uncertain: nothing relaunches it silently.
    code = request_and_approve(OTHER, name="wolt-b")["code"]
    for stage in ("scaffolding", "scaffolded", "launching"):
        assert ordinary(op="create-report", request=OTHER, stage=stage)["result"] == "ok"
    other = {**TERMS, "name": "wolt-b"}
    assert create(OTHER, other)["status"] == "launching" and len(calls) == 2
    assert ordinary(op="create-report", request=OTHER, stage="launching") == {"result": "refused"}  # nor directly
    assert owner(op="reconcile", code=code)["status"] == "launch-failed"  # the owner decides
    assert create(OTHER, other)["status"] == "launched" and calls[-1] == "launch"


@pytest.mark.parametrize("failure", ["after-spawn", "refused"])
def test_only_a_definite_non_start_releases_the_first_launch(lodge, monkeypatch, failure):
    import sessions
    from session_runtime import RuntimeHandle

    monkeypatch.setenv("WOLTSPACE_ISOLATION", "external")
    (lodge.wolts / ".space").mkdir()
    (lodge.wolts / "woltspace.json").write_text(json.dumps({"inbox": {"enabled": True, "native_hints": True}}))
    monkeypatch.setattr(sessions, "WOLTS_DIR", lodge.wolts)
    spawned = []

    def spawn(name, cwd, command):  # the real start path up to tmux; the first spawn fails as asked
        spawned.append(name)
        if failure == "refused" and len(spawned) == 1:
            raise subprocess.CalledProcessError(1, ["tmux", "new-session"])
        return RuntimeHandle(woltspace_session_id=name, tmux_session_name=name, pane_id="%1")

    real_publish = sessions.publish_runtime

    def publish(*args, **kwargs):  # a first session already spawned, then its publication fails
        if failure == "after-spawn" and len(spawned) == 1:
            raise OSError("lodge.db is busy")
        return real_publish(*args, **kwargs)

    for attr, value in (("_tmux_spawn", spawn), ("publish_runtime", publish), ("_tmux_alive", lambda data: True),
                        ("_tmux_exists", lambda where: None), ("harness_install_problem", lambda *a, **k: None),
                        ("ensure_site", lambda wolt: None), ("get_tunnel_url", lambda: "")):
        monkeypatch.setattr(sessions, attr, value)
    native = SimpleNamespace(prepare=lambda root, name, harness, attempt: {
        "kind": harness, "addr": str(root / ".space" / name / attempt), "attempt": attempt}, retire=lambda locator: None)
    monkeypatch.setitem(sys.modules, "native_adapters", native)

    def create():
        return protected_create.create(RID, TERMS, lodge.wolts, lambda linkage: (lodge.wolts / "wolt-a" / "wolt").mkdir(
            parents=True) or (lodge.wolts / "wolt-a" / "wolt" / "wolt.json").write_text("{}"),
            lambda: sessions.start_session(wolt="wolt-a", prompt="hi"))

    code = request_and_approve()["code"]
    with pytest.raises((OSError, subprocess.CalledProcessError)):
        create()
    if failure == "after-spawn":  # a live first session may exist: never spawned again on its own
        assert create()["status"] == "launching" and len(spawned) == 1
        assert owner(op="reconcile", code=code)["status"] == "launch-failed"  # the owner checked and decided
    else:
        assert ordinary(op="create-status", request=RID)["status"] == "launch-failed"
    assert create()["status"] == "launched" and len(spawned) == 2


def test_a_retry_that_read_approved_never_touches_a_live_scaffold(lodge, monkeypatch):
    request_and_approve()
    read, scaffolding, finished, out = threading.Event(), threading.Event(), threading.Event(), {}
    real_call = protected_create._call

    def call(request):
        reply = real_call(request)
        if threading.current_thread().name == "late" and request["op"] == "create-request":
            read.set()  # the late retry has seen "approved" ...
            assert scaffolding.wait(5)  # ... and resumes only once the other one is inside its scaffold
        return reply

    def scaffold(linkage):
        (lodge.wolts / "wolt-a").mkdir()
        scaffolding.set()
        assert finished.wait(5)

    def late():
        out["late"] = protected_create.create(RID, TERMS, lodge.wolts, scaffold, dict)
        finished.set()

    monkeypatch.setattr(protected_create, "_call", call)
    thread = threading.Thread(target=late, name="late")
    thread.start()
    assert read.wait(5)
    first = protected_create.create(RID, TERMS, lodge.wolts, scaffold, dict)
    thread.join(5)
    assert out["late"]["status"] == "scaffolding" and first["status"] == "launched"


def test_a_folder_that_appears_after_the_check_is_never_written(tmp_path, monkeypatch):
    import wolt_archive

    monkeypatch.setattr(wolts, "WOLTS_DIR", tmp_path)

    def appears(name, wolts_dir=None):  # runs after the existence check, before the scaffold
        (tmp_path / name).mkdir()
        (tmp_path / name / "owner.txt").write_text("kept")
        return False

    monkeypatch.setattr(wolt_archive, "in_archive", appears)
    with pytest.raises(FileExistsError):
        wolts.create_creature_wolt("wolt-a", "beaver")
    assert [p.name for p in (tmp_path / "wolt-a").iterdir()] == ["owner.txt"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_lodge_page_and_tui_keep_one_request_id_and_read_both_session_shapes():
    test = Path(__file__).with_name("create-request.test.mjs")
    run = subprocess.run(["node", "--test", str(test)], capture_output=True, text=True, timeout=60)
    assert run.returncode == 0, run.stdout + run.stderr


def test_name_is_held_until_retirement_and_restore_keeps_the_approved_id(lodge):
    pid = request_and_approve()["id"]
    snapshot = (lodge.store / "registry.db").read_bytes()  # old media: approved, not yet scaffolded
    for stage in ("scaffolding", "scaffolded", "launching", "launched"):
        if stage != "launched":  # an unfinished create keeps its name: before scaffold and before first launch
            assert owner(op="rename", wolt="wolt-a", to="wolt-r") == {"result": "creating"}
        assert ordinary(op="create-report", request=RID, stage=stage)["status"] == stage
    assert owner(op="rename", wolt="wolt-a", to="wolt-r") == {"result": "ok"}
    assert owner(op="enroll", wolt="wolt-r")["id"] == pid  # rename keeps the stable ID
    assert ordinary(op="create-request", request=OTHER, terms={**TERMS, "name": "wolt-r"}) == {"result": "name-held"}
    assert owner(op="register", action=broker.ACTION) == {"result": "ok"}
    assert [owner(op=o, wolt="wolt-r", action=broker.ACTION)["result"] for o in ("grant", "run")] == ["ok"] * 2
    assert owner(op="retire", wolt="wolt-r") == {"result": "ok"}
    assert ordinary(op="create-status", request=RID)["status"] == "retired"
    again = request_and_approve(OTHER, name="wolt-r")
    assert again["result"] == "ok" and again["id"] != pid  # a recreated name is a new principal ...
    assert owner(op="run", wolt="wolt-r", action=broker.ACTION) == {"result": "not-granted"}  # ... with no grant
    (lodge.store / "registry.db").write_bytes(snapshot)
    restored = broker.Broker(lodge.store)
    status = restored.create("worker", {"op": "create-status", "request": RID})
    assert (status["status"], status["id"]) == ("approved", pid)
    assert restored.create("worker", {"op": "create-request", "request": OTHER, "terms": {
        **TERMS, "name": "wolt-r"}})["status"] == "pending"  # the old media never knew the recreate


def test_an_exact_stage_two_registry_migrates_once_and_keeps_its_rows(tmp_path):
    v1_store = tmp_path / "policy"
    v1_store.mkdir(mode=0o700)
    with sqlite3.connect(v1_store / "registry.db") as conn:
        conn.executescript(f"{broker.TABLES} PRAGMA user_version = 1;"
                           " INSERT INTO principals (id, name) VALUES ('p-" + "1" * 32 + "', 'wolt-a');")
    (v1_store / "registry.db").chmod(0o600)
    b = broker.Broker(v1_store)
    with sqlite3.connect(v1_store / "registry.db") as db:
        assert db.execute("PRAGMA user_version").fetchone() == (2,)
        assert db.execute("SELECT id, name FROM principals").fetchall() == [("p-" + "1" * 32, "wolt-a")]
    assert b.create("worker", {"op": "create-request", "request": RID, "terms": TERMS}) == {"result": "name-held"}
    broker.Broker(v1_store)  # an ordinary restart of the migrated file


def test_api_and_cli_submit_and_resume_only_through_the_approval(lodge, monkeypatch, capsys):
    import harnesses
    from server import app as app_module
    from runtime_context import RuntimeContext

    for module in (app_module, wolts):
        monkeypatch.setattr(module, "WOLTS_DIR", lodge.wolts)
    launched = []
    monkeypatch.setattr(app_module, "start_session",
                        lambda **kwargs: launched.append(kwargs) or {"name": f"{kwargs['wolt']}-session"})

    async def post(**body):
        transport = httpx.ASGITransport(app=app_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost:7777") as client:
            return await client.post("/sessions/new/create", json={"name": "wolt-a", "type": "beaver", **body})

    monkeypatch.setenv("WOLTSPACE_FEATURE_ISOLATION", "true")
    with pytest.raises(PermissionError):
        wolts.create_creature_wolt("wolt-z", "beaver")  # no direct scaffold while isolation is on
    assert asyncio.run(post()).status_code == 409  # no request ID: refused, nothing reserved
    assert asyncio.run(post(request_id=RID, workdir=str(lodge.wolts))).status_code == 400
    pending = asyncio.run(post(request_id=RID))
    assert pending.status_code == 202 and pending.json()["status"] == "pending" and not any(lodge.wolts.iterdir())
    assert pending.json()["detail"] == f"waiting for the host owner: woltspace secrets review {pending.json()['code']}"
    terms = owner(op="review", code=pending.json()["code"])["terms"]
    assert terms["harness"] == "claude" and terms["policy"]  # the effective engine and level are approved terms
    other_level = next(level for level in harnesses.levels(RuntimeContext.from_env().isolation)["claude"]
                       if level != terms["policy"])
    assert asyncio.run(post(request_id=RID, execution_policy=other_level)).json()["result"] == "conflict"
    monkeypatch.setattr(app_module, "get_default_harness", lambda: "codex")  # the lodge default moved on
    monkeypatch.setattr(app_module, "harness_install_problem", lambda *args, **kwargs: None)
    assert asyncio.run(post(request_id=RID)).json()["result"] == "conflict"
    monkeypatch.setattr(app_module, "get_default_harness", lambda: "claude")
    fingerprint = owner(op="review", code=pending.json()["code"])["fingerprint"]
    pid = owner(op="approve", code=pending.json()["code"], terms=fingerprint)["id"]
    done = asyncio.run(post(request_id=RID))
    assert done.status_code == 200 and done.json()["session"] == {"name": "wolt-a-session"}
    assert [(k["harness"], k["execution_policy"]) for k in launched] == [(terms["harness"], terms["policy"])]
    assert (lodge.wolts / "wolt-a" / protected_create.MARKER).read_text() == f"{RID} {pid}\n"
    assert (lodge.wolts / "wolt-a" / "wolt" / "wolt.json").is_file()
    assert asyncio.run(post(request_id=RID)).json()["status"] == "launched"  # a replay starts nothing new

    def cli(*argv):
        monkeypatch.setattr(sys, "argv", [str(CLI), *argv])
        with pytest.raises(SystemExit) as exit_code:
            runpy.run_path(str(CLI), run_name="__main__")
        return exit_code.value.code, json.loads(capsys.readouterr().out)

    assert cli("wolt-c", "otter", "--request", OTHER)[1]["status"] == "pending"
    fingerprint = owner(op="review", code=ordinary(op="create-status", request=OTHER)["code"])["fingerprint"]
    owner(op="approve", code=ordinary(op="create-status", request=OTHER)["code"], terms=fingerprint)
    first = cli("wolt-c", "otter", "--request", OTHER)
    assert first[0] == 0 and first[1]["status"] == "scaffolded"  # the first launch stays separate
    assert cli("wolt-c", "otter", "--request", OTHER) == first and (lodge.wolts / "wolt-c" / "wolt").is_dir()
    assert cli("wolt-c", "otter", "--role", "x", "--request", OTHER) == (1, {"result": "conflict"})
    monkeypatch.delenv("WOLTSPACE_FEATURE_ISOLATION")  # flag off: the ordinary path, no broker and no marker
    assert asyncio.run(post(name="wolt-d")).status_code == 200
    assert not (lodge.wolts / "wolt-d" / protected_create.MARKER).exists()
