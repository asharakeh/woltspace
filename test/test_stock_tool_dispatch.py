"""Row zero: does the pinned stock Codex app-server run an ordinary shell tool under the protected fence?

A loopback stub stands in for the model. Its first reply is a function call to the shell tool the engine
itself lists; its second reply ends the turn. The tool's output must come back in the engine's next request.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import hashlib
import json
import os
from pathlib import Path
import secrets
import select
import sys
import threading
import time

import pytest

FIXTURE = Path(__file__).parent / "ordinary-stock-fixture"
PINNED = "ad83b94c093f0cdd8176a6bc8005a461bdf23a759863e157d40f562b8a9d664d"  # codex 0.172.0 musl, as hosted.sh
CANDIDATES = [Path("/usr/local/lib/woltspace-stock-fixture"),
              Path("/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/"
                   "x86_64-unknown-linux-musl/bin")]


def stock():
    for directory in CANDIDATES:
        binary = directory / "codex"
        if binary.is_file() and hashlib.sha256(binary.read_bytes()).hexdigest() == PINNED:
            return directory
    return None


STOCK = stock()
pytestmark = pytest.mark.skipif(STOCK is None, reason="pinned stock codex 0.172.0 not present")


def sse(events):
    return b"".join(f"event: {kind}\ndata: {json.dumps({'type': kind, 'sequence_number': n, **fields})}\n\n".encode()
                    for n, (kind, fields) in enumerate(events))


def completed(response_id, output):
    response = {"id": response_id, "object": "response", "status": "completed", "output": output,
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                          "input_tokens_details": {"cached_tokens": 0},
                          "output_tokens_details": {"reasoning_tokens": 0}}}
    events = [("response.created", {"response": dict(response, status="in_progress", output=[])})]
    for index, item in enumerate(output):
        events += [("response.output_item.added", {"output_index": index, "item": item}),
                   ("response.output_item.done", {"output_index": index, "item": item})]
    return sse(events + [("response.completed", {"response": response})])


def shell_call(tools, nonce, command=None):
    """A function call for the engine's own shell tool, shaped by the schema it sent us."""
    if command:
        return "exec_command", {"cmd": command}
    for tool in tools:
        name = tool.get("name") or tool.get("type")
        properties = (tool.get("parameters") or {}).get("properties") or {}
        if "command" in properties:  # e.g. shell: command is an argv array
            argv = ["/bin/sh", "-c", f"echo {nonce} > tool-ran; echo {nonce}"]
            value = argv if properties["command"].get("type") == "array" else " ".join(argv[2:])
            return name, {"command": value}
        if "cmd" in properties:  # e.g. exec_command: one shell string
            return name, {"cmd": f"echo {nonce} > tool-ran; echo {nonce}"}
    return None, None


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(body)
        if len(self.server.requests) == 1:
            name, arguments = shell_call(body.get("tools") or [], self.server.nonce, self.server.command)
            self.server.tool = name
            output = ([{"id": "fc_1", "type": "function_call", "status": "completed", "call_id": "call_1",
                        "name": name, "arguments": json.dumps(arguments)}] if name else
                      [{"id": "msg_1", "type": "message", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "no shell tool", "annotations": []}]}])
        else:
            output = [{"id": "msg_2", "type": "message", "role": "assistant", "status": "completed",
                       "content": [{"type": "output_text", "text": "done", "annotations": []}]}]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(completed(f"resp_{len(self.server.requests)}", output))


def run_turn(tmp_path, sandbox, command=None, reads=(), writes=(), home=None):
    sys.path.insert(0, str(FIXTURE))
    import fence

    home = home or tmp_path / "home"
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = HTTPServer(("127.0.0.1", 0), Stub)
    server.requests, server.tool, server.nonce = [], None, "nonce-" + secrets.token_hex(8)
    server.command = command
    threading.Thread(target=server.serve_forever, daemon=True).start()
    (home / "config.toml").write_text(f"""
model = "fixture"
model_provider = "fixture"
check_for_update_on_startup = false
approval_policy = "never"
sandbox_mode = "{sandbox}"
[model_providers.fixture]
name = "Local fixture"
base_url = "http://127.0.0.1:{server.server_port}"
wire_api = "responses"
request_max_retries = 0
stream_max_retries = 0
[analytics]
enabled = false
""")
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for name in ("HOME", "CODEX_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME",
                 "XDG_RUNTIME_DIR", "TMPDIR"):
        env[name] = str(home)
    engine_in, engine_out = os.pipe(), os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.dup2(engine_in[0], 0)
            os.dup2(engine_out[1], 1)
            os.dup2(os.open("/dev/null", os.O_WRONLY), 2)
            os.chdir(home)
            os.closerange(3, os.sysconf("SC_OPEN_MAX"))
            fence.fence(home, server.server_port, (STOCK, *reads), writes)
            os.execve(str(STOCK / "codex"), [str(STOCK / "codex"), "app-server", "--listen", "stdio://"], env)
        finally:
            os._exit(127)
    os.close(engine_in[0])
    os.close(engine_out[1])
    events, pending, deadline = [], b"", time.monotonic() + 60

    def send(method, params, number=None):
        os.write(engine_in[1], json.dumps({"method": method, "params": params,
                                           **({"id": number} if number is not None else {})}).encode() + b"\n")

    def receive():
        nonlocal pending
        while b"\n" not in pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([engine_out[0]], [], [], remaining)[0], "engine timeout"
            chunk = os.read(engine_out[0], 65536)
            assert chunk, "engine closed stdio"
            pending += chunk
        line, pending = pending.split(b"\n", 1)
        event = json.loads(line)
        events.append(event)
        return event

    def result(number):
        while (event := receive()).get("id") != number:
            pass
        assert "result" in event, event
        return event["result"]

    try:
        send("initialize", {"clientInfo": {"name": "fixture", "version": "1"}}, 1)
        result(1)
        send("initialized", {})
        send("thread/start", {"cwd": str(home)}, 2)
        thread = result(2)["thread"]["id"]
        send("turn/start", {"threadId": thread, "input": [{"type": "text", "text": "Run the fixture tool."}]}, 3)
        result(3)
        while not ((event := receive()).get("method") == "turn/completed"):
            pass
    finally:
        os.close(engine_in[1])
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
        os.close(engine_out[0])
        server.shutdown()
        server.server_close()
    return server, events, home


# Our fence is the only tool sandbox: Codex's own read-only mode cannot build its bubblewrap layer under it.
@pytest.mark.parametrize("sandbox,runs", [("danger-full-access", True), ("read-only", False)])
def test_stock_engine_dispatches_its_shell_tool_under_the_fence(tmp_path, sandbox, runs, record_property):
    server, events, home = run_turn(tmp_path, sandbox)
    tools = [t.get("name") or t.get("type") for t in server.requests[0].get("tools") or []]
    returned = [item for request in server.requests[1:] for item in request.get("input") or []
                if isinstance(item, dict) and item.get("type") == "function_call_output"]
    status = [e["params"]["turn"]["status"] for e in events if e.get("method") == "turn/completed"]
    items = sorted({e["params"]["item"]["type"] for e in events if e.get("method") == "item/completed"})
    report = {"sandbox": sandbox, "tools": tools, "chosen": server.tool, "requests": len(server.requests),
              "returned": [str(item.get("output"))[:300] for item in returned], "turn": status, "items": items,
              "marker": (home / "tool-ran").read_text().strip() if (home / "tool-ran").exists() else None}
    print("ROW-ZERO " + json.dumps(report), flush=True)
    record_property("row_zero", json.dumps(report))
    assert server.tool == "exec_command" and len(server.requests) == 2 and status == ["completed"]
    assert len(returned) == 1  # the engine answered our one call, ran or refused
    assert (server.nonce in str(returned[0].get("output"))) == runs
    assert report["marker"] == (server.nonce if runs else None)  # written only in the worker's own directory


def test_stock_tool_runs_the_packaged_helper_only_through_its_own_launch(tmp_path, monkeypatch):
    """A's tool reaches A's pipes through its fence grant; B's tool, fenced without one, reaches neither."""
    from woltspace import protected_stock as supervisor
    from test_telegram_notice import HELLO, HELPER, Broker

    monkeypatch.setattr(supervisor.os, "chown", lambda *_: None)  # not root here: ownership is the image's
    (tmp_path / "a" / "home").mkdir(parents=True)
    action, pipes = supervisor.notice_endpoint(tmp_path / "a")
    broker, stopped = Broker(["ok"]), threading.Event()
    relay = threading.Thread(target=supervisor.relay_notices,
                             args=(*pipes, supervisor.Channel(broker.theirs, HELLO), stopped), daemon=True)
    relay.start()
    helper = f"/usr/bin/python3 -I {HELPER}"
    try:
        intruder = (f"HOME={tmp_path}/a/home {helper}; echo n > {action}/request; "
                    f"cat {action}/reply; ls {tmp_path}/a; echo done")
        server, _, _ = run_turn(tmp_path / "b", "danger-full-access", intruder, (HELPER,), (),
                                tmp_path / "b" / "home")
        output = str(server.requests[1]["input"][-1]["output"])
        assert "unavailable" in output and output.count("Permission denied") == 3 and broker.requests == []
        server, _, _ = run_turn(tmp_path / "a", "danger-full-access", helper,
                                (HELPER, action / "reply"), (action / "request",), tmp_path / "a" / "home")
        output = str(server.requests[1]["input"][-1]["output"])
        assert "Process exited with code 0" in output and "\nok\n" in output
        assert broker.requests == [{**HELLO, "action": "telegram.notice"}]
    finally:
        stopped.set()
        relay.join(5)
        supervisor.remove_endpoint(action, pipes)
