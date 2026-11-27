"""Credential-free stock app-server stdio turn against a fixed Responses stream."""
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import select
import sys
import time



ROOT = Path("/state")
WORKDIR = ROOT


class Endpoint(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        valid = (
            self.path == "/responses"
            and not self.headers.get("Authorization")
            and request.get("model") == "fixture"
            and request.get("stream") is True
            and any(
                piece.get("text") == self.server.prompt
                for item in request["input"] if item.get("role") == "user"
                for piece in item["content"]
            )
        )
        self.server.accepted.append(valid)
        if not valid:
            self.send_error(400, "fixture request mismatch")
            return
        if self.server.overlap:
            (ROOT / "arrived").touch()
            deadline = time.monotonic() + 30
            while not (ROOT / "release").is_file():
                if time.monotonic() >= deadline:
                    self.send_error(408, "fixture release deadline")
                    return
                time.sleep(.025)
        answer = self.server.answer
        item = {
            "id": f"msg_{answer}", "type": "message", "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": answer, "annotations": []}],
        }
        response = {
            "id": f"resp_{answer}", "object": "response", "status": "completed",
            "output": [item],
            "usage": {
                "input_tokens": 1, "output_tokens": 1, "total_tokens": 2,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        }
        events = [
            ("response.created", {"response": dict(response, status="in_progress", output=[])}),
            ("response.output_item.added", {"output_index": 0,
              "item": dict(item, status="in_progress", content=[])}),
            ("response.output_text.delta", {"output_index": 0, "content_index": 0,
              "item_id": item["id"], "delta": answer}),
            ("response.output_item.done", {"output_index": 0, "item": item}),
            ("response.completed", {"response": response}),
        ]
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        for sequence, (kind, fields) in enumerate(events):
            payload = {"type": kind, "sequence_number": sequence, **fields}
            self.wfile.write(f"event: {kind}\ndata: {json.dumps(payload)}\n\n".encode())


def _drive(child, server, lane, expected):
    def send(method, params, number=None):
        message = {"method": method, "params": params}
        if number is not None:
            message["id"] = number
        child.stdin.write(json.dumps(message).encode() + b"\n")
        child.stdin.flush()

    pending = b""
    deadline = time.monotonic() + 40

    def receive(phase):
        nonlocal pending
        while b"\n" not in pending:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([child.stdout], [], [], remaining)[0], f"{phase} timeout"
            chunk = os.read(child.stdout.fileno(), 65536)
            assert chunk, f"{phase} stdio closed"
            pending += chunk
        line, pending = pending.split(b"\n", 1)
        return json.loads(line)

    def result(number, phase):
        while True:
            event = receive(phase)
            if event.get("id") == number:
                assert "result" in event, f"{phase} RPC rejected"
                return event["result"]

    send("initialize", {"clientInfo": {"name": "fixture", "version": "1"}}, 1)
    result(1, "initialize")
    send("initialized", {})
    if expected:
        send("thread/resume", {"threadId": expected, "cwd": str(WORKDIR)}, 2)
        thread = result(2, "thread/resume")["thread"]["id"]
        assert thread == expected, "resume identity mismatch"
    else:
        send("thread/start", {"cwd": str(WORKDIR)}, 2)
        thread = result(2, "thread/start")["thread"]["id"]
    print("ready", flush=True)
    for command in sys.stdin:
        verb = command.strip()
        if verb == "exit":
            return thread
        assert verb in ("overlap", "reuse", "resume", "survive")
        server.prompt = f"Fixture prompt {lane} {verb}"
        server.answer = f"fixture-{lane}-{verb}"
        server.overlap = verb == "overlap"
        server.accepted.clear()
        deadline = time.monotonic() + 40
        turn_id = 3
        send("turn/start", {"threadId": thread, "input": [
            {"type": "text", "text": server.prompt}
        ]}, turn_id)
        turn = result(turn_id, "turn/start")["turn"]["id"]
        answers = []
        while True:
            event = receive("turn")
            params = event.get("params", {})
            if params.get("threadId") != thread or params.get("turnId", turn) != turn:
                continue
            if event.get("method") == "item/completed":
                item = params["item"]
                if item["type"] == "agentMessage":
                    answers.append(item["text"])
            if event.get("method") == "turn/completed":
                assert params["turn"]["id"] == turn, "completion turn mismatch"
                assert params["turn"]["status"] == "completed", "stock turn failed"
                assert answers == [server.answer], "fixed reply missing"
                assert server.accepted == [True], "expected one keyless request"
                (ROOT / "thread").write_text(thread + "\n")
                print("complete", flush=True)
                break
    raise AssertionError("driver closed without exit")
