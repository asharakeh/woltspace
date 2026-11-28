"""Synthetic api.telegram.org for the disposable fixture: TLS on 443, one ledger line per request it accepts."""
import hashlib
import json
import os
import re
import socket
import ssl
import threading
import time
from pathlib import Path

FIXTURE = Path("/fixture")
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/certs/provider.pem", "/certs/provider.key")
digest, chat = (FIXTURE / "expect").read_text().split()  # sha256 of the synthetic token, and the chat


def handle(conn):
    try:
        with context.wrap_socket(conn, server_side=True) as tls:
            tls.settimeout(10)
            stream = tls.makefile("rb")
            line = re.fullmatch(rb"POST /bot(([0-9]+):[^/ ]+)/sendMessage HTTP/1.1\r\n", stream.readline(512))
            headers = dict(h.decode().lower().split(":", 1) for h in iter(lambda: stream.readline(1024), b"\r\n"))
            body = json.loads(stream.read(int(headers["content-length"])))
            assert line and hashlib.sha256(line[1]).hexdigest() == digest, "unexpected token"
            assert body == {"chat_id": int(chat), "text": "Woltspace broker notice."}, "unexpected request"
            mode = (FIXTURE / "mode").read_text().strip()
            with (FIXTURE / "accepts").open("a") as ledger:
                ledger.write(mode + "\n")
                ledger.flush()
                os.fsync(ledger.fileno())
            if mode == "crash":
                time.sleep(3600)  # accepted, but the answer never reaches the broker
            reply = json.dumps({"ok": True, "result": {"message_id": 1, "from": {"id": int(line[2]), "is_bot": True},
                                                       "chat": {"id": int(chat) + (mode == "mismatch")}}}).encode()
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                        % len(reply) + reply)
    except Exception as exc:  # every refused or broken request is visible to the harness
        with (FIXTURE / "errors").open("a") as errors:
            errors.write(f"{type(exc).__name__} {exc}\n")


with socket.create_server(("0.0.0.0", 443)) as listener:
    while True:
        threading.Thread(target=handle, args=(listener.accept()[0],), daemon=True).start()
