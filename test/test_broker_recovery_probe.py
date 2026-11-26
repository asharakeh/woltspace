"""Disposable crash probe for the installed dummy broker and its dedicated volume."""
import json
import os
import socket
import sys
from pathlib import Path
from unittest.mock import patch

from woltspace import dummy_broker as broker
from woltspace.channels import plan_connectors
from woltspace.cli import main
from woltspace.layout import RuntimeLayout, resolve_install_root

CONNECTOR = Path(".space/connectors/legacy/connector.json")
CONFIG = Path(".space/legacy.json")
MARKER = Path(".space/marker.txt")


def fixture(root: Path) -> None:
    source = root / "old"
    manifest = source / CONNECTOR
    manifest.parent.mkdir(parents=True)
    manifest.write_text(json.dumps({
        "name": "legacy", "protocol": 1, "command": ["{python}", "inert.py"],
        "route": [["room", "[a-z]+"]],
    }))
    manifest.with_name("inert.py").write_text("raise SystemExit(97)\n")
    (source / CONFIG).write_text('{"channels":{"legacy":{"enabled":true}}}\n')
    (source / MARKER).write_text("retained dummy lodge data\n")


def quarantine(root: Path) -> None:
    restored = root / "restored" / "wolts"
    for path in (CONNECTOR, CONNECTOR.with_name("inert.py"), CONFIG, MARKER):
        assert (restored / path).read_bytes() == (root / "old" / path).read_bytes()
    assert not (restored / "policy.json").exists()
    assert not (restored / "action.key").exists()
    layout = RuntimeLayout(restored, resolve_install_root(os.getenv("WOLTSPACE_DIR")))
    env = {"WOLTSPACE_CONFIG": str(restored / CONFIG), "WOLTSPACE_ENTRYPOINT": "1"}

    def legacy_plan():
        plan, = (p for p in plan_connectors(layout, env) if p.name == "legacy")
        return plan

    assert legacy_plan().enabled
    # Explicit operator action before boot; retain the connector and lodge data.
    (restored / CONFIG).write_text('{"channels":{"legacy":{"enabled":false}}}\n')
    plan = legacy_plan()
    assert not plan.enabled and plan.detail == "disabled"


def test_backup_restore_and_quarantine(tmp_path):
    fixture(tmp_path)
    assert main(["backup", "--wolts-dir", str(tmp_path / "old"), "--out", str(tmp_path),
                 "--tag", "before-cutover"]) == 0
    archive = tmp_path / "woltspace-backup-before-cutover.tar.gz"
    assert main(["restore", str(archive), "--to", str(tmp_path / "restored")]) == 0
    quarantine(tmp_path)


def interrupt_grant(policy_dir: Path, service: int) -> None:
    request = {"op": "grant", "wolt": "wolt-a", "action": broker.ACTION}
    audit = policy_dir / "audit.log"
    previous_audit = audit.read_bytes()
    path = policy_dir / "policy.json"
    previous_policy = json.loads(path.read_bytes())
    assert previous_policy["grants"] == ["wolt-b"]

    server, client = socket.socketpair()
    with server, client:
        client.settimeout(5)
        pid = os.fork()
        if pid == 0:
            try:
                client.close()
                if os.getuid() == 0:
                    os.setgroups([])
                    os.setgid(service)
                    os.setuid(service)

                original_write = os.write

                def stop_before_audit(fd, data):
                    info, expected = os.fstat(fd), audit.stat()
                    if (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino):
                        assert json.loads(data) == {
                            "caller": "host-admin", "op": "grant",
                            "action": broker.ACTION, "result": "ok",
                        }
                        # Policy replace and fsync have returned; the audit syscall has not run.
                        os._exit(73)
                    return original_write(fd, data)

                with patch.object(os, "write", stop_before_audit):
                    broker.answer(server, policy_dir)
            finally:
                os._exit(74)

        server.close()
        try:
            client.sendall(json.dumps(request).encode() + b"\n")
            assert client.recv(256) == b""
        finally:
            _, status = os.waitpid(pid, 0)
        assert os.waitstatus_to_exitcode(status) == 73

    assert json.loads(path.read_bytes()) == {**previous_policy, "grants": ["wolt-a", "wolt-b"]}
    assert audit.read_bytes() == previous_audit


def test_single_durable_grant_without_audit_or_reply(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(broker, "ADMIN_UID", os.getuid())
    for request in (
        {"op": "enroll", "wolt": "wolt-a"},
        {"op": "enroll", "wolt": "wolt-b"},
        {"op": "register", "action": broker.ACTION},
        {"op": "grant", "wolt": "wolt-b", "action": broker.ACTION},
    ):
        assert broker.apply(tmp_path, request) == "ok"
    (tmp_path / "audit.log").touch(mode=0o600)
    interrupt_grant(tmp_path, os.getuid())


if __name__ == "__main__":
    operation, target = sys.argv[1:]
    path = Path(target)
    if operation == "crash":
        assert path == broker.POLICY_DIR and os.getuid() == 0
        assert (path.stat().st_uid, path.stat().st_gid) == (990, 990)
        interrupt_grant(path, 990)
    else:
        {"fixture": fixture, "quarantine": quarantine}[operation](path)
