"""Offline test of host-side cleanup after an inventory failure."""
import json
import os
import signal
import subprocess
from types import SimpleNamespace

import pytest

import host


def test_cleanup_continues_after_inventory_failure(tmp_path, monkeypatch, capsys):
    root = tmp_path / "owned"
    root.mkdir()
    monkeypatch.setattr(host.tempfile, "mkdtemp", lambda **_: str(root))
    run = host.Run("image", tmp_path)
    run.names = {"first": "id1", "second": "id2", "foreign": None}
    containers = dict(run.names, foreign="id3")
    worker = subprocess.Popen(
        ["/bin/sleep", "30"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    run.workers.append(worker)

    def docker(*args, **_):
        if args[:2] == ("container", "inspect"):
            name = args[2]
            label = "other" if name == "foreign" else root.name
            return SimpleNamespace(returncode=0, stdout=json.dumps([{
                "Id": containers[name], "Config": {"Labels": {host.LABEL: label}},
            }]))
        if args[:2] == ("rm", "-f"):
            name = next(key for key, ident in containers.items() if ident == args[2])
            del containers[name]
            return None
        if args[:2] == ("container", "ls") and "--format" in args:
            return SimpleNamespace(stdout="\n".join(containers))
        return SimpleNamespace(stdout="")

    def inventory(ident):
        if ident == "id1":
            os.kill(os.getpid(), signal.SIGTERM)
            raise OSError("injected failure")

    monkeypatch.setattr(host, "docker", docker)
    monkeypatch.setattr(run, "inventory", inventory)
    try:
        with pytest.raises(RuntimeError, match="owned resource cleanup failed"):
            run.cleanup()
        assert containers == {"foreign": "id3"}
        assert worker.poll() is not None
        assert not root.exists()
        assert capsys.readouterr().out.strip() == (
            "FAIL cleanup errors=2 unknown=0 containers=1 networks=0 volumes=0 "
            "drivers=0 pids=0 roots=0"
        )
    finally:
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)
