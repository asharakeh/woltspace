"""Trusted startup unit contracts; UID separation still requires the real Docker run."""
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from woltspace import broker_startup as boot
from woltspace import dummy_broker


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text("dummy\n")
    monkeypatch.setattr(boot, "CONFIG", path)
    monkeypatch.setattr(boot, "protected", lambda path: None)
    monkeypatch.setattr(boot, "SUDO_PATHS", [tmp_path / "sudo"])
    monkeypatch.setattr(boot.pwd, "getpwall", list)
    monkeypatch.setattr(boot.grp, "getgrall", list)
    monkeypatch.delenv("WOLTSPACE_DIR", raising=False)
    monkeypatch.setenv("HOST_UID", "1000")
    monkeypatch.setenv("HOST_GID", "1000")
    return path


def test_preflight_validates_fixed_admin_input(config):
    boot.preflight()
    config.unlink()
    with pytest.raises(ValueError):
        boot.preflight()


@pytest.mark.parametrize("key,value", [("HOST_UID", "0"), ("HOST_GID", "0"), ("HOST_UID", "990"),
    ("HOST_GID", "990"), ("HOST_UID", "bad"), ("WOLTSPACE_DIR", "/tmp/benign")])
def test_bad_host_identity_or_install_refused(config, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        boot.preflight()


@pytest.mark.parametrize("kind", ["uid", "gid", "sudo", "group", "config"])
def test_collision_privilege_and_bad_config_refused(config, monkeypatch, kind):
    if kind == "uid":
        monkeypatch.setattr(boot.pwd, "getpwall", lambda: [SimpleNamespace(pw_uid=990)])
    elif kind in {"gid", "group"}:
        group = SimpleNamespace(gr_gid=990 if kind == "gid" else 1000, gr_name="sudo", gr_mem=[])
        monkeypatch.setattr(boot.grp, "getgrall", lambda: [group])
    elif kind == "sudo":
        boot.SUDO_PATHS[0].touch()
    else:
        config.write_text("not the approved dummy config")
    with pytest.raises(ValueError):
        boot.preflight()


def test_real_trusted_path_and_untrusted_fixture(tmp_path):
    boot.protected(Path("/usr/bin/python3"))
    with pytest.raises(ValueError):
        boot.protected(tmp_path)


def test_actual_core_action_and_executable(tmp_path, capsys):
    store, policy = tmp_path / "dummy", tmp_path / "policy"
    store.write_text("synthetic-only")
    policy.mkdir(mode=0o700)
    assert dummy_broker.action(store) == {"result": "accepted"}
    short = Path(tempfile.mkdtemp(dir="/tmp", prefix="wsb."))  # AF_UNIX path limit; removed below
    child = subprocess.Popen([sys.executable, "-I", "-S", dummy_broker.__file__, str(store), str(policy),
                              str(short / "admin.sock")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin"}, close_fds=True)
    assert child.stdout is not None and child.stderr is not None
    try:
        assert select.select([child.stdout], [], [], 3)[0]
        assert json.loads(child.stdout.readline()) == {"result": "accepted"}
        assert dummy_broker.admin(["enroll", "wolt-a"], short / "admin.sock") == 1  # this caller is not uid 0
        assert capsys.readouterr().out == '{"result": "denied"}\n'
        assert sorted(p.name for p in policy.iterdir()) == ["registry.db"]
        assert oct(policy.joinpath("registry.db").stat().st_mode & 0o777) == "0o600"
    finally:
        child.terminate()
        child.wait(timeout=3)
        child.stdout.close()
        child.stderr.close()
        (short / "admin.sock").unlink(missing_ok=True)
        short.rmdir()
    old = tmp_path / "s1"
    old.mkdir(mode=0o700)
    (old / "policy.json").write_text("{}")  # an earlier layout is refused at startup, never adopted
    done = subprocess.run([sys.executable, "-I", "-S", dummy_broker.__file__, str(store), str(old),
                           str(tmp_path / "x.sock")], capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=10)
    assert (done.returncode, done.stdout, done.stderr) == (1, b"", b"")
    assert [p.name for p in old.iterdir()] == ["policy.json"]
    store.write_text("")
    with pytest.raises(ValueError):
        dummy_broker.action(store)


@pytest.mark.parametrize("mode", ["stop", "interrupt", "lost", "node-exit", "missing-ready", "bad-ready",
    "startup-stop", "early-loss", "ready-timeout", "kill", "cleanup-failure", "resume"])
def test_supervised_owned_children_and_cleanup(tmp_path, monkeypatch, mode):
    events, children, handlers = [], [], {}
    class Child:
        def __init__(self, role):
            self.role, self.returncode = role, None
            self.stdout = SimpleNamespace(fileno=lambda: 42, close=lambda: None) if role == "broker" else None
        def poll(self):
            return self.returncode
        def terminate(self):
            events.append((self.role, "term"))
        def kill(self):
            events.append((self.role, "kill"))
            self.returncode = -9
        def wait(self, timeout=0.0):
            assert 0 < timeout <= boot.DRAIN_SECONDS
            if self.role == "node" and (mode == "cleanup-failure" or (mode == "kill" and self.returncode is None)):
                raise subprocess.TimeoutExpired("dummy", timeout)
            events.append((self.role, "wait"))
            self.returncode = self.returncode or 0
            return self.returncode
    def spawn(argv, **kw):
        child = Child("broker" if not children else "node")
        children.append(child)
        if child.role == "broker":
            assert kw["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
            assert kw["close_fds"] and kw["cwd"] == "/"
            assert kw["user"] == kw["group"] == 990 and kw["extra_groups"] == []
            if mode == "early-loss":
                child.returncode = 7
        return child
    def tick(delay):
        if mode == "lost":
            children[0].returncode = 7
        elif mode == "node-exit":
            children[1].returncode = 9
        else:
            sig = signal.SIGINT if mode == "interrupt" else signal.SIGTERM
            handlers[sig](sig, None)
    monkeypatch.setattr(boot, "STORE", tmp_path / "private" / "store")
    monkeypatch.setattr(boot, "owned", lambda info: True, raising=False)  # UID separation is an image test
    if mode == "resume":
        boot.STORE.parent.mkdir(mode=0o700)
        boot.STORE.write_text("stale-dummy")
    monkeypatch.setattr(boot, "protected", lambda path: None)
    monkeypatch.setattr(dummy_broker, "SOCKET", tmp_path / "run" / "admin.sock")
    monkeypatch.setattr(boot, "prepare_policy", lambda: dummy_broker.SOCKET.parent.mkdir() or dummy_broker.SOCKET.touch())
    monkeypatch.setattr(boot.subprocess, "Popen", spawn)
    def handler(sig, fn):
        old = handlers.get(sig, signal.SIG_DFL)
        handlers[sig] = fn
        return old
    monkeypatch.setattr(boot.signal, "signal", handler)
    monkeypatch.setattr(boot.select, "select", lambda *args: (args[0], [], []))
    def read(*args):
        if mode == "startup-stop":
            handlers[signal.SIGTERM](signal.SIGTERM, None)
        return b"" if mode == "missing-ready" else (b"{}\n" if mode == "bad-ready" else b'{"result":"accepted"}\n')
    functions = {name: getattr(os, name) for name in ("open", "O_WRONLY", "O_CREAT", "O_EXCL", "O_NOFOLLOW", "fdopen", "fchmod")}
    monkeypatch.setattr(boot, "os", SimpleNamespace(**functions, read=read,
        chown=lambda *a: None, fchown=lambda *a: None))
    clock = iter([1, 7]) if mode == "ready-timeout" else iter([])
    monkeypatch.setattr(boot, "time", SimpleNamespace(monotonic=lambda: next(clock, 9 if mode == "ready-timeout" else 1), sleep=tick))
    if mode == "cleanup-failure":
        with pytest.raises(RuntimeError, match="cleanup failed"):
            boot.supervise(["dummy-node"])
    else:
        result = boot.supervise(["dummy-node"])
        assert result == (0 if mode in {"stop", "interrupt", "kill", "resume"} else 9 if mode == "node-exit" else 1)
    assert len(children) == (1 if mode in {"missing-ready", "bad-ready", "startup-stop", "early-loss", "ready-timeout"} else 2)
    assert all(child.returncode is not None for child in children)
    if len(children) == 2 and mode != "cleanup-failure":
        assert events.index(("node", "wait")) < events.index(("broker", "wait"))
    if mode == "cleanup-failure":
        assert ("node", "kill") in events and ("broker", "wait") in events
    assert not boot.STORE.parent.exists() and not dummy_broker.SOCKET.parent.exists()
    assert handlers == {signal.SIGTERM: signal.SIG_DFL, signal.SIGINT: signal.SIG_DFL}


@pytest.mark.parametrize("state", ["fresh", "empty", "stale", "mode", "owner", "extra", "dir-link", "file-link", "file-dir", "hardlink"])
def test_recreate_only_valid_stale_store(tmp_path, monkeypatch, state):
    assert boot.owned(SimpleNamespace(st_uid=0, st_gid=0))
    assert boot.owned(SimpleNamespace(st_uid=990, st_gid=990))
    assert not boot.owned(SimpleNamespace(st_uid=0, st_gid=990))
    store, target = tmp_path / "private" / "store", tmp_path / "sentinel"
    target.write_text("unchanged")
    monkeypatch.setattr(boot, "STORE", store)
    monkeypatch.setattr(boot, "protected", lambda path: None)
    monkeypatch.setattr(boot, "owned", lambda info: state != "owner")  # mock only root/service ownership
    monkeypatch.setattr(boot.os, "chown", lambda *args: None)
    monkeypatch.setattr(boot.os, "fchown", lambda *args: None)
    if state != "fresh":
        store.parent.mkdir(mode=0o700)
    if state == "stale":
        store.write_text("stale-dummy")
    elif state == "mode":
        store.parent.chmod(0o755)
    elif state == "extra":
        (store.parent / "unexpected").write_text("keep")
    elif state == "dir-link":
        store.parent.rmdir()
        store.parent.symlink_to(tmp_path, target_is_directory=True)
    elif state == "file-link":
        store.symlink_to(target)
    elif state == "file-dir":
        store.mkdir()
    elif state == "hardlink":
        os.link(target, store)
    if state in {"fresh", "empty", "stale"}:
        boot.fresh_store()
        assert store.read_text() != "stale-dummy" and len(store.read_text()) == 32
        assert store.stat().st_mode & 0o777 == 0o400
    else:
        with pytest.raises(ValueError):
            boot.fresh_store()
        assert target.read_text() == "unchanged"


def test_opted_node_loads_settings_before_early_setup(tmp_path, monkeypatch):
    from woltspace import cli
    from woltspace import container_entrypoint as entry
    (tmp_path / ".env").write_text("DEV_MODE=true\nWOLTSPACE_PUBLIC_TUNNEL=false\nDUMMY_NODE_MARKER=from-file\n")
    monkeypatch.setattr(os, "environ", {"PATH": "/usr/bin:/bin", "HOME": str(tmp_path),
        "WOLTSPACE_FEATURE_ISOLATION": "true", "WOLTSPACE_WOLTS_DIR": str(tmp_path), "CODEX_HOME": str(tmp_path / "codex")})
    monkeypatch.setattr(entry, "resolve_install_root", lambda *args: tmp_path / "bundle")
    monkeypatch.setattr(entry, "resolve_wolt_name", lambda *args: "")
    for name in ("scaffold_lodge", "derive_worktui_skill", "sync_claude_md_platform_section", "configure_git",
                 "write_trust_config", "write_settings_json"):
        monkeypatch.setattr(entry, name, lambda *args: None)
    seen = {}
    monkeypatch.setattr(entry, "open_tmux_window", lambda *a: seen.update(early=dict(os.environ)))
    monkeypatch.setattr(entry, "start_tunnel_report", lambda path, env: seen.update(tunnel=env))
    monkeypatch.setattr(cli, "serve", lambda **kw: seen.update(serve=kw) or 7)
    assert entry.run_node_phase() == 7
    assert seen["early"]["DEV_MODE"] == "true" and seen["early"]["DUMMY_NODE_MARKER"] == "from-file"
    assert seen["tunnel"]["WOLTSPACE_PUBLIC_TUNNEL"] == "false"
    assert {"DEV_MODE", "DUMMY_NODE_MARKER"} <= seen["serve"]["env_file_keys"]


def test_root_flag_on_and_flag_off_keep_distinct_owners(monkeypatch):
    from woltspace import container_entrypoint as entry
    events = []
    monkeypatch.setenv("HOME", os.environ["HOME"])  # root phase writes HOME; restore the private test home
    monkeypatch.setattr(entry.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(entry, "_root_tool", lambda name: "/root-bin/" + name)
    monkeypatch.setattr(entry.os, "execv", lambda *a: events.append("exec"))
    monkeypatch.setattr(boot, "preflight", lambda: events.append("validate"))
    monkeypatch.setattr(boot, "supervise", lambda argv: events.append(argv) or 7)
    monkeypatch.setenv("WOLTSPACE_FEATURE_ISOLATION", "false")
    entry.run_root_phase()
    assert events == ["exec"]
    events.clear()
    monkeypatch.setenv("WOLTSPACE_FEATURE_ISOLATION", "true")
    assert entry.run_root_phase() == 7
    assert events == ["validate", ["/root-bin/gosu", "node", "/usr/local/bin/woltspace", "container-entrypoint"]]



@pytest.mark.parametrize("state", ["ready", "fresh", "interrupted", "not-mount", "link", "mode", "owner", "run-mode"])
def test_policy_volume_must_be_a_private_mount(tmp_path, monkeypatch, state):
    volume, run, chowned = tmp_path / "volume", tmp_path / "run", []
    monkeypatch.setattr(dummy_broker, "POLICY_DIR", volume)
    monkeypatch.setattr(dummy_broker, "SOCKET", run / "admin.sock")
    monkeypatch.setattr(boot, "protected", lambda path: None)
    monkeypatch.setattr(boot.os.path, "ismount", lambda path: state != "not-mount")
    monkeypatch.setattr(boot.os, "chown", lambda path, uid, gid: chowned.append((Path(path), uid, gid)))
    real_chmod, steps = os.chmod, []
    monkeypatch.setattr(boot.os, "chmod", lambda path, mode: steps.append(("chmod", bool(chowned))) or real_chmod(path, mode))
    real_lstat = Path.lstat
    def lstat(self):  # mock only ownership: Docker's fresh mount is root's, a used one the service's
        ids = (0, 0) if state in {"fresh", "interrupted"} and self == volume and not chowned else (1234, 990) if state == "owner" else (990, 990)
        return SimpleNamespace(st_mode=real_lstat(self).st_mode, st_uid=ids[0], st_gid=ids[1])
    monkeypatch.setattr(Path, "lstat", lstat)
    if state == "link":
        (tmp_path / "elsewhere").mkdir(mode=0o700)
        volume.symlink_to(tmp_path / "elsewhere")
    else:
        volume.mkdir(mode=0o755 if state in {"mode", "fresh"} else 0o700)  # Docker's fresh mount is 0755
    if state == "run-mode":
        run.mkdir(mode=0o755)
    if state in {"ready", "fresh", "interrupted"}:  # interrupted: chmod done, chown not, so retry works
        boot.prepare_policy()
        assert [c[0] for c in chowned] == ([run] if state == "ready" else [volume, run]) and run.is_dir()
        assert steps == ([] if state == "ready" else [("chmod", False)])  # private before it changes owner
        assert volume.stat().st_mode & 0o777 == 0o700
        assert {c[1:] for c in chowned} == {(990, 990)}
    else:
        with pytest.raises(ValueError):
            boot.prepare_policy()
