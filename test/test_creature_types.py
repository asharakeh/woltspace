"""Custom creatures: a new name and emoji on one of the three sizes.

Covers the acceptance checks agreed for the feature: nothing changes for a
lodge without custom creatures, a custom creature behaves like its size but
keeps its own identity everywhere it is shown, model precedence, refused
writes leave the settings file intact, and an assignment applies from the
next session only.
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "container" / "lib"))

import creature_types  # noqa: E402
import harnesses  # noqa: E402
from creature_types import (  # noqa: E402
    add_custom, base_type, creature_emoji, custom_creatures, emoji_from, remove_custom,
)
from harnesses import creature_model, resolve_model, tier_default_model  # noqa: E402

STAR = {"emoji": "⭐", "size": "raccoon", "models": {"codex": "gpt-5.5"}, "role": "Reviewer"}


@pytest.fixture
def lodge(tmp_path, monkeypatch):
    monkeypatch.setenv("WOLTSPACE_WOLTS_DIR", str(tmp_path))
    (tmp_path / "woltspace.json").write_text(json.dumps({
        "harness": {"default": "claude"},
        "creatures": {"active_wolf": "howlie"},
    }))
    return tmp_path


def _wolt(root, name, **cfg):
    home = root / name / "wolt"
    home.mkdir(parents=True)
    (home / "wolt.json").write_text(json.dumps({"name": name, **cfg}, indent=2))
    return home / "wolt.json"


def _settings(root):
    return json.loads((root / "woltspace.json").read_text())


# --- no custom creatures: nothing changes ---------------------------------

def test_without_custom_creatures_built_ins_resolve_as_before(lodge):
    assert custom_creatures() == {}
    for t in ("raccoon", "beaver", "otter", "rodent", "wolf", "dog"):
        assert base_type(t) == t
    for harness in ("claude", "codex"):
        for tier in ("raccoon", "beaver", "otter", "wolf"):
            assert creature_model(harness, tier) == tier_default_model(harness, tier)


def test_built_in_emoji_stay_what_each_surface_always_said(lodge):
    add_custom("star", STAR)
    telegram = {"raccoon": "🦝", "beaver": "🦫", "otter": "🦦", "rodent": "🦫", "wolf": "🐺", "dog": "🐶"}
    for t, emoji in telegram.items():
        assert emoji_from(telegram, t, "🦫") == emoji
    assert emoji_from(telegram, "spider", "🦫") == "🦫"
    assert emoji_from(telegram, "star", "🦫") == "⭐"
    assert creature_emoji("raccoon") == "🦝"


def test_wolts_module_without_custom_creatures(lodge):
    from wolts import is_rodent, is_valid_type

    assert is_rodent("beaver") and is_rodent("rodent")
    assert not is_rodent("wolf") and not is_rodent("star")
    assert not is_valid_type("star")


# --- identity vs behaviour ------------------------------------------------

def test_custom_creature_behaves_like_its_size_and_keeps_its_identity(lodge):
    from wolts import is_rodent, is_valid_type

    add_custom("star", STAR)
    assert base_type("star") == "raccoon"
    assert creature_emoji("star") == "⭐"
    assert is_rodent("star") and is_valid_type("star")


def test_model_precedence_pin_then_creature_then_size(lodge):
    add_custom("star", STAR)
    # the creature's own model on codex
    assert resolve_model("codex", "star") == "gpt-5.5"
    # the wolt's own pin wins over it
    assert resolve_model("codex", "star", "gpt-5.6-sol") == "gpt-5.6-sol"
    # an engine the creature names no model for: its size's default
    assert resolve_model("claude", "star") == tier_default_model("claude", "raccoon")


def test_a_creature_model_the_engine_no_longer_offers_falls_back_to_the_size(lodge):
    settings = _settings(lodge)
    settings["creatures"]["custom"] = {"star": {"emoji": "⭐", "size": "raccoon", "models": {"codex": "gone"}}}
    (lodge / "woltspace.json").write_text(json.dumps(settings))
    assert creature_model("codex", "star") == tier_default_model("codex", "raccoon")


def test_a_hand_edited_bad_entry_is_ignored(lodge):
    settings = _settings(lodge)
    settings["creatures"]["custom"] = {"wolf": {"emoji": "⭐", "size": "raccoon"},
                                       "odd": {"emoji": "⭐", "size": "eagle"}}
    (lodge / "woltspace.json").write_text(json.dumps(settings))
    assert custom_creatures() == {}
    assert base_type("odd") == "odd"


# --- writes ---------------------------------------------------------------

@pytest.mark.parametrize("cid, entry", [
    ("Star", STAR),
    ("raccoon", STAR),
    ("wolf", STAR),
    ("star", {**STAR, "size": "wolf"}),
    ("star", {**STAR, "emoji": "x"}),
    ("star", {**STAR, "emoji": "⭐ ⭐"}),
    ("star", {**STAR, "models": {"codex": "not-a-model"}}),
    ("star", {**STAR, "models": {"nope": "gpt-5.5"}}),
    ("star", {**STAR, "lore": "new"}),
])
def test_invalid_creatures_are_refused_without_touching_settings(lodge, cid, entry):
    before = (lodge / "woltspace.json").read_bytes()
    with pytest.raises(ValueError):
        add_custom(cid, entry)
    assert (lodge / "woltspace.json").read_bytes() == before


def test_add_keeps_every_other_setting_and_refuses_overwrite(lodge):
    add_custom("star", STAR)
    settings = _settings(lodge)
    assert settings["creatures"]["active_wolf"] == "howlie"
    assert settings["harness"] == {"default": "claude"}
    assert settings["creatures"]["custom"]["star"]["size"] == "raccoon"
    with pytest.raises(ValueError, match="already exists"):
        add_custom("star", {**STAR, "emoji": "🌟"})
    assert custom_creatures()["star"]["emoji"] == "⭐"


def test_an_unreadable_settings_file_is_never_replaced(lodge):
    (lodge / "woltspace.json").write_text("{not json")
    with pytest.raises(ValueError, match="could not be read"):
        add_custom("star", STAR)
    assert (lodge / "woltspace.json").read_text() == "{not json"


def test_remove_refuses_a_creature_a_wolt_still_is(lodge):
    add_custom("star", STAR)
    _wolt(lodge, "nova", type="star")
    with pytest.raises(ValueError, match="nova"):
        remove_custom("star")
    assert "star" in custom_creatures()
    (lodge / "nova" / "wolt" / "wolt.json").write_text(json.dumps({"name": "nova", "type": "raccoon"}))
    remove_custom("star")
    assert "star" not in custom_creatures()
    assert _settings(lodge)["creatures"]["active_wolf"] == "howlie"


# --- creating a wolt of a custom creature ---------------------------------

def test_create_a_custom_creature_wolt_gets_a_site_its_role_and_base_lore(lodge):
    import wolts

    add_custom("star", STAR)
    with patch("wolts.WOLTS_DIR", lodge), patch("wolts.setup_wolt_claude_config"), \
            patch("wolts.subprocess.run"):
        wolts.create_creature_wolt("nova", "star")
    cfg = json.loads((lodge / "nova" / "wolt" / "wolt.json").read_text())
    assert cfg["type"] == "star" and cfg["role"] == "Reviewer"
    index = (lodge / "nova" / "wolt" / "site" / "index.html").read_text()
    assert "⭐" in index
    assert "raccoon-sized" in (lodge / "nova" / "CLAUDE.md").read_text()


# --- the lodge API --------------------------------------------------------

@pytest.fixture
def client(lodge, monkeypatch):
    from server import app as server_app

    monkeypatch.setattr(server_app, "WOLTS_DIR", lodge)
    monkeypatch.setattr(server_app, "get_default_harness", lambda: "claude")
    monkeypatch.setattr(harnesses, "_woltspace_json_path", lambda: lodge / "woltspace.json")
    return TestClient(server_app.app, base_url="http://localhost:7777")


def test_api_add_list_remove(client, lodge):
    r = client.post("/creatures", json={"id": "star", **STAR})
    assert r.status_code == 200, r.text
    listed = client.get("/creatures").json()
    assert [s["id"] for s in listed["sizes"]] == ["otter", "beaver", "raccoon"]
    assert listed["custom"][0]["id"] == "star" and listed["custom"][0]["wolts"] == []
    assert client.post("/creatures", json={"id": "star", **STAR}).status_code == 400
    assert client.delete("/creatures/star").status_code == 200
    assert client.get("/creatures").json()["custom"] == []


def test_assign_changes_only_the_type_and_reports_what_the_wolt_keeps(client, lodge):
    add_custom("star", STAR)
    path = _wolt(lodge, "nova", type="raccoon", role="Planner", harness="codex", model="gpt-6-astra")
    r = client.post("/wolts/nova/creature", json={"type": "star"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["emoji"] == "⭐" and body["previous_type"] == "raccoon"
    assert body["kept"] == {"harness": "codex", "model": "gpt-6-astra", "role": "Planner"}
    assert body["applies"] == "next session"
    cfg = json.loads(path.read_text())
    assert cfg == {"name": "nova", "type": "star", "role": "Planner",
                   "harness": "codex", "model": "gpt-6-astra"}


def test_assign_without_a_pin_uses_the_creatures_model(client, lodge):
    add_custom("star", STAR)
    _wolt(lodge, "nova", type="raccoon", harness="codex")
    body = client.post("/wolts/nova/creature", json={"type": "star"}).json()
    assert body["model"] == "gpt-5.5"


def test_assign_follows_a_starter_site_emoji_but_not_a_chosen_one(client, lodge):
    add_custom("star", STAR)
    _wolt(lodge, "nova", type="raccoon")
    _wolt(lodge, "kit", type="raccoon")
    for name, emoji in (("nova", "🦝"), ("kit", "🦊")):
        site = lodge / name / "wolt" / "site"
        site.mkdir()
        (site / "site.json").write_text(json.dumps({"title": name, "tokens": {"emoji": emoji}}))
    assert client.post("/wolts/nova/creature", json={"type": "star"}).json()["site_emoji_updated"]
    assert not client.post("/wolts/kit/creature", json={"type": "star"}).json()["site_emoji_updated"]
    assert json.loads((lodge / "nova/wolt/site/site.json").read_text())["tokens"]["emoji"] == "⭐"
    assert json.loads((lodge / "kit/wolt/site/site.json").read_text())["tokens"]["emoji"] == "🦊"


def test_assign_refuses_unknown_types_and_leaves_wolf_and_dog_alone(client, lodge):
    _wolt(lodge, "howlie", type="wolf")
    path = _wolt(lodge, "nova", type="raccoon")
    before = path.read_bytes()
    assert client.post("/wolts/nova/creature", json={"type": "dragon"}).status_code == 400
    assert client.post("/wolts/nova/creature", json={"type": "wolf"}).status_code == 400
    assert client.post("/wolts/howlie/creature", json={"type": "beaver"}).status_code == 400
    assert path.read_bytes() == before


def test_wolts_list_shows_the_custom_emoji_and_base_type(client, lodge):
    add_custom("star", STAR)
    _wolt(lodge, "nova", type="star")
    _wolt(lodge, "uxwolt", type="raccoon")
    by_name = {w["name"]: w for w in client.get("/wolts").json()}
    assert (by_name["nova"]["emoji"], by_name["nova"]["base_type"]) == ("⭐", "raccoon")
    assert (by_name["uxwolt"]["emoji"], by_name["uxwolt"]["base_type"]) == ("🦝", "raccoon")


def test_lodge_create_route_accepts_a_custom_creature(client, lodge, monkeypatch):
    from server import app as server_app

    add_custom("star", STAR)
    made = {}
    monkeypatch.setattr(server_app, "harness_install_problem", lambda *a, **k: None)
    monkeypatch.setattr("wolts.create_creature_wolt", lambda name, t, **k: made.update(name=name, type=t))
    monkeypatch.setattr(server_app, "start_session", lambda **k: {"name": "nova-x"})
    r = client.post("/sessions/new/create", json={"name": "nova", "type": "star"})
    assert r.status_code == 200, r.text
    assert made == {"name": "nova", "type": "star"}
    assert client.post("/sessions/new/create", json={"name": "rex", "type": "dragon"}).status_code == 400


# --- next session only ----------------------------------------------------

def test_a_running_session_keeps_its_model_and_the_next_one_gets_the_change(
    lodge, monkeypatch, fake_runtime
):
    """The model is chosen once, at spawn, and stored on the session; resume
    builds its command from that record, not from wolt.json. So assigning a
    creature only changes what a new session gets."""
    import paths
    import sessions

    monkeypatch.setattr(sessions, "WOLTS_DIR", lodge)
    monkeypatch.setattr(paths, "WOLTS_DIR", lodge)
    monkeypatch.setenv("WOLTSPACE_ISOLATION", "host")
    add_custom("quick", {"emoji": "⚡", "size": "otter"})
    path = _wolt(lodge, "nova", type="raccoon", harness="claude")
    (lodge / "nova" / "wolt" / "site").mkdir()

    running = sessions.start_session(wolt="nova")
    sessions.prepare_session_command(running["name"], "spawn")  # stamps the conversation id
    raccoon_model = tier_default_model("claude", "raccoon")
    assert running["model"] == raccoon_model

    cfg = json.loads(path.read_text())
    cfg["type"] = "quick"
    path.write_text(json.dumps(cfg))

    resumed = sessions.prepare_session_command(running["name"], "resume")
    assert f"--model {raccoon_model}" in resumed
    following = sessions.start_session(wolt="nova")
    assert following["model"] == tier_default_model("claude", "otter") != raccoon_model
    assert following["creature"] == "quick"
