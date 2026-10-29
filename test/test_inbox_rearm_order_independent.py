"""A rearm must clear an earlier stop, never a later stop in the same second."""
import inbox_wake
import sessions
from test_inbox_wake import lodge, wake, mail  # noqa: F401


def test_stop_after_rearm_in_same_second_still_inhibits(lodge, wake, monkeypatch):
    monkeypatch.setattr(inbox_wake.time, "time", lambda: 10000)
    monkeypatch.setattr(inbox_wake, "_schedule", lambda *a: None)
    mail(lodge)
    lodge.registry.create("pal-old", wolt="pal")
    token = lodge.store.grant("pal-old", "pal")
    got = lodge.store.fetch(token)
    lodge.store.ack(token, got.seq, got.claim)
    sessions.stop_session("pal-old")
    inbox_wake.rearm(lodge.root, "pal")
    lodge.registry.create("pal-new", wolt="pal")
    sessions.stop_session("pal-new")
    mail(lodge, "k2")
    inbox_wake._wake(str(lodge.root), "pal")
    assert wake.starts == [], "rearm incorrectly cleared a later explicit stop"
