"""Explicit operator stop must inhibit wake regardless of session origin."""
import inbox_wake
import sessions
from test_inbox_wake import lodge, wake, mail  # noqa: F401


def test_stopping_a_manual_session_does_not_allow_mail_to_restart_it(lodge, wake):
    lodge.registry.create("pal-manual", wolt="pal")
    sessions.stop_session("pal-manual")
    mail(lodge)
    inbox_wake._wake(str(lodge.root), "pal")
    assert wake.starts == [], "mail restarted after explicit stop of an unreserved manual session"
