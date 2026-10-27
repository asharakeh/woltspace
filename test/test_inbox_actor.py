"""inbox_actor: one delivery authority per store, a fake engine, and every way a call can end."""

import asyncio
import sqlite3

import pytest

from inbox_support import FakeEngine, failing, limits, lose_confirmation, rows, state, usage

import inbox
import inbox_actor
import lodge_db

Outcome = inbox.Outcome


class Clock:
    now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def lodge(tmp_path):
    """Build coordinators on one private store; each test stops its own."""

    async def make(engine=None, generation="g1", **over):
        engine = engine or FakeEngine(tmp_path / "ledger")
        coordinator = inbox_actor.Coordinator(
            inbox.Store(tmp_path, limits(**over)), engine, generation=generation,
            overdue_after=60, clock=Clock())
        await coordinator.start()
        return coordinator, engine

    return make


async def settle():
    for _ in range(5):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_admit_to_acceptance_through_the_library(tmp_path, lodge):
    seen = []
    coordinator, engine = await lodge()
    coordinator.observer = lambda status: seen.append((status.state, state(tmp_path, status.key)))
    receipt = coordinator.admit("k1", "pal", "c1", "hello")
    waiter = asyncio.create_task(coordinator.wait("k1", 5))
    attempt = await engine.wait_calls(1)
    assert (attempt.key, attempt.body, attempt.generation) == ("k1", "hello", "g1")
    engine.resolve(Outcome.ACCEPTED)
    done = await waiter
    assert (receipt.state, done.state, done.calls) == ("queued", "native_accepted", 1)
    assert seen == [("native_accepted", [("native_accepted", None, 1, 1)])]  # published after commit
    assert rows(tmp_path, "SELECT outcome FROM inbox_attempts") == [("accepted",)]
    assert usage(tmp_path)["pal"] == (0, 0, 1)
    assert [e.state for e in coordinator.events().events] == ["queued", "attempting", "native_accepted"]
    assert len(engine.effects()) == 1
    await coordinator.stop()


@pytest.mark.asyncio
async def test_one_coordinator_per_store_and_one_open_call_per_conversation(tmp_path, lodge):
    coordinator, engine = await lodge()
    with pytest.raises(inbox.InboxError, match="already"):
        await inbox_actor.Coordinator(coordinator.store, engine, generation="g2",
                                      overdue_after=60).start()
    coordinator.admit("a", "pal", "c1", "x")
    coordinator.admit("b", "pal", "c1", "y")
    await engine.wait_calls(1)
    await settle()
    assert len(engine.calls) == 1
    engine.resolve(Outcome.ACCEPTED)
    assert (await engine.wait_calls(2)).key == "b"
    await coordinator.stop()
    assert coordinator._actors == {} and engine.calls[-1][1].cancelled()  # joined, not just asked
    with pytest.raises(inbox.InboxError):
        await coordinator.start()  # once stopped, for good


@pytest.mark.asyncio
async def test_a_call_that_swallows_its_cancel_cannot_start_another(tmp_path, lodge):
    class Stubborn(FakeEngine):
        async def __call__(self, attempt):
            try:
                return await super().__call__(attempt)
            except asyncio.CancelledError:
                if len(self.calls) > 1:
                    raise
                return Outcome.NOT_ADMITTED  # the first cancel only

    coordinator, engine = await lodge(Stubborn(tmp_path / "ledger"))
    coordinator.admit("a", "pal", "c1", "x")
    await engine.wait_calls(1)
    await asyncio.wait_for(coordinator.stop(), 5)
    assert len(engine.calls) == 1 and state(tmp_path, "a")[0][:3] == ("queued", None, 1)


@pytest.mark.asyncio
async def test_no_transaction_is_open_while_the_engine_works(tmp_path, lodge):
    probes = []

    class Probing(FakeEngine):
        async def __call__(self, attempt):
            other = sqlite3.connect(lodge_db.path(tmp_path), timeout=0, isolation_level=None)
            other.execute("BEGIN IMMEDIATE")  # fails at once if anyone holds the write lock
            other.execute("INSERT INTO meta VALUES ('probe', '1')")
            other.execute("COMMIT")
            other.close()
            probes.append(lodge_db.in_write())
            return await super().__call__(attempt)

    coordinator, engine = await lodge(Probing(tmp_path / "ledger"))
    coordinator.admit("a", "pal", "c1", "x")
    await engine.wait_calls(1)
    assert probes == [False]
    assert rows(tmp_path, "SELECT value FROM meta WHERE key='probe'") == [("1",)]
    engine.resolve(Outcome.ACCEPTED)
    await coordinator.wait("a", 5)
    await coordinator.stop()


@pytest.mark.asyncio
async def test_a_caller_who_stops_waiting_leaves_the_call_and_the_mail_alone(tmp_path, lodge):
    coordinator, engine = await lodge(waiters=2)
    coordinator.admit("a", "pal", "c1", "x")
    await engine.wait_calls(1)
    with pytest.raises(TimeoutError):
        await coordinator.wait("a", 0.01)
    cancelled = asyncio.create_task(coordinator.wait("a", 5))
    full = [asyncio.create_task(coordinator.wait("a", 5)) for _ in range(2)]
    await settle()
    assert full[1].done() and full[1].exception().code == "waiters"
    cancelled.cancel()
    await settle()
    clock = coordinator.clock
    clock.now = 61
    assert coordinator.overdue("pal", "c1") and not coordinator.overdue("pal", "c2")
    assert not engine.calls[0][1].done() and state(tmp_path, "a")[0][0] == "attempting"
    engine.resolve(Outcome.ACCEPTED)
    assert (await full[0]).state == "native_accepted"
    assert coordinator._n_waiters == 0 and coordinator._waiters == {}
    assert not coordinator.overdue("pal", "c1")
    await coordinator.stop()


@pytest.mark.parametrize("results, expect, calls", [
    ([Outcome.NOT_ADMITTED] * 3, ("blocked", "calls_used"), 3),
    ([Outcome.NOT_ADMITTED, Outcome.ACCEPTED], ("native_accepted", None), 2),
    ([Outcome.DEFERRED], ("blocked", "defer_without_submission"), 1),
    ([Outcome.USER_STOP], ("blocked", "user_stop"), 1),
    ([RuntimeError("engine fell over")], ("uncertain", "unknown"), 1),
    (["delivered!"], ("uncertain", "unknown"), 1),
])
@pytest.mark.asyncio
async def test_only_a_definite_non_admission_is_retried_and_three_calls_at_most(
        tmp_path, lodge, results, expect, calls):
    coordinator, engine = await lodge()
    coordinator.admit("a", "pal", "c1", "x")
    coordinator.admit("b", "pal", "c1", "y")
    waiter = asyncio.create_task(coordinator.wait("a", 5))  # waits through every retry
    for n, result in enumerate(results, 1):
        await engine.wait_calls(n)
        engine.resolve(result)
    settled = await waiter
    await settle()
    assert ((settled.state, settled.reason), settled.calls, len(engine.calls)) == (
        expect, calls, calls + (expect[0] == "native_accepted"))
    for missing in ("withdraw", "resume", "retry", "override"):
        assert not hasattr(coordinator, missing)
    await coordinator.stop()


@pytest.mark.asyncio
async def test_held_heads_hold_their_conversation_while_others_move(tmp_path, lodge):
    coordinator, engine = await lodge(work=2)
    for key, conv in (("a1", "c1"), ("a2", "c1"), ("b1", "c2"), ("d1", "c3")):
        coordinator.admit(key, "pal", conv, key)
    await engine.wait_calls(2)
    await settle()
    assert [c[0].key for c in engine.calls] == ["a1", "b1"]  # c3 waits for a free actor
    engine.resolve(Outcome.USER_STOP, 1)
    assert (await engine.wait_calls(3)).key == "d1"
    engine.resolve(Outcome.UNKNOWN, 0)
    engine.resolve(Outcome.ACCEPTED, 2)
    await coordinator.wait("d1", 5)
    await settle()
    assert [c[0].key for c in engine.calls] == ["a1", "b1", "d1"]
    assert [state(tmp_path, k)[0][0] for k in ("a1", "a2", "b1", "d1")] == [
        "uncertain", "queued", "blocked", "native_accepted"]
    await coordinator.stop()


@pytest.mark.asyncio
async def test_an_effect_whose_outcome_cannot_commit_halts_and_is_never_replayed(tmp_path, lodge):
    coordinator, engine = await lodge()
    coordinator.admit("a", "pal", "c1", "x")
    coordinator.admit("d", "pal", "c2", "x")  # in flight elsewhere when the store fails
    coordinator.admit("e", "pal", "c2", "x")
    await engine.wait_calls(2)
    waiter = asyncio.create_task(coordinator.wait("a", 5))
    await settle()
    with failing(tmp_path, "inbox_events"):
        engine.resolve(Outcome.ACCEPTED, 0)
        await settle()
        assert isinstance(coordinator.halted, inbox.Unavailable)
    with pytest.raises(inbox_actor.Halted):
        await waiter
    engine.resolve(Outcome.ACCEPTED, 1)  # recorded, but e is not claimed
    await settle()
    assert state(tmp_path, "d")[0][0] == "native_accepted" and state(tmp_path, "e")[0][0] == "queued"
    assert len(engine.effects()) == 2
    assert state(tmp_path, "a") == [("attempting", None, 1, 0)]
    assert rows(tmp_path, "SELECT e.state FROM inbox_events e JOIN inbox_messages m USING (seq)"
                          " WHERE m.key='a'") == [("queued",), ("attempting",)]
    coordinator.admit("b", "pal", "c1", "y")
    coordinator.admit("c", "nunu", "c1", "z")  # another recipient waits too
    await settle()
    assert len(engine.calls) == 2
    with pytest.raises(inbox_actor.Halted):
        await coordinator.wait("c", 5)
    await coordinator.stop()

    successor, fresh = await lodge(generation="g2")
    await fresh.wait_calls(2)
    await settle()
    assert sorted(c[0].key for c in fresh.calls) == ["c", "e"] and len(engine.effects()) == 2
    assert state(tmp_path, "a") == [("uncertain", "interrupted", 1, 0)]
    assert state(tmp_path, "b")[0][0] == "queued"
    for index in (0, 1):
        fresh.resolve(Outcome.ACCEPTED, index)
    await successor.wait("c", 5)
    await successor.stop()


@pytest.mark.asyncio
async def test_a_lost_confirmation_after_commit_is_never_replayed(tmp_path, lodge, monkeypatch):
    coordinator, engine = await lodge()
    coordinator.admit("a", "pal", "c1", "x")
    await engine.wait_calls(1)
    lose_confirmation(monkeypatch, 1)  # the accepted outcome's write
    engine.resolve(Outcome.ACCEPTED)
    await settle()
    assert isinstance(coordinator.halted, inbox.Unavailable)
    monkeypatch.undo()
    await coordinator.stop()
    successor, fresh = await lodge(generation="g2")
    await settle()
    assert state(tmp_path, "a") == [("native_accepted", None, 1, 1)]
    assert fresh.calls == [] and len(engine.effects()) == 1
    await successor.stop()


@pytest.mark.asyncio
async def test_a_failed_claim_calls_nothing_and_a_failed_recovery_stays_halted(tmp_path, lodge):
    coordinator, engine = await lodge()
    with failing(tmp_path, "inbox_attempts"):
        coordinator.admit("a", "pal", "c1", "x")
        await settle()
    assert engine.calls == [] and isinstance(coordinator.halted, inbox.Unavailable)
    assert state(tmp_path, "a")[0][0] == "queued"
    await coordinator.stop()
    inbox.Store(tmp_path, limits()).claim("pal", "c1", "g1")  # a predecessor's open attempt
    successor = inbox_actor.Coordinator(inbox.Store(tmp_path, limits()), engine, generation="g2",
                                        overdue_after=60)
    with failing(tmp_path, "inbox_events"):
        with pytest.raises(inbox.Unavailable):
            await successor.start()
    successor.admit("b", "pal", "c2", "y")
    await settle()
    assert engine.calls == [] and isinstance(successor.halted, inbox.Unavailable)
    assert state(tmp_path, "a")[0][0] == "attempting"
    await successor.stop()


@pytest.mark.asyncio
async def test_a_failing_observer_cannot_undo_or_repeat_a_delivery(tmp_path, lodge):
    coordinator, engine = await lodge()

    def broken(status):
        raise RuntimeError("exporter down")

    coordinator.observer = broken
    coordinator.admit("a", "pal", "c1", "x")
    coordinator.admit("b", "pal", "c1", "y")
    await engine.wait_calls(1)
    engine.resolve(Outcome.ACCEPTED)
    assert (await coordinator.wait("a", 5)).state == "native_accepted"
    assert (await engine.wait_calls(2)).key == "b"  # the actor goes on
    await settle()
    assert len(engine.calls) == 2 and coordinator.halted is None
    await coordinator.stop()


@pytest.mark.asyncio
async def test_a_coordinator_needs_a_valid_generation_and_reads_through_the_store(tmp_path, monkeypatch):
    store = inbox.Store(tmp_path, limits())
    for bad in ("", "g" * 21, "\udcff"):
        with pytest.raises(inbox.Invalid):
            inbox_actor.Coordinator(store, FakeEngine(tmp_path / "l"), generation=bad, overdue_after=1)
    coordinator = inbox_actor.Coordinator(store, FakeEngine(tmp_path / "l"), generation="g", overdue_after=1)
    with pytest.raises(inbox.Unavailable):  # no store yet: unavailable, not missing
        await coordinator.wait("a", 1)
