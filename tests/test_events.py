from agents.events import NEW_CRASH, EventBus


def test_publish_drain_in_memory():
    bus = EventBus(url=None)
    bus.publish(NEW_CRASH, {"sig": "abc"})
    bus.publish(NEW_CRASH, {"sig": "def"})
    events = bus.drain()
    assert len(events) == 2
    assert events[0]["event"] == NEW_CRASH
    assert events[0]["data"]["sig"] == "abc"
    assert bus.drain() == []


def test_drain_filter_by_type_preserves_others():
    bus = EventBus(url=None)
    bus.publish("other", {})
    bus.publish(NEW_CRASH, {"sig": "x"})
    events = bus.drain({NEW_CRASH})
    assert len(events) == 1
    assert events[0]["event"] == NEW_CRASH
    # the "other" event must remain queued
    remaining = bus.drain()
    assert len(remaining) == 1
    assert remaining[0]["event"] == "other"


def test_run_worker_bounded():
    bus = EventBus(url=None)
    bus.publish(NEW_CRASH, {"n": 1})
    bus.publish(NEW_CRASH, {"n": 2})
    seen = []
    count = bus.run_worker(seen.append, event_types={NEW_CRASH}, max_iterations=2)
    assert count == 2
    assert len(seen) == 2
