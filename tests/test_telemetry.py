from agents import telemetry


def test_span_noop():
    with telemetry.span("test"):
        pass


def test_counter_histogram_noop():
    telemetry.counter("x", 1)
    telemetry.histogram("x", 1.0)


def test_record_latency_noop():
    telemetry.record_latency("x", 0.5)


def test_status_reports_disabled_by_default():
    assert telemetry.otel_status()["enabled"] is False
