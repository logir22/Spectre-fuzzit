"""OpenTelemetry integration (traces + metrics), fail-open.

When ``OTEL_ENABLED`` is unset (default), every helper is a cheap no-op, so
SPECTRE runs identically without an observability backend. When enabled, spans
and metrics are exported over OTLP/gRPC to a collector (Grafana/Loki stack).
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager
from typing import Any, Iterator, Optional

logger = logging.getLogger(__name__)

OTEL_ENABLED = os.environ.get("OTEL_ENABLED", "0") == "1"
OTEL_ENDPOINT = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

_tracer = None
_meter = None
_initialized = False


def _ensure() -> None:
    global _tracer, _meter, _initialized
    if _initialized:
        return
    _initialized = True
    if not OTEL_ENABLED:
        return
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource(attributes={"service.name": "spectre"})

        trace_provider = TracerProvider(resource=resource)
        trace_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_ENDPOINT))
        )
        trace.set_tracer_provider(trace_provider)

        reader = PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=OTEL_ENDPOINT))
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))

        _tracer = trace.get_tracer("spectre")
        _meter = metrics.get_meter("spectre")
        logger.info("OpenTelemetry enabled (endpoint=%s).", OTEL_ENDPOINT)
    except Exception as exc:  # noqa: BLE001 - fail-open
        logger.warning("OpenTelemetry init failed (disabled): %s", exc)
        _tracer = None
        _meter = None


@contextmanager
def span(name: str, **attrs: Any) -> Iterator[None]:
    """Wrap a block in an OTel span (no-op when telemetry is disabled)."""
    _ensure()
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as s:
        for k, v in attrs.items():
            s.set_attribute(str(k), v)
        yield


def counter(name: str, value: int = 1, **attrs: Any) -> None:
    """Increment a metric counter (no-op when disabled)."""
    _ensure()
    if _meter is None:
        return
    try:
        _meter.create_counter(name).add(value, attrs)
    except Exception:  # noqa: BLE001
        pass


def histogram(name: str, value: float, **attrs: Any) -> None:
    """Record a distribution value, e.g. latency (no-op when disabled)."""
    _ensure()
    if _meter is None:
        return
    try:
        _meter.create_histogram(name).record(value, attrs)
    except Exception:  # noqa: BLE001
        pass


def record_latency(name: str, seconds: float, **attrs: Any) -> None:
    histogram(name, seconds, **attrs)


def timed(name: str, **attrs: Any):
    """Decorator that records wall-clock latency of a function call."""

    def decorator(fn):
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return fn(*args, **kwargs)
            finally:
                record_latency(name, time.perf_counter() - start, **attrs)

        return wrapper

    return decorator


def otel_status() -> dict[str, Any]:
    return {"enabled": OTEL_ENABLED, "endpoint": OTEL_ENDPOINT}
