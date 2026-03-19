"""OpenTelemetry tracing helpers (HTTP + Celery).

This module keeps OTel optional and safe-by-default.

Enable:
  - QC_OTEL_ENABLED=1

Export (recommended):
  - OTEL_TRACES_EXPORTER=otlp
  - OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4318
  - OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf

Notes:
- We propagate trace context into Celery headers via W3C TraceContext (traceparent/tracestate).
- Request correlation `request_id` is orthogonal; we still carry it for audit/logging.

"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

_otel_initialized = False


def otel_enabled() -> bool:
    if os.environ.get("OTEL_SDK_DISABLED", "").strip().lower() in {"1", "true", "yes"}:
        return False
    return os.environ.get("QC_OTEL_ENABLED", "0").strip() == "1"


def _service_name(default: str) -> str:
    return (
        os.environ.get("QC_OTEL_SERVICE_NAME")
        or os.environ.get("OTEL_SERVICE_NAME")
        or default
    )


def init_tracing(*, default_service_name: str) -> bool:
    """Initialize global tracer provider once per process."""
    global _otel_initialized
    if _otel_initialized:
        return True
    if not otel_enabled():
        return False

    traces_exporter = os.environ.get("OTEL_TRACES_EXPORTER", "otlp").strip().lower()
    if traces_exporter in {"none", "noop", "null"}:
        _otel_initialized = True
        return True

    # Lazy imports so non-OTel installs can still run (dev minimalism).
    from opentelemetry import trace  # type: ignore
    from opentelemetry.sdk.resources import Resource  # type: ignore
    from opentelemetry.sdk.trace import TracerProvider  # type: ignore
    from opentelemetry.sdk.trace.export import (  # type: ignore
        BatchSpanProcessor,
        SimpleSpanProcessor,
        ConsoleSpanExporter,
    )

    resource = Resource.create(
        {
            "service.name": _service_name(default_service_name),
        }
    )
    provider = TracerProvider(resource=resource)

    if traces_exporter == "console":
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf").strip().lower()
        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318").strip()

        if protocol in {"grpc", "grpc/protobuf"}:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=endpoint)
        else:
            # HTTP/protobuf exporter expects /v1/traces
            if not endpoint.endswith("/v1/traces"):
                endpoint = endpoint.rstrip("/") + "/v1/traces"
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=endpoint)

        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    _otel_initialized = True
    return True


def instrument_flask(app: Any) -> None:
    if not init_tracing(default_service_name="queencalifia-api"):
        return
    from opentelemetry.instrumentation.flask import FlaskInstrumentor  # type: ignore
    from opentelemetry.instrumentation.requests import RequestsInstrumentor  # type: ignore
    from opentelemetry.instrumentation.redis import RedisInstrumentor  # type: ignore

    FlaskInstrumentor().instrument_app(app)
    RequestsInstrumentor().instrument()
    RedisInstrumentor().instrument()


def instrument_celery() -> None:
    if not init_tracing(default_service_name="queencalifia-worker"):
        return
    from opentelemetry.instrumentation.celery import CeleryInstrumentor  # type: ignore
    from opentelemetry.instrumentation.redis import RedisInstrumentor  # type: ignore

    CeleryInstrumentor().instrument()
    RedisInstrumentor().instrument()


def inject(carrier: Dict[str, str]) -> None:
    if not otel_enabled():
        return
    from opentelemetry import propagate  # type: ignore
    propagate.inject(carrier)


def extract(carrier: Dict[str, str]) -> Any:
    if not otel_enabled():
        return None
    from opentelemetry import propagate  # type: ignore
    return propagate.extract(carrier)


def attach_extracted_context(carrier: Dict[str, str]):
    """Attach extracted context. Returns a detach token or None."""
    if not otel_enabled():
        return None
    from opentelemetry import context as otel_context  # type: ignore
    ctx = extract(carrier) or otel_context.get_current()
    return otel_context.attach(ctx)


def detach(token: Any) -> None:
    if not otel_enabled() or token is None:
        return
    from opentelemetry import context as otel_context  # type: ignore
    otel_context.detach(token)


def current_trace_ids() -> tuple[Optional[str], Optional[str]]:
    """Return (trace_id_hex, span_id_hex) for log enrichment."""
    if not otel_enabled():
        return None, None
    from opentelemetry import trace  # type: ignore

    span = trace.get_current_span()
    ctx = span.get_span_context() if span else None
    if not ctx or not ctx.is_valid:
        return None, None
    return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"


@contextmanager
def start_span(name: str, attributes: Optional[Dict[str, Any]] = None) -> Iterator[None]:
    """Start a span if tracing is enabled; otherwise no-op."""
    if not otel_enabled():
        yield
        return
    from opentelemetry import trace  # type: ignore
    tracer = trace.get_tracer("queencalifia")
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                try:
                    span.set_attribute(k, v)
                except Exception:
                    pass
        yield
