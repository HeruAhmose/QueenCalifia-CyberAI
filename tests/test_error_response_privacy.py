"""Secrets in upstream failures must not cross public response/log boundaries."""
from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from flask import Flask

SENTINEL = "privacy-test-credential-never-return"
FAILURE = f"https://internal.example/private?api_key={SENTINEL} /private/keys.json"


@pytest.fixture
def market_client(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "backend"))
    monkeypatch.setenv("QC_NO_AUTH", "1")
    monkeypatch.setenv("QC_PRODUCTION", "0")
    routes = importlib.import_module("modules.market.routes")
    app = Flask(__name__)
    app.config["settings"] = SimpleNamespace()
    app.register_blueprint(routes.market_bp, url_prefix="/api/market")
    return app.test_client(), routes


@pytest.mark.parametrize("path,method", [
    ("/snapshot?asset_type=crypto&symbol=BTC", "get_market_snapshot"),
    ("/fred/GDP", "fetch_fred"),
    ("/nasdaq/WIKI/TEST", "fetch_nasdaq"),
])
@pytest.mark.parametrize("error,status", [(ValueError, 400), (requests.ConnectionError, 502)])
def test_market_errors_are_safe(market_client, monkeypatch, path, method, error, status):
    client, routes = market_client
    monkeypatch.setattr(routes, method, Mock(side_effect=error(FAILURE)))
    response = client.get("/api/market" + path)
    assert response.status_code == status
    assert response.json["error"]
    assert SENTINEL not in response.get_data(as_text=True)
    assert "internal.example" not in response.get_data(as_text=True)


def test_nasdaq_does_not_echo_error_body_or_authenticated_url(market_client, monkeypatch):
    client, routes = market_client
    upstream = requests.Response()
    upstream.status_code = 403
    upstream._content = json.dumps({"error": FAILURE}).encode()
    monkeypatch.setattr(routes, "fetch_nasdaq", Mock(side_effect=requests.HTTPError(FAILURE, response=upstream)))
    response = client.get("/api/market/nasdaq/WIKI/TEST")
    assert response.status_code == 502
    assert response.json == {"error": "nasdaq_upstream_error", "upstream_status": 403}


@pytest.mark.parametrize("method,args,key", [
    ("ollama_health", (), "status"), ("vllm_health", (), "status"),
    ("ollama_models", (), "error"), ("ollama_pull", ("test-model",), "error"),
])
def test_identity_provider_failures_are_safe(monkeypatch, method, args, key):
    from backend.modules.identity import provider
    monkeypatch.setattr(provider.http, "get", Mock(side_effect=requests.ConnectionError(FAILURE)))
    monkeypatch.setattr(provider.http, "post", Mock(side_effect=requests.ConnectionError(FAILURE)))
    result = getattr(provider, method)(*args)
    assert result[key] == "provider_unavailable"
    assert SENTINEL not in json.dumps(result)


@pytest.mark.parametrize("error,status", [(PermissionError, 403), (RuntimeError, 500)])
def test_scanner_errors_are_safe(app_factory, monkeypatch, error, status):
    app = app_factory(require_api_key=False)
    from conftest import DummyLiveScanner
    monkeypatch.setattr(DummyLiveScanner, "scan", Mock(side_effect=error(FAILURE)))
    response = app.test_client().post("/api/v1/scanner/scan", json={
        "target": "127.0.0.1", "acknowledge_authorized": True,
    })
    assert response.status_code == status
    assert SENTINEL not in response.get_data(as_text=True)


def test_public_readiness_hides_redis_credentials_on_success_and_failure(app_factory, monkeypatch):
    app = app_factory(require_api_key=False)
    monkeypatch.setenv("QC_REQUIRE_REDIS", "1")
    monkeypatch.setenv("QC_REDIS_URL", f"redis://user:{SENTINEL}@internal.example:6379")
    from core import redis_client
    client = Mock()
    monkeypatch.setattr(redis_client, "get_redis", lambda: client)
    for failure, expected_status in [(None, 200), (RuntimeError(FAILURE), 503)]:
        client.ping.side_effect = failure
        response = app.test_client().get("/readyz")
        assert response.status_code == expected_status
        assert response.json["checks"]["redis"]["required"] is True
        assert SENTINEL not in response.get_data(as_text=True)
        assert "internal.example" not in response.get_data(as_text=True)


def test_prompt_guard_never_logs_secret_bearing_context_labels(caplog):
    from sovereignty.prompt_guard import sanitize_untrusted_text
    with caplog.at_level(logging.WARNING, logger="sovereignty.prompt_guard"):
        result = sanitize_untrusted_text(f"password={SENTINEL}", context_label=FAILURE)
    assert SENTINEL not in result
    assert SENTINEL not in caplog.text
    assert "internal.example" not in caplog.text
    assert "redactions=1" in caplog.text


def test_feed_sync_failure_never_returns_or_persists_exception(tmp_path, monkeypatch, caplog):
    from engines.threat_intel_auto import ThreatIntelEngine, ThreatFeed, FeedFormat
    engine = ThreatIntelEngine(db_path=str(tmp_path / "feeds.db"), auto_start=False, load_default_feeds=False)
    feed = ThreatFeed("test", "Test feed", "https://example.com/feed", FeedFormat.JSON)
    engine._feeds[feed.feed_id] = feed
    monkeypatch.setattr(engine, "_fetch_and_parse_feed", Mock(side_effect=requests.ConnectionError(FAILURE)))
    record = Mock()
    monkeypatch.setattr(engine, "record_sync", record)
    result = engine.sync_feed(feed.feed_id)
    assert result == {"feed_id": "test", "ok": False, "error": "feed sync failed"}
    assert SENTINEL not in json.dumps(record.call_args.kwargs)
    assert SENTINEL not in caplog.text
