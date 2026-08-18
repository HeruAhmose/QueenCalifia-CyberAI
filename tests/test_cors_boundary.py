from __future__ import annotations

from werkzeug.test import Client
from werkzeug.wrappers import Response

from core.cors_boundary import CorsOriginBoundaryMiddleware, is_browser_origin_allowed


def _permissive_upstream(environ, start_response):
    response = Response("ok", status=200, content_type="text/plain")
    response.headers["Access-Control-Allow-Origin"] = environ.get("HTTP_ORIGIN", "*")
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Expose-Headers"] = "X-Internal"
    return response(environ, start_response)


def _client(*, configured_origins=(), production=True):
    return Client(
        CorsOriginBoundaryMiddleware(
            _permissive_upstream,
            configured_origins=configured_origins,
            production=production,
        ),
        Response,
    )


def test_production_allows_exact_configured_origin():
    origin = "https://queen-dashboard.storage.googleapis.com"
    response = _client(configured_origins=origin).get("/", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == origin
    assert response.headers.get("Access-Control-Allow-Credentials") is None


def test_production_allows_canonical_queen_origin_without_env_override():
    origin = "https://queencalifia.tamerian.com"
    response = _client().get("/", headers={"Origin": origin})

    assert response.headers["Access-Control-Allow-Origin"] == origin


def test_production_allows_queen_firebase_preview_only():
    approved = "https://queencalifia-cyberai--release-42.web.app"
    unrelated = "https://another-project--release-42.web.app"

    assert is_browser_origin_allowed(approved, production=True)
    assert not is_browser_origin_allowed(unrelated, production=True)


def test_production_blocks_unrelated_firebase_origin_and_scrubs_upstream_cors():
    origin = "https://another-project.web.app"
    response = _client().get("/", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") is None
    assert response.headers.get("Access-Control-Allow-Credentials") is None
    assert response.headers.get("Access-Control-Expose-Headers") is None
    assert "Origin" in response.headers.get("Vary", "")


def test_production_blocks_unconfigured_gcs_bucket_origin():
    origin = "https://unrelated-bucket.storage.googleapis.com"
    response = _client().get("/", headers={"Origin": origin})

    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") is None


def test_production_blocks_localhost_by_default():
    assert not is_browser_origin_allowed("http://localhost:5173", production=True)
    assert not is_browser_origin_allowed("http://127.0.0.1:3000", production=True)


def test_development_allows_loopback_and_service_origins():
    assert is_browser_origin_allowed("http://localhost:5173", production=False)
    assert is_browser_origin_allowed("http://127.0.0.1:3000", production=False)
    assert is_browser_origin_allowed("http://queencalifia-cyberai:10000", production=False)


def test_localhost_lookalike_is_never_treated_as_loopback():
    assert not is_browser_origin_allowed("https://localhost.evil.example", production=False)
    assert not is_browser_origin_allowed("https://evil-localhost.example", production=False)


def test_malformed_origin_is_rejected():
    assert not is_browser_origin_allowed("https://queencalifia.tamerian.com/path", production=True)
    assert not is_browser_origin_allowed("https://user@queencalifia.tamerian.com", production=True)
