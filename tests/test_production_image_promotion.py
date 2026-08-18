from __future__ import annotations

from pathlib import Path

import pytest

from scripts.ci.check_production_image_promotion import validate_promotion


API_DIGEST = "sha256:" + ("a" * 64)
FRONTEND_DIGEST = "sha256:" + ("b" * 64)


def _write_values(path: Path, *, api_digest: str, frontend_digest: str) -> None:
    path.write_text(
        f"""api:
  image:
    digest: {api_digest!r}
frontend:
  image:
    digest: {frontend_digest!r}
""",
        encoding="utf-8",
    )


def test_valid_promotion_requires_exact_staged_digests(tmp_path):
    staging = tmp_path / "staging.yaml"
    production = tmp_path / "production.yaml"
    _write_values(staging, api_digest=API_DIGEST, frontend_digest=FRONTEND_DIGEST)
    _write_values(production, api_digest=API_DIGEST, frontend_digest=FRONTEND_DIGEST)

    validate_promotion(staging, production)


def test_blank_digest_fails_closed(tmp_path):
    staging = tmp_path / "staging.yaml"
    production = tmp_path / "production.yaml"
    _write_values(staging, api_digest="", frontend_digest=FRONTEND_DIGEST)
    _write_values(production, api_digest="", frontend_digest=FRONTEND_DIGEST)

    with pytest.raises(SystemExit, match="immutable sha256"):
        validate_promotion(staging, production)


def test_non_sha256_digest_fails_closed(tmp_path):
    staging = tmp_path / "staging.yaml"
    production = tmp_path / "production.yaml"
    _write_values(staging, api_digest="sha512:" + ("a" * 128), frontend_digest=FRONTEND_DIGEST)
    _write_values(production, api_digest="sha512:" + ("a" * 128), frontend_digest=FRONTEND_DIGEST)

    with pytest.raises(SystemExit, match="immutable sha256"):
        validate_promotion(staging, production)


def test_production_digest_must_match_staging(tmp_path):
    staging = tmp_path / "staging.yaml"
    production = tmp_path / "production.yaml"
    _write_values(staging, api_digest=API_DIGEST, frontend_digest=FRONTEND_DIGEST)
    _write_values(
        production,
        api_digest="sha256:" + ("c" * 64),
        frontend_digest=FRONTEND_DIGEST,
    )

    with pytest.raises(SystemExit, match="production digest does not match staged digest"):
        validate_promotion(staging, production)
