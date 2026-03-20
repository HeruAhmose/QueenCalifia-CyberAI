"""Regression coverage for persisted scheduled threat intel retrieval."""

from __future__ import annotations

import time

from engines.threat_intel_auto import FeedFormat, ThreatFeed, ThreatIntelEngine


def _fake_http_factory(mapping: dict[str, tuple[str, str]]):
    def _http_get(url: str, headers: dict[str, str] | None = None) -> tuple[str, str]:
        return mapping[url]

    return _http_get


def test_multi_feed_sync_persists_indicators_and_cves(tmp_path):
    db_path = tmp_path / "threat_intel.db"
    feeds = {
        "https://example.test/kev.json": (
            "application/json",
            """
            {
              "vulnerabilities": [
                {
                  "cveID": "CVE-2026-0001",
                  "shortDescription": "Critical exploited issue",
                  "knownRansomwareCampaignUse": "Known",
                  "product": "Example Server",
                  "dueDate": "2026-03-31"
                }
              ]
            }
            """,
        ),
        "https://example.test/iocs.txt": (
            "text/plain",
            "https://phish.example/login\nhttps://evil.example/dropper\n",
        ),
    }

    engine = ThreatIntelEngine(
        db_path=str(db_path),
        auto_start=False,
        load_default_feeds=False,
        http_get=_fake_http_factory(feeds),
    )
    engine.register_feed(
        ThreatFeed(
            feed_id="kev",
            name="KEV",
            source_url="https://example.test/kev.json",
            feed_format=FeedFormat.JSON,
            update_interval_sec=1,
            parser_config={"kind": "cisa_kev"},
        )
    )
    engine.register_feed(
        ThreatFeed(
            feed_id="iocs",
            name="IOCs",
            source_url="https://example.test/iocs.txt",
            feed_format=FeedFormat.CUSTOM,
            update_interval_sec=1,
            parser_config={"kind": "ioc_lines", "indicator_type": "url", "severity": "high"},
        )
    )

    result = engine.sync_due_feeds()
    assert result["feeds_due"] >= 2
    assert len(engine.get_critical_cves()) == 1
    assert len(engine.get_high_confidence_indicators(0.5)) == 2

    restarted = ThreatIntelEngine(db_path=str(db_path), auto_start=False, load_default_feeds=False)
    assert restarted.feed_count >= 2
    assert len(restarted.get_critical_cves()) == 1
    assert len(restarted.get_high_confidence_indicators(0.5)) == 2


def test_scheduler_lease_prevents_duplicate_owners(tmp_path):
    db_path = tmp_path / "threat_intel.db"
    first = ThreatIntelEngine(db_path=str(db_path), auto_start=False, load_default_feeds=False)
    second = ThreatIntelEngine(db_path=str(db_path), auto_start=False, load_default_feeds=False)

    assert first._acquire_scheduler_lease() is True
    assert second._acquire_scheduler_lease() is False


def test_feed_is_due_again_after_interval(tmp_path):
    db_path = tmp_path / "threat_intel.db"
    engine = ThreatIntelEngine(db_path=str(db_path), auto_start=False, load_default_feeds=False)
    engine.register_feed(
        ThreatFeed(
            feed_id="delayed",
            name="Delayed Feed",
            source_url="https://example.test/delay.txt",
            feed_format=FeedFormat.CUSTOM,
            update_interval_sec=1,
            parser_config={"kind": "ioc_lines", "indicator_type": "url"},
        )
    )

    feed = engine.get_feed("delayed")
    assert feed is not None
    feed.last_sync = time.time()
    assert engine.get_feeds_due_for_sync() == []

    feed.last_sync = time.time() - 5
    due = engine.get_feeds_due_for_sync()
    assert any(item.feed_id == "delayed" for item in due)
