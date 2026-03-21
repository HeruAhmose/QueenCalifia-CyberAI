"""
engines.threat_intel_auto — Persisted scheduled multi-feed retrieval engine
===========================================================================

This engine provides:
  - durable SQLite-backed storage for feeds, indicators, CVEs, actors, and sync logs
  - scheduled feed retrieval with a cross-process SQLite lease for multi-worker safety
  - real parsers for JSON, CSV, STIX bundles, and newline IOC feeds
  - automatic decay / lifecycle handling for indicators
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("engines.threat_intel")


def _db_default_path() -> str:
    explicit = os.environ.get("QC_THREAT_INTEL_DB", "").strip()
    if explicit:
        return explicit
    evo_path = os.environ.get("QC_EVOLUTION_DB", "qc_evolution.db")
    evo_dir = os.path.dirname(os.path.abspath(evo_path)) or "."
    return os.path.join(evo_dir, "qc_threat_intel.db")


def _now() -> float:
    return time.time()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _normalize_url(value: str) -> str:
    return str(value or "").strip()


def _sha256(value: str) -> str:
    import hashlib
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class FeedFormat(str, Enum):
    STIX_TAXII = "stix_taxii"
    CSV = "csv"
    JSON = "json"
    OPEN_IOC = "open_ioc"
    MISP = "misp"
    CUSTOM = "custom"


class FeedStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class ThreatFeed:
    """Configured threat intelligence feed."""
    feed_id: str
    name: str
    source_url: str
    feed_format: FeedFormat
    status: FeedStatus = FeedStatus.ACTIVE
    update_interval_sec: int = 900
    last_sync: float = 0.0
    last_success: float = 0.0
    error_count: int = 0
    ioc_count: int = 0
    confidence_weight: float = 1.0
    tags: List[str] = field(default_factory=list)
    auth_required: bool = False
    created_at: float = field(default_factory=_now)
    parser_config: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def due_for_sync(self) -> bool:
        return _now() - self.last_sync > self.update_interval_sec

    @property
    def healthy(self) -> bool:
        return self.error_count < 5 and self.status == FeedStatus.ACTIVE


@dataclass
class ThreatIndicator:
    """Enriched threat indicator with lifecycle tracking."""
    indicator_id: str
    value: str
    indicator_type: str
    confidence: float = 0.0
    severity: str = "medium"
    sources: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    last_updated: float = field(default_factory=_now)
    expires_at: float = 0.0
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    threat_actor: str = ""
    campaign: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    active: bool = True
    decay_rate: float = 0.01

    def apply_decay(self) -> None:
        age_days = (_now() - self.last_seen) / 86400
        self.confidence = max(0.0, self.confidence - (self.decay_rate * age_days))
        if self.expires_at and _now() > self.expires_at:
            self.active = False
        if self.confidence < 0.1:
            self.active = False

    @property
    def age_hours(self) -> float:
        return (_now() - self.first_seen) / 3600


@dataclass
class CVERecord:
    """CVE with auto-priority scoring."""
    cve_id: str
    description: str
    cvss_score: float = 0.0
    severity: str = "medium"
    affected_products: List[str] = field(default_factory=list)
    exploit_available: bool = False
    in_the_wild: bool = False
    patch_available: bool = False
    first_published: float = field(default_factory=_now)
    last_modified: float = field(default_factory=_now)
    references: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    @property
    def priority_score(self) -> float:
        score = self.cvss_score * 8
        if self.exploit_available:
            score += 10
        if self.in_the_wild:
            score += 10
        if not self.patch_available:
            score += 5
        age_days = (_now() - self.first_published) / 86400
        if age_days < 7:
            score += 5
        return min(score, 100.0)


@dataclass
class ThreatActorProfile:
    """Threat actor attribution profile."""
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    nation_state: str = ""
    motivation: str = ""
    sophistication: str = "medium"
    target_industries: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    known_techniques: List[str] = field(default_factory=list)
    known_tools: List[str] = field(default_factory=list)
    campaigns: List[str] = field(default_factory=list)
    ioc_count: int = 0
    last_activity: float = 0.0
    confidence: float = 0.0


class ThreatIntelEngine:
    """Persisted scheduled threat intelligence lifecycle manager."""

    LEASE_NAME = "scheduler"

    def __init__(
        self,
        db_path: str | None = None,
        *,
        auto_start: bool | None = None,
        load_default_feeds: bool = True,
        http_get: Callable[[str, dict[str, str] | None], tuple[str, str]] | None = None,
    ):
        self._lock = threading.RLock()
        self._feeds: Dict[str, ThreatFeed] = {}
        self._indicators: Dict[str, ThreatIndicator] = {}
        self._cves: Dict[str, CVERecord] = {}
        self._actors: Dict[str, ThreatActorProfile] = {}
        self._sync_log: List[Dict[str, Any]] = []
        self._custom_parsers: Dict[str, Callable[[ThreatFeed, str], Dict[str, int]]] = {}
        self.db_path = os.path.abspath(db_path or _db_default_path())
        self._http_get = http_get or self._default_http_get
        self._scheduler_poll_seconds = max(15, int(os.environ.get("QC_THREAT_INTEL_POLL_SECONDS", "60")))
        self._lease_ttl_seconds = max(45, int(os.environ.get("QC_THREAT_INTEL_LEASE_SECONDS", "180")))
        self._owner_id = f"{os.getpid()}-{uuid.uuid4().hex[:10]}"
        self._stop_event = threading.Event()
        self._scheduler_thread: threading.Thread | None = None

        self._init_db()
        self._load_persisted_state()
        if load_default_feeds:
            self._register_default_feeds()

        if auto_start is None:
            sync_flag = os.environ.get("QC_THREAT_INTEL_AUTO_SYNC", "").strip().lower()
            if sync_flag in ("1", "true", "yes", "on"):
                auto_start = True
            elif sync_flag in ("0", "false", "no", "off"):
                auto_start = False
            else:
                # Production default: keep feeds syncing unless explicitly disabled.
                auto_start = os.environ.get("QC_PRODUCTION", "").strip() == "1"
        self._auto_start = bool(auto_start)
        if self._auto_start:
            self.start_scheduler()

    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS threat_feeds (
                    feed_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    feed_format TEXT NOT NULL,
                    status TEXT NOT NULL,
                    update_interval_sec INTEGER NOT NULL,
                    last_sync REAL NOT NULL DEFAULT 0,
                    last_success REAL NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    ioc_count INTEGER NOT NULL DEFAULT 0,
                    confidence_weight REAL NOT NULL DEFAULT 1.0,
                    tags_json TEXT NOT NULL,
                    auth_required INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    parser_config_json TEXT NOT NULL,
                    headers_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    last_updated REAL NOT NULL,
                    expires_at REAL NOT NULL DEFAULT 0,
                    tags_json TEXT NOT NULL,
                    mitre_techniques_json TEXT NOT NULL,
                    threat_actor TEXT,
                    campaign TEXT,
                    context_json TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    decay_rate REAL NOT NULL DEFAULT 0.01
                );

                CREATE TABLE IF NOT EXISTS threat_cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    cvss_score REAL NOT NULL DEFAULT 0,
                    severity TEXT NOT NULL,
                    affected_products_json TEXT NOT NULL,
                    exploit_available INTEGER NOT NULL DEFAULT 0,
                    in_the_wild INTEGER NOT NULL DEFAULT 0,
                    patch_available INTEGER NOT NULL DEFAULT 0,
                    first_published REAL NOT NULL,
                    last_modified REAL NOT NULL,
                    references_json TEXT NOT NULL,
                    mitre_techniques_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS threat_actors (
                    actor_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    aliases_json TEXT NOT NULL,
                    nation_state TEXT,
                    motivation TEXT,
                    sophistication TEXT,
                    target_industries_json TEXT NOT NULL,
                    target_regions_json TEXT NOT NULL,
                    known_techniques_json TEXT NOT NULL,
                    known_tools_json TEXT NOT NULL,
                    campaigns_json TEXT NOT NULL,
                    ioc_count INTEGER NOT NULL DEFAULT 0,
                    last_activity REAL NOT NULL DEFAULT 0,
                    confidence REAL NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS threat_sync_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    feed_id TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    iocs_ingested INTEGER NOT NULL DEFAULT 0,
                    cves_ingested INTEGER NOT NULL DEFAULT 0,
                    actors_ingested INTEGER NOT NULL DEFAULT 0,
                    detail_json TEXT,
                    timestamp REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS threat_scheduler_lease (
                    lease_name TEXT PRIMARY KEY,
                    owner_id TEXT NOT NULL,
                    acquired_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                """
            )

    def _load_persisted_state(self) -> None:
        with self._connect() as conn:
            for row in conn.execute("SELECT * FROM threat_feeds").fetchall():
                self._feeds[row["feed_id"]] = ThreatFeed(
                    feed_id=row["feed_id"],
                    name=row["name"],
                    source_url=row["source_url"],
                    feed_format=FeedFormat(row["feed_format"]),
                    status=FeedStatus(row["status"]),
                    update_interval_sec=int(row["update_interval_sec"]),
                    last_sync=float(row["last_sync"]),
                    last_success=float(row["last_success"]),
                    error_count=int(row["error_count"]),
                    ioc_count=int(row["ioc_count"]),
                    confidence_weight=float(row["confidence_weight"]),
                    tags=json.loads(row["tags_json"] or "[]"),
                    auth_required=bool(row["auth_required"]),
                    created_at=float(row["created_at"]),
                    parser_config=json.loads(row["parser_config_json"] or "{}"),
                    headers=json.loads(row["headers_json"] or "{}"),
                )
            for row in conn.execute("SELECT * FROM threat_indicators").fetchall():
                self._indicators[row["indicator_id"]] = ThreatIndicator(
                    indicator_id=row["indicator_id"],
                    value=row["value"],
                    indicator_type=row["indicator_type"],
                    confidence=float(row["confidence"]),
                    severity=row["severity"],
                    sources=json.loads(row["sources_json"] or "[]"),
                    first_seen=float(row["first_seen"]),
                    last_seen=float(row["last_seen"]),
                    last_updated=float(row["last_updated"]),
                    expires_at=float(row["expires_at"]),
                    tags=json.loads(row["tags_json"] or "[]"),
                    mitre_techniques=json.loads(row["mitre_techniques_json"] or "[]"),
                    threat_actor=row["threat_actor"] or "",
                    campaign=row["campaign"] or "",
                    context=json.loads(row["context_json"] or "{}"),
                    active=bool(row["active"]),
                    decay_rate=float(row["decay_rate"]),
                )
            for row in conn.execute("SELECT * FROM threat_cves").fetchall():
                self._cves[row["cve_id"]] = CVERecord(
                    cve_id=row["cve_id"],
                    description=row["description"],
                    cvss_score=float(row["cvss_score"]),
                    severity=row["severity"],
                    affected_products=json.loads(row["affected_products_json"] or "[]"),
                    exploit_available=bool(row["exploit_available"]),
                    in_the_wild=bool(row["in_the_wild"]),
                    patch_available=bool(row["patch_available"]),
                    first_published=float(row["first_published"]),
                    last_modified=float(row["last_modified"]),
                    references=json.loads(row["references_json"] or "[]"),
                    mitre_techniques=json.loads(row["mitre_techniques_json"] or "[]"),
                )
            for row in conn.execute("SELECT * FROM threat_actors").fetchall():
                self._actors[row["actor_id"]] = ThreatActorProfile(
                    actor_id=row["actor_id"],
                    name=row["name"],
                    aliases=json.loads(row["aliases_json"] or "[]"),
                    nation_state=row["nation_state"] or "",
                    motivation=row["motivation"] or "",
                    sophistication=row["sophistication"] or "medium",
                    target_industries=json.loads(row["target_industries_json"] or "[]"),
                    target_regions=json.loads(row["target_regions_json"] or "[]"),
                    known_techniques=json.loads(row["known_techniques_json"] or "[]"),
                    known_tools=json.loads(row["known_tools_json"] or "[]"),
                    campaigns=json.loads(row["campaigns_json"] or "[]"),
                    ioc_count=int(row["ioc_count"]),
                    last_activity=float(row["last_activity"]),
                    confidence=float(row["confidence"]),
                )
            self._sync_log = [dict(row) for row in conn.execute("SELECT * FROM threat_sync_log ORDER BY id DESC LIMIT 200").fetchall()]

    def _default_feed_definitions(self) -> list[ThreatFeed]:
        env_blob = os.environ.get("QC_THREAT_INTEL_FEEDS_JSON", "").strip()
        if env_blob:
            try:
                data = json.loads(env_blob)
                feeds = []
                for item in data:
                    feeds.append(
                        ThreatFeed(
                            feed_id=str(item["feed_id"]),
                            name=str(item["name"]),
                            source_url=_normalize_url(item["source_url"]),
                            feed_format=FeedFormat(item["feed_format"]),
                            status=FeedStatus(item.get("status", "active")),
                            update_interval_sec=int(item.get("update_interval_sec", 900)),
                            confidence_weight=float(item.get("confidence_weight", 1.0)),
                            tags=list(item.get("tags", [])),
                            auth_required=bool(item.get("auth_required", False)),
                            parser_config=dict(item.get("parser_config", {})),
                            headers=dict(item.get("headers", {})),
                        )
                    )
                return feeds
            except Exception:
                logger.exception("Failed to parse QC_THREAT_INTEL_FEEDS_JSON; using defaults")

        return [
            ThreatFeed(
                feed_id="cisa_kev",
                name="CISA Known Exploited Vulnerabilities",
                source_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                feed_format=FeedFormat.JSON,
                update_interval_sec=3600,
                confidence_weight=0.98,
                tags=["cve", "kev", "exploited"],
                parser_config={"kind": "cisa_kev"},
            ),
            ThreatFeed(
                feed_id="openphish",
                name="OpenPhish Feed",
                source_url="https://openphish.com/feed.txt",
                feed_format=FeedFormat.CUSTOM,
                update_interval_sec=900,
                confidence_weight=0.9,
                tags=["phishing", "url"],
                parser_config={"kind": "ioc_lines", "indicator_type": "url", "severity": "high"},
            ),
        ]

    def _register_default_feeds(self) -> None:
        for feed in self._default_feed_definitions():
            if feed.feed_id not in self._feeds:
                self.register_feed(feed)

    def _default_http_get(self, url: str, headers: dict[str, str] | None = None) -> tuple[str, str]:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content_type = str(resp.headers.get("Content-Type", ""))
            body = resp.read().decode("utf-8", errors="replace")
            return content_type, body

    def _persist_feed(self, feed: ThreatFeed) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_feeds
                   (feed_id, name, source_url, feed_format, status, update_interval_sec, last_sync,
                    last_success, error_count, ioc_count, confidence_weight, tags_json, auth_required,
                    created_at, parser_config_json, headers_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    feed.feed_id,
                    feed.name,
                    feed.source_url,
                    feed.feed_format.value,
                    feed.status.value,
                    int(feed.update_interval_sec),
                    float(feed.last_sync),
                    float(feed.last_success),
                    int(feed.error_count),
                    int(feed.ioc_count),
                    float(feed.confidence_weight),
                    _json_dumps(feed.tags),
                    int(feed.auth_required),
                    float(feed.created_at),
                    _json_dumps(feed.parser_config),
                    _json_dumps(feed.headers),
                ),
            )

    def _persist_indicator(self, indicator: ThreatIndicator) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_indicators
                   (indicator_id, value, indicator_type, confidence, severity, sources_json, first_seen,
                    last_seen, last_updated, expires_at, tags_json, mitre_techniques_json, threat_actor,
                    campaign, context_json, active, decay_rate)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    indicator.indicator_id,
                    indicator.value,
                    indicator.indicator_type,
                    float(indicator.confidence),
                    indicator.severity,
                    _json_dumps(indicator.sources),
                    float(indicator.first_seen),
                    float(indicator.last_seen),
                    float(indicator.last_updated),
                    float(indicator.expires_at or 0),
                    _json_dumps(indicator.tags),
                    _json_dumps(indicator.mitre_techniques),
                    indicator.threat_actor,
                    indicator.campaign,
                    _json_dumps(indicator.context),
                    int(indicator.active),
                    float(indicator.decay_rate),
                ),
            )

    def _persist_cve(self, cve: CVERecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_cves
                   (cve_id, description, cvss_score, severity, affected_products_json, exploit_available,
                    in_the_wild, patch_available, first_published, last_modified, references_json,
                    mitre_techniques_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve.cve_id,
                    cve.description,
                    float(cve.cvss_score),
                    cve.severity,
                    _json_dumps(cve.affected_products),
                    int(cve.exploit_available),
                    int(cve.in_the_wild),
                    int(cve.patch_available),
                    float(cve.first_published),
                    float(cve.last_modified),
                    _json_dumps(cve.references),
                    _json_dumps(cve.mitre_techniques),
                ),
            )

    def _persist_actor(self, actor: ThreatActorProfile) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO threat_actors
                   (actor_id, name, aliases_json, nation_state, motivation, sophistication, target_industries_json,
                    target_regions_json, known_techniques_json, known_tools_json, campaigns_json, ioc_count,
                    last_activity, confidence)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    actor.actor_id,
                    actor.name,
                    _json_dumps(actor.aliases),
                    actor.nation_state,
                    actor.motivation,
                    actor.sophistication,
                    _json_dumps(actor.target_industries),
                    _json_dumps(actor.target_regions),
                    _json_dumps(actor.known_techniques),
                    _json_dumps(actor.known_tools),
                    _json_dumps(actor.campaigns),
                    int(actor.ioc_count),
                    float(actor.last_activity),
                    float(actor.confidence),
                ),
            )

    def register_feed(self, feed: ThreatFeed) -> str:
        with self._lock:
            self._feeds[feed.feed_id] = feed
            self._persist_feed(feed)
            logger.info(
                "threat_intel.feed_registered: id=%s name=%s interval=%ds",
                feed.feed_id,
                feed.name,
                feed.update_interval_sec,
            )
            return feed.feed_id

    def get_feed(self, feed_id: str) -> Optional[ThreatFeed]:
        with self._lock:
            return self._feeds.get(feed_id)

    def get_feeds_due_for_sync(self) -> List[ThreatFeed]:
        with self._lock:
            return [f for f in self._feeds.values() if f.due_for_sync and f.healthy]

    def list_feeds(self) -> List[ThreatFeed]:
        with self._lock:
            return sorted(self._feeds.values(), key=lambda item: item.feed_id)

    def record_sync(
        self,
        feed_id: str,
        *,
        success: bool,
        iocs_ingested: int = 0,
        cves_ingested: int = 0,
        actors_ingested: int = 0,
        detail: dict[str, Any] | None = None,
    ) -> None:
        timestamp = _now()
        with self._lock:
            feed = self._feeds.get(feed_id)
            if not feed:
                return
            feed.last_sync = timestamp
            if success:
                feed.last_success = timestamp
                feed.ioc_count += iocs_ingested
                feed.error_count = 0
                if feed.status == FeedStatus.ERROR:
                    feed.status = FeedStatus.ACTIVE
            else:
                feed.error_count += 1
                if feed.error_count >= 5:
                    feed.status = FeedStatus.ERROR
            self._persist_feed(feed)
            entry = {
                "feed_id": feed_id,
                "success": success,
                "iocs_ingested": iocs_ingested,
                "cves_ingested": cves_ingested,
                "actors_ingested": actors_ingested,
                "detail": detail or {},
                "timestamp": timestamp,
            }
            self._sync_log.insert(0, entry)
            self._sync_log = self._sync_log[:500]
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO threat_sync_log
                       (feed_id, success, iocs_ingested, cves_ingested, actors_ingested, detail_json, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        feed_id,
                        int(success),
                        int(iocs_ingested),
                        int(cves_ingested),
                        int(actors_ingested),
                        _json_dumps(detail or {}),
                        timestamp,
                    ),
                )

    def ingest_indicator(self, indicator: ThreatIndicator) -> str:
        with self._lock:
            existing = self._indicators.get(indicator.indicator_id)
            if existing:
                existing.confidence = max(existing.confidence, indicator.confidence)
                existing.last_seen = max(existing.last_seen, indicator.last_seen)
                existing.last_updated = _now()
                existing.active = True
                existing.expires_at = max(existing.expires_at, indicator.expires_at)
                existing.severity = indicator.severity if indicator.severity else existing.severity
                existing.threat_actor = indicator.threat_actor or existing.threat_actor
                existing.campaign = indicator.campaign or existing.campaign
                for src in indicator.sources:
                    if src not in existing.sources:
                        existing.sources.append(src)
                for tag in indicator.tags:
                    if tag not in existing.tags:
                        existing.tags.append(tag)
                for tech in indicator.mitre_techniques:
                    if tech not in existing.mitre_techniques:
                        existing.mitre_techniques.append(tech)
                if indicator.context:
                    existing.context.update(indicator.context)
                self._persist_indicator(existing)
                return existing.indicator_id

            self._indicators[indicator.indicator_id] = indicator
            self._persist_indicator(indicator)
            return indicator.indicator_id

    def bulk_ingest(self, indicators: List[ThreatIndicator]) -> int:
        count = 0
        for ind in indicators:
            self.ingest_indicator(ind)
            count += 1
        return count

    def search_indicators(self, query: str, indicator_type: Optional[str] = None) -> List[ThreatIndicator]:
        with self._lock:
            results = []
            for ind in self._indicators.values():
                if not ind.active:
                    continue
                if indicator_type and ind.indicator_type != indicator_type:
                    continue
                if query.lower() in ind.value.lower():
                    results.append(ind)
            return sorted(results, key=lambda item: (-item.confidence, item.value))

    def apply_decay_all(self) -> int:
        expired = 0
        with self._lock:
            for ind in self._indicators.values():
                was_active = ind.active
                ind.apply_decay()
                if was_active and not ind.active:
                    expired += 1
                self._persist_indicator(ind)
        return expired

    def get_high_confidence_indicators(self, min_confidence: float = 0.7) -> List[ThreatIndicator]:
        with self._lock:
            results = [i for i in self._indicators.values() if i.active and i.confidence >= min_confidence]
            return sorted(results, key=lambda item: (-item.confidence, -item.last_seen))

    def ingest_cve(self, cve: CVERecord) -> str:
        with self._lock:
            self._cves[cve.cve_id] = cve
            self._persist_cve(cve)
            return cve.cve_id

    def get_critical_cves(self, min_priority: float = 70.0) -> List[CVERecord]:
        with self._lock:
            return sorted(
                [c for c in self._cves.values() if c.priority_score >= min_priority],
                key=lambda c: -c.priority_score,
            )

    def get_exploitable_cves(self) -> List[CVERecord]:
        with self._lock:
            return [c for c in self._cves.values() if c.exploit_available or c.in_the_wild]

    def register_actor(self, actor: ThreatActorProfile) -> str:
        with self._lock:
            self._actors[actor.actor_id] = actor
            self._persist_actor(actor)
            return actor.actor_id

    def search_actors(self, query: str) -> List[ThreatActorProfile]:
        with self._lock:
            q = query.lower()
            return [
                a for a in self._actors.values()
                if q in a.name.lower()
                or q in str(a.aliases).lower()
                or q in a.nation_state.lower()
            ]

    def get_actor_techniques(self, actor_id: str) -> List[str]:
        with self._lock:
            actor = self._actors.get(actor_id)
            return actor.known_techniques if actor else []

    def _indicator_id(self, indicator_type: str, value: str) -> str:
        return _sha256(f"{indicator_type}:{value}".lower())[:32]

    def _infer_indicator_type(self, value: str) -> str:
        raw = value.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            return "url"
        if "@" in raw and "." in raw:
            return "email"
        if all(ch.isdigit() or ch == "." for ch in raw) and raw.count(".") == 3:
            return "ip"
        if len(raw) in {32, 40, 64} and all(ch in "0123456789abcdefABCDEF" for ch in raw):
            return "hash"
        return "domain"

    def _parse_ioc_lines(self, feed: ThreatFeed, body: str) -> Dict[str, int]:
        cfg = feed.parser_config or {}
        indicator_type = cfg.get("indicator_type", "url")
        severity = cfg.get("severity", "high")
        indicators = []
        for line in body.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            indicators.append(
                ThreatIndicator(
                    indicator_id=self._indicator_id(indicator_type, value),
                    value=value,
                    indicator_type=indicator_type,
                    confidence=min(1.0, 0.6 * feed.confidence_weight),
                    severity=severity,
                    sources=[feed.feed_id],
                    tags=list(feed.tags),
                    context={"feed": feed.name},
                )
            )
        if not indicators:
            return {"indicators": 0, "cves": 0, "actors": 0}
        ingested = self.bulk_ingest(indicators)
        return {"indicators": ingested, "cves": 0, "actors": 0}

    def probe_health(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM threat_feeds").fetchone()
        return {
            "healthy": True,
            "metrics": {
                "db_path": self.db_path,
                "feeds_registered": int(row["count"]) if row else 0,
                "scheduler_running": bool(self._scheduler_thread and self._scheduler_thread.is_alive()),
            },
        }

    def recover_runtime_state(self) -> Dict[str, Any]:
        with self._lock:
            self._feeds = {}
            self._indicators = {}
            self._cves = {}
            self._actors = {}
            self._sync_log = []
            self._init_db()
            self._load_persisted_state()
            return {
                "healed": True,
                "strategy": "reload_threat_intel_state",
                "feeds": len(self._feeds),
            }

    def _parse_cisa_kev(self, feed: ThreatFeed, payload: dict[str, Any]) -> Dict[str, int]:
        cves = 0
        vulns = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
        for item in vulns:
            cve_id = str(item.get("cveID", "")).strip()
            if not cve_id:
                continue
            known_ransomware = str(item.get("knownRansomwareCampaignUse", "")).lower() == "known"
            cvss_score = float(item.get("cvssScore", 0) or 0)
            if cvss_score <= 0 and known_ransomware:
                cvss_score = 9.8
            cve = CVERecord(
                cve_id=cve_id,
                description=str(item.get("shortDescription", "")),
                cvss_score=cvss_score,
                severity="critical" if known_ransomware else "high",
                affected_products=[str(item.get("product", ""))],
                exploit_available=True,
                in_the_wild=True,
                patch_available=bool(item.get("dueDate")),
                references=[feed.source_url],
            )
            self.ingest_cve(cve)
            cves += 1
        return {"indicators": 0, "cves": cves, "actors": 0}

    def _parse_json_feed(self, feed: ThreatFeed, body: str) -> Dict[str, int]:
        payload = json.loads(body)
        kind = str((feed.parser_config or {}).get("kind", "generic")).strip()
        if kind == "cisa_kev":
            return self._parse_cisa_kev(feed, payload)

        indicators = 0
        cves = 0
        actors = 0
        if isinstance(payload, dict):
            if isinstance(payload.get("indicators"), list):
                for item in payload["indicators"]:
                    value = str(item.get("value", "")).strip()
                    if not value:
                        continue
                    indicator_type = str(item.get("indicator_type") or self._infer_indicator_type(value))
                    self.ingest_indicator(
                        ThreatIndicator(
                            indicator_id=str(item.get("indicator_id") or self._indicator_id(indicator_type, value)),
                            value=value,
                            indicator_type=indicator_type,
                            confidence=float(item.get("confidence", 0.7)),
                            severity=str(item.get("severity", "medium")),
                            sources=[feed.feed_id],
                            tags=list(feed.tags) + list(item.get("tags", [])),
                            mitre_techniques=list(item.get("mitre_techniques", [])),
                            threat_actor=str(item.get("threat_actor", "")),
                            campaign=str(item.get("campaign", "")),
                            context=dict(item.get("context", {})),
                        )
                    )
                    indicators += 1
            if isinstance(payload.get("cves"), list):
                for item in payload["cves"]:
                    cve_id = str(item.get("cve_id", "")).strip()
                    if not cve_id:
                        continue
                    self.ingest_cve(
                        CVERecord(
                            cve_id=cve_id,
                            description=str(item.get("description", "")),
                            cvss_score=float(item.get("cvss_score", 0) or 0),
                            severity=str(item.get("severity", "medium")),
                            affected_products=list(item.get("affected_products", [])),
                            exploit_available=bool(item.get("exploit_available", False)),
                            in_the_wild=bool(item.get("in_the_wild", False)),
                            patch_available=bool(item.get("patch_available", False)),
                            references=list(item.get("references", [])),
                            mitre_techniques=list(item.get("mitre_techniques", [])),
                        )
                    )
                    cves += 1
            if isinstance(payload.get("actors"), list):
                for item in payload["actors"]:
                    actor_id = str(item.get("actor_id", "")).strip()
                    name = str(item.get("name", "")).strip()
                    if not actor_id or not name:
                        continue
                    self.register_actor(
                        ThreatActorProfile(
                            actor_id=actor_id,
                            name=name,
                            aliases=list(item.get("aliases", [])),
                            nation_state=str(item.get("nation_state", "")),
                            motivation=str(item.get("motivation", "")),
                            sophistication=str(item.get("sophistication", "medium")),
                            target_industries=list(item.get("target_industries", [])),
                            target_regions=list(item.get("target_regions", [])),
                            known_techniques=list(item.get("known_techniques", [])),
                            known_tools=list(item.get("known_tools", [])),
                            campaigns=list(item.get("campaigns", [])),
                            ioc_count=int(item.get("ioc_count", 0)),
                            last_activity=float(item.get("last_activity", 0) or 0),
                            confidence=float(item.get("confidence", 0) or 0),
                        )
                    )
                    actors += 1
        return {"indicators": indicators, "cves": cves, "actors": actors}

    def _parse_stix_bundle(self, feed: ThreatFeed, body: str) -> Dict[str, int]:
        payload = json.loads(body)
        objects = payload.get("objects", []) if isinstance(payload, dict) else []
        indicators = 0
        cves = 0
        actors = 0
        for item in objects:
            stix_type = str(item.get("type", "")).strip().lower()
            if stix_type == "indicator":
                pattern = str(item.get("pattern", "")).strip()
                value = pattern.replace("[", "").replace("]", "").replace("'", "")
                if "=" in value:
                    value = value.split("=", 1)[1].strip()
                indicator_type = self._infer_indicator_type(value)
                self.ingest_indicator(
                    ThreatIndicator(
                        indicator_id=str(item.get("id") or self._indicator_id(indicator_type, value)),
                        value=value,
                        indicator_type=indicator_type,
                        confidence=min(1.0, 0.75 * feed.confidence_weight),
                        severity="high",
                        sources=[feed.feed_id],
                        tags=list(feed.tags),
                        context={"stix_pattern": pattern, "name": item.get("name")},
                    )
                )
                indicators += 1
            elif stix_type == "vulnerability":
                name = str(item.get("name", "")).strip()
                if not name:
                    continue
                self.ingest_cve(
                    CVERecord(
                        cve_id=name,
                        description=str(item.get("description", "")),
                        cvss_score=0,
                        severity="high",
                        references=list(item.get("external_references", [])),
                    )
                )
                cves += 1
            elif stix_type == "threat-actor":
                actor_id = str(item.get("id", "")).strip()
                name = str(item.get("name", "")).strip()
                if not actor_id or not name:
                    continue
                self.register_actor(
                    ThreatActorProfile(
                        actor_id=actor_id,
                        name=name,
                        aliases=list(item.get("aliases", [])),
                        confidence=min(1.0, 0.7 * feed.confidence_weight),
                    )
                )
                actors += 1
        return {"indicators": indicators, "cves": cves, "actors": actors}

    def _parse_csv_feed(self, feed: ThreatFeed, body: str) -> Dict[str, int]:
        cfg = feed.parser_config or {}
        kind = str(cfg.get("kind", "generic")).strip()
        reader = csv.DictReader(io.StringIO(body))
        indicators = 0
        cves = 0
        actors = 0
        for row in reader:
            normalized = {str(k or "").strip().lower(): v for k, v in row.items()}
            if kind == "abuse_ch_ip_csv":
                value = str(normalized.get("ip_address") or normalized.get("ip") or "").strip()
                if not value:
                    continue
                self.ingest_indicator(
                    ThreatIndicator(
                        indicator_id=self._indicator_id("ip", value),
                        value=value,
                        indicator_type="ip",
                        confidence=min(1.0, 0.78 * feed.confidence_weight),
                        severity=str(cfg.get("severity", "high")),
                        sources=[feed.feed_id],
                        tags=list(feed.tags),
                        context={"malware": normalized.get("malware"), "asn": normalized.get("asn")},
                    )
                )
                indicators += 1
                continue

            value = str(normalized.get("value") or normalized.get("indicator") or normalized.get("ioc") or "").strip()
            if value:
                indicator_type = str(normalized.get("indicator_type") or self._infer_indicator_type(value))
                self.ingest_indicator(
                    ThreatIndicator(
                        indicator_id=self._indicator_id(indicator_type, value),
                        value=value,
                        indicator_type=indicator_type,
                        confidence=float(normalized.get("confidence") or 0.7),
                        severity=str(normalized.get("severity") or "medium"),
                        sources=[feed.feed_id],
                        tags=list(feed.tags),
                    )
                )
                indicators += 1
                continue

            cve_id = str(normalized.get("cve") or normalized.get("cve_id") or "").strip()
            if cve_id:
                self.ingest_cve(
                    CVERecord(
                        cve_id=cve_id,
                        description=str(normalized.get("description") or ""),
                        cvss_score=float(normalized.get("cvss_score") or 0),
                        severity=str(normalized.get("severity") or "medium"),
                    )
                )
                cves += 1
        return {"indicators": indicators, "cves": cves, "actors": actors}

    def _fetch_and_parse_feed(self, feed: ThreatFeed) -> Dict[str, int]:
        content_type, body = self._http_get(feed.source_url, feed.headers or None)
        if feed.feed_format == FeedFormat.JSON:
            return self._parse_json_feed(feed, body)
        if feed.feed_format == FeedFormat.CSV:
            return self._parse_csv_feed(feed, body)
        if feed.feed_format == FeedFormat.STIX_TAXII:
            return self._parse_stix_bundle(feed, body)
        if feed.feed_format == FeedFormat.CUSTOM:
            kind = str((feed.parser_config or {}).get("kind", "ioc_lines"))
            if kind == "ioc_lines":
                return self._parse_ioc_lines(feed, body)
            parser = self._custom_parsers.get(kind)
            if parser:
                return parser(feed, body)
            raise ValueError(f"unknown custom feed parser: {kind}")
        raise ValueError(f"unsupported feed format: {feed.feed_format.value}")

    def sync_feed(self, feed_id: str) -> Dict[str, Any]:
        with self._lock:
            feed = self._feeds.get(feed_id)
            if not feed:
                raise KeyError(feed_id)

        try:
            ingested = self._fetch_and_parse_feed(feed)
            self.record_sync(
                feed.feed_id,
                success=True,
                iocs_ingested=int(ingested.get("indicators", 0)),
                cves_ingested=int(ingested.get("cves", 0)),
                actors_ingested=int(ingested.get("actors", 0)),
                detail={"source_url": feed.source_url},
            )
            return {"feed_id": feed.feed_id, "ok": True, **ingested}
        except Exception as exc:
            logger.exception("threat intel sync failed for %s", feed.feed_id)
            self.record_sync(
                feed.feed_id,
                success=False,
                detail={"error": str(exc), "source_url": feed.source_url},
            )
            return {"feed_id": feed.feed_id, "ok": False, "error": str(exc)}

    def sync_due_feeds(self) -> Dict[str, Any]:
        feeds = self.get_feeds_due_for_sync()
        results = [self.sync_feed(feed.feed_id) for feed in feeds]
        expired = self.apply_decay_all()
        return {
            "feeds_due": len(feeds),
            "results": results,
            "expired_indicators": expired,
        }

    def _acquire_scheduler_lease(self) -> bool:
        now = _now()
        expires_at = now + self._lease_ttl_seconds
        with self._connect() as conn:
            row = conn.execute(
                "SELECT owner_id, expires_at FROM threat_scheduler_lease WHERE lease_name=?",
                (self.LEASE_NAME,),
            ).fetchone()
            if row and row["owner_id"] != self._owner_id and float(row["expires_at"]) > now:
                return False
            conn.execute(
                """INSERT INTO threat_scheduler_lease (lease_name, owner_id, acquired_at, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(lease_name) DO UPDATE SET
                     owner_id=excluded.owner_id,
                     acquired_at=excluded.acquired_at,
                     expires_at=excluded.expires_at""",
                (self.LEASE_NAME, self._owner_id, now, expires_at),
            )
        return True

    def _scheduler_loop(self) -> None:
        while not self._stop_event.wait(self._scheduler_poll_seconds):
            try:
                if self._acquire_scheduler_lease():
                    self.sync_due_feeds()
            except Exception:
                logger.exception("Threat intel scheduler tick failed")

    def start_scheduler(self) -> None:
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            return
        self._scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="qc-threat-intel-scheduler",
            daemon=True,
        )
        self._scheduler_thread.start()

    def stop_scheduler(self) -> None:
        self._stop_event.set()
        if self._scheduler_thread and self._scheduler_thread.is_alive():
            self._scheduler_thread.join(timeout=2)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            active_indicators = sum(1 for i in self._indicators.values() if i.active)
            feeds_healthy = sum(1 for f in self._feeds.values() if f.healthy)
            return {
                "db_path": self.db_path,
                "feeds": len(self._feeds),
                "feeds_healthy": feeds_healthy,
                "indicators_total": len(self._indicators),
                "indicators_active": active_indicators,
                "cves_tracked": len(self._cves),
                "cves_critical": len(self.get_critical_cves()),
                "actors_profiled": len(self._actors),
                "syncs_logged": len(self._sync_log),
                "scheduler": {
                    "enabled": self._auto_start,
                    "owner_id": self._owner_id,
                    "poll_seconds": self._scheduler_poll_seconds,
                    "lease_seconds": self._lease_ttl_seconds,
                    "running": bool(self._scheduler_thread and self._scheduler_thread.is_alive()),
                },
                "feeds_detail": [
                    {
                        "feed_id": f.feed_id,
                        "name": f.name,
                        "status": f.status.value,
                        "format": f.feed_format.value,
                        "last_sync": f.last_sync,
                        "last_success": f.last_success,
                        "error_count": f.error_count,
                        "ioc_count": f.ioc_count,
                        "source_url": f.source_url,
                    }
                    for f in sorted(self._feeds.values(), key=lambda item: item.feed_id)
                ],
            }

    @property
    def indicator_count(self) -> int:
        with self._lock:
            return len(self._indicators)

    @property
    def feed_count(self) -> int:
        with self._lock:
            return len(self._feeds)
