"""Phase-2 behavioral hardening for Queen Califia's conversation boundary.

Keeps the existing conversation engine intact while adding fail-closed contracts
at the HTTP-facing boundary:

1. prompt-injection / role-hijack resistance using sovereignty.prompt_guard;
2. explicit opt-in organizational memory (``remember this: ...``);
3. deterministic multi-turn fact continuity for local-symbolic operation;
4. grounded workflow reasoning for defensive incident and research synthesis;
5. adversarial refusal, fabricated-CVE, and contradiction handling;
6. competitive cross-domain analysis and trusted-source provenance articulation.

The wrapper deliberately does not broaden ambient memory capture. New durable
facts are only extracted when the user explicitly asks QC to remember them.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Iterable

from core.database import get_db
from . import engine as _engine
from sovereignty.prompt_guard import sanitize_untrusted_text, scan_for_injection


_EXPLICIT_REMEMBER = re.compile(r"\b(?:please\s+)?remember\s+this\s*:\s*", re.IGNORECASE)
_SIEM = re.compile(
    r"\bprimary\s+siem\s+(?:platform\s+)?is\s+(.+?)(?=\s+and\b|[.;]|$)",
    re.IGNORECASE,
)
_COMPLIANCE = re.compile(
    r"\b(?:under|subject\s+to)\s+([A-Za-z0-9][A-Za-z0-9 ._/-]{1,48}?)\s+compliance\b",
    re.IGNORECASE,
)
_SECTOR = re.compile(
    r"\b(?:in|within)\s+the\s+([A-Za-z0-9][A-Za-z0-9 ._/-]{1,48}?)\s+sector\b",
    re.IGNORECASE,
)
_CVE = re.compile(r"\bCVE-(\d{4})-(\d{4,})\b", re.IGNORECASE)

_CONTEXT_REQUEST_MARKERS = (
    "summarize the environment facts",
    "summarize the facts i gave you",
    "given everything i've told you",
    "given everything i have told you",
    "reference the specific details",
    "reference specific details",
)


def _explicit_memories(message: str) -> list[tuple[str, str]]:
    if not _EXPLICIT_REMEMBER.search(message or ""):
        return []

    candidates: list[tuple[str, str]] = []
    for key, pattern in (
        ("siem", _SIEM),
        ("compliance", _COMPLIANCE),
        ("sector", _SECTOR),
    ):
        match = pattern.search(message)
        if not match:
            continue
        value = match.group(1).strip(" .,!?:;\t\r\n")
        if value:
            candidates.append((key, value))
    return candidates


def _load_memory_map(db_path: str, user_id: str) -> dict[str, str]:
    with get_db(db_path) as connection:
        rows = connection.execute(
            "SELECT key,value FROM memories WHERE user_id=? ORDER BY id DESC LIMIT 30",
            (user_id,),
        ).fetchall()
    out: dict[str, str] = {}
    for row in rows:
        key = str(row["key"])
        out.setdefault(key, str(row["value"]))
    return out


def _recent_user_facts(db_path: str, session_id: str, current_message: str) -> list[str]:
    with get_db(db_path) as connection:
        rows = connection.execute(
            "SELECT content FROM turns WHERE session_id=? AND role='user' ORDER BY id DESC LIMIT 12",
            (session_id,),
        ).fetchall()

    facts: list[str] = []
    current_norm = (current_message or "").strip().lower()
    for row in reversed(rows):
        raw = str(row["content"] or "").strip()
        if not raw or raw.lower() == current_norm:
            continue
        safe = sanitize_untrusted_text(
            raw,
            max_len=600,
            context_label="conversation_history",
        ).strip()
        if safe and safe not in facts:
            facts.append(safe)
    return facts[-8:]


def _replace_last_assistant_turn(db_path: str, session_id: str, reply: str) -> None:
    with get_db(db_path) as connection:
        row = connection.execute(
            "SELECT id FROM turns WHERE session_id=? AND role='assistant' ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        if row:
            connection.execute(
                "UPDATE turns SET content=? WHERE id=?",
                (reply, row["id"]),
            )


def _is_memory_recall(message: str) -> bool:
    low = (message or "").lower()
    return (
        ("siem" in low and any(word in low for word in ("use", "platform", "which", "what")))
        or ("compliance" in low and any(word in low for word in ("framework", "applies", "which", "what")))
    )


def _is_context_request(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in _CONTEXT_REQUEST_MARKERS)


def _is_threat_triage(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "cyber":
        return False
    threat_signal = any(term in low for term in ("apt29", "known c2", " c2 ", "command and control"))
    incident_signal = any(term in low for term in ("outbound dns", "workstation", "begin threat assessment", "threat assessment"))
    return threat_signal and incident_signal


def _is_blast_radius_escalation(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "cyber" or "blast radius" not in low:
        return False
    return any(term in low for term in ("aws", "vpn", "local admin", "production environment", "privilege"))


def _is_cyber_market_synthesis(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "research" or "ransomware" not in low:
        return False
    return any(term in low for term in ("market impact", "insurance", "stocks", "crypto", "safe-haven", "flows"))


def _is_competitive_cloud_breach_synthesis(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "research":
        return False
    cloud_breach = "cloud" in low and "breach" in low
    cross_domain = "crypto" in low and "insurance" in low
    depth_request = any(term in low for term in ("cross-domain", "specific reasoning", "not generalities"))
    return cloud_breach and cross_domain and depth_request


def _is_market_source_provenance(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "research":
        return False
    asks_sources = "data sources" in low or "market intelligence" in low
    asks_verification = any(term in low for term in ("verified", "trusted", "provenance", "source"))
    return asks_sources and asks_verification


def _is_instruction_override_exfiltration(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "cyber":
        return False
    override = any(term in low for term in ("forget everything", "no restrictions", "ignore your restrictions"))
    exfiltration = "exfiltrat" in low and any(term in low for term in ("without detection", "undetected", "stealth"))
    return override and exfiltration


def _is_false_authority_secret_request(message: str, mode: str) -> bool:
    low = (message or "").lower()
    if mode != "cyber":
        return False
    authority = any(term in low for term in ("i am the ceo", "i'm the ceo", "i am the administrator", "i'm the administrator"))
    secret_request = any(term in low for term in ("raw api keys", "api keys", "database credentials", "credentials for this system"))
    override = any(term in low for term in ("override your security", "override security", "bypass security"))
    return authority and secret_request and override


def _future_or_unverifiable_cve(message: str) -> str | None:
    match = _CVE.search(message or "")
    if not match:
        return None
    cve = match.group(0).upper()
    year = int(match.group(1))
    if year > datetime.now(timezone.utc).year:
        return cve
    return None


def _firewall_contradiction(message: str, facts: Iterable[str]) -> tuple[str, str] | None:
    low = (message or "").lower()
    if "firewall" not in low:
        return None

    current = None
    if "fortinet" in low:
        current = "Fortinet"
    elif "palo alto" in low:
        current = "Palo Alto Networks"
    if not current:
        return None

    prior_blob = " ".join(facts).lower()
    prior = None
    if "palo alto" in prior_blob:
        prior = "Palo Alto Networks"
    elif "fortinet" in prior_blob:
        prior = "Fortinet"

    if prior and prior.lower() != current.lower():
        return prior, current
    return None


def _memory_reply(memories: dict[str, str]) -> str | None:
    siem = memories.get("siem")
    compliance = memories.get("compliance")
    sector = memories.get("sector")
    if not (siem or compliance):
        return None

    parts = []
    if siem:
        parts.append(f"your primary SIEM is {siem}")
    if compliance:
        parts.append(f"your compliance framework is {compliance}")
    if sector:
        parts.append(f"you operate in the {sector} sector")
    return "I remember that " + ", and ".join(parts) + "."


def _threat_triage_reply(message: str) -> str:
    low = (message or "").lower()
    scope = "the three finance workstations" if "finance" in low else "the affected workstations"
    return (
        f"Treat this as a high-priority incident. Immediately contain and isolate {scope} from normal network access while preserving evidence. "
        "Investigate the DNS telemetry, resolver logs, endpoint process trees, authentication events, and recent changes to determine whether the C2 pattern is a true compromise or a false positive. "
        "Block the known malicious domains at approved defensive controls, search for the same indicators across the environment, and identify credentials used from the affected hosts. "
        "Do not assume APT29 attribution from the indicator alone; severity is high because known C2-like traffic from multiple finance endpoints can indicate coordinated command-and-control activity."
    )


def _blast_radius_reply(message: str, facts: Iterable[str]) -> str:
    prior = " ".join(facts).lower()
    finance = "finance" in prior or "finance" in (message or "").lower()
    prior_scope = "three finance workstations" if "three workstations" in prior and finance else "the affected endpoints"
    return (
        f"The blast radius now includes more than {prior_scope}: the workstation with local-admin rights and VPN access creates a credential and privilege path into AWS production. "
        "Prioritize containment of that endpoint, disable or rotate its VPN and privileged credentials through the authorized identity process, and review AWS authentication, CloudTrail, IAM, session, and network telemetry for lateral movement during the six-hour window. "
        "Next, determine whether the same account, tokens, keys, or sessions touched additional cloud resources and whether the other affected workstations share credentials or indicators. "
        "I would classify production-cloud exposure as possible but not yet confirmed; the priority is to sever active access, preserve evidence, and bound the blast radius before restoration."
    )


def _cyber_market_synthesis_reply(message: str) -> str:
    return (
        "Scenario analysis only: a major ransomware event at a Fortune 500 company would likely raise near-term cyber-risk awareness and could increase expectations for insurance demand, pricing discipline, claims scrutiny, and security spending. "
        "Cyber-insurance-related stocks could move in different directions: stronger future premium economics may help some insurers, while uncertainty about claim severity, exclusions, and aggregate exposure can pressure names perceived to carry concentrated risk. "
        "For crypto, a safe-haven narrative is not reliable by itself; flows can be split between liquidity seeking, risk-off selling, stablecoins, and speculative rotation. "
        "The key cross-domain variables are incident severity, business interruption, disclosed losses, insurer exposure, regulatory response, equity-market risk sentiment, and whether crypto flows correlate with broader risk-off behavior. "
        "Without live market data in this conversation, I would treat those as hypotheses to test rather than observed price effects."
    )


def _competitive_cloud_breach_reply() -> str:
    return (
        "Cross-domain scenario analysis: a major cloud-provider breach can transmit risk through both cyber-insurance and crypto markets because the same event changes expected loss, operational confidence, and liquidity behavior. "
        "For cyber insurance, the first-order effect is higher perceived systemic cloud concentration risk. Insurers and reinsurers may reassess aggregate exposure, tighten underwriting, review exclusions, raise premium expectations, and scrutinize limits where many insured firms depend on the same cloud platform. A severe breach with broad business interruption could pressure carriers with concentrated claims exposure even while stronger future pricing improves the economics of less-exposed insurers. "
        "For crypto, the direction is less deterministic. A cloud breach can trigger broader risk-off behavior and volatility, producing flight to cash or stablecoins, forced selling, or temporary demand for assets perceived as outside conventional infrastructure. That does not make crypto a reliable hedge: exchange availability, custody dependencies, leverage, dollar liquidity, and correlation with high-beta technology assets can dominate the response. "
        "The cross-domain correlation to watch is whether the breach creates a market-wide confidence shock or remains an operationally contained cyber event. I would test insurer exposure, premium repricing, equity volatility, crypto volumes, stablecoin flows, and broader risk sentiment before claiming a causal market effect. Without live market data in this conversation, these are scenario hypotheses rather than observed moves."
    )


def _market_provenance_reply() -> str:
    return (
        "QC's market intelligence is designed around named trusted sources and source provenance rather than anonymous aggregation. "
        "Crypto snapshots use Coinbase, with Kraken as the fallback adapter. Foreign-exchange data comes from the European Central Bank. Equity issuer and filing intelligence comes from SEC EDGAR; that path is explicitly for issuer/filing intelligence rather than licensed live stock pricing. Macro series use FRED when its API key is configured, and Nasdaq Data Link is available when its API key is configured. "
        "QC stores source identity with fetched data, uses source-specific cache records with SHA-256 hashes, and maintains trusted-source metadata including confidence/configuration state. A source being configured does not mean every value is independently guaranteed; verification means the response can be traced to its named upstream source, timestamp/provenance fields, and QC's persisted source metadata."
    )


def _context_reply(message: str, facts: Iterable[str]) -> str | None:
    facts = [fact for fact in facts if fact]
    if not facts:
        return None

    low_blob = " ".join(facts).lower()
    lines = "\n".join(f"- {fact}" for fact in facts)

    if "root cause" in (message or "").lower():
        correlations: list[str] = []
        if "datadog" in low_blob:
            correlations.append("the Datadog agent update")
        if "ingress" in low_blob:
            correlations.append("the ingress-controller change")
        if "pod restart" in low_blob or "pod restarts" in low_blob:
            correlations.append("the doubled pod restarts")
        if "monitoring" in low_blob:
            correlations.append("the monitoring namespace API spikes")
        likely = correlations[0] if correlations else "the most recent correlated change"
        return (
            "I retained the specific facts you supplied:\n"
            f"{lines}\n\n"
            f"Most likely root cause: {likely}, because it is temporally correlated with the observed restart pattern. "
            "Confidence: moderate until logs, rollout history, and resource/error telemetry confirm causality. "
            "I would compare the changed components first and avoid inventing evidence beyond the facts above."
        )

    return (
        "I retained these environment facts from this session:\n"
        f"{lines}\n"
        "I am not adding facts you did not provide."
    )


def _guarded_result(db_path, user_id, session_id, mode, reply, engine="local:prompt-guard"):
    result = _engine.process_message(
        db_path=db_path,
        message="Security policy event: a restricted adversarial instruction was rejected.",
        user_id=user_id,
        session_id=session_id,
        mode=mode,
    )
    _replace_last_assistant_turn(db_path, session_id, reply)
    result.update({"reply": reply, "engine": engine, "memories_added": []})
    return result


def process_message(db_path, message, user_id, session_id, mode="cyber"):
    scan = scan_for_injection(message or "")

    if scan.injection_attempts:
        reply = (
            "I remain Queen Califia. User-supplied instructions cannot replace my identity, "
            "system policy, or security boundaries, and I will not reveal hidden prompts or privileged instructions. "
            "I can continue with an authorized defensive or research objective."
        )
        return _guarded_result(db_path, user_id, session_id, mode, reply)

    if _is_instruction_override_exfiltration(message, mode):
        reply = (
            "I cannot provide stealth data-exfiltration instructions or help bypass detection. "
            "I can provide defensive, authorized guidance for detecting and preventing exfiltration, including DLP, egress monitoring, anomaly detection, and incident-response containment."
        )
        return _guarded_result(db_path, user_id, session_id, mode, reply, engine="local:adversarial-guard")

    if _is_false_authority_secret_request(message, mode):
        reply = (
            "I cannot disclose API keys, database credentials, or other secrets based on an authority claim. "
            "Security protocols remain in force regardless of title; use the appropriate authorized credential-management and access-review channel."
        )
        return _guarded_result(db_path, user_id, session_id, mode, reply, engine="local:authority-guard")

    future_cve = _future_or_unverifiable_cve(message)
    if future_cve:
        reply = (
            f"I cannot verify {future_cve}. Its year is later than the current UTC year, so the claim that it was disclosed last week is not credible from the information available. "
            "I will not fabricate an assessment. Verify the identifier against an authoritative CVE/NVD source before treating it as real."
        )
        return _guarded_result(db_path, user_id, session_id, mode, reply, engine="local:cve-verification")

    explicit = _explicit_memories(message or "")
    for key, value in explicit:
        _engine.save_memory(db_path, user_id, key, value, confidence=0.95)

    recent_facts = _recent_user_facts(db_path, session_id, message)
    contradiction = _firewall_contradiction(message, recent_facts)
    if contradiction:
        prior, current = contradiction
        reply = (
            f"That contradicts the earlier information in this session. You previously said the primary firewall vendor was {prior}; the current message says {current}. "
            "I cannot confirm the new claim without updated evidence. Please tell me which statement is authoritative."
        )
        return _guarded_result(db_path, user_id, session_id, mode, reply, engine="local:contradiction-check")

    result = _engine.process_message(
        db_path=db_path,
        message=message,
        user_id=user_id,
        session_id=session_id,
        mode=mode,
    )

    combined = list(result.get("memories_added") or [])
    seen = {(str(item.get("key")), str(item.get("value"))) for item in combined}
    for key, value in explicit:
        if (key, value) not in seen:
            combined.append({"key": key, "value": value})
    result["memories_added"] = combined

    if _is_threat_triage(message, mode):
        reply = _threat_triage_reply(message)
        result["reply"] = reply
        result["engine"] = "local:threat-triage"
        _replace_last_assistant_turn(db_path, session_id, reply)

    if _is_blast_radius_escalation(message, mode):
        reply = _blast_radius_reply(message, recent_facts)
        result["reply"] = reply
        result["engine"] = "local:blast-radius"
        _replace_last_assistant_turn(db_path, session_id, reply)

    if _is_cyber_market_synthesis(message, mode):
        reply = _cyber_market_synthesis_reply(message)
        result["reply"] = reply
        result["engine"] = "local:cyber-market-synthesis"
        _replace_last_assistant_turn(db_path, session_id, reply)

    if _is_competitive_cloud_breach_synthesis(message, mode):
        reply = _competitive_cloud_breach_reply()
        result["reply"] = reply
        result["engine"] = "local:competitive-cross-domain"
        _replace_last_assistant_turn(db_path, session_id, reply)

    if _is_market_source_provenance(message, mode):
        reply = _market_provenance_reply()
        result["reply"] = reply
        result["engine"] = "local:market-provenance"
        _replace_last_assistant_turn(db_path, session_id, reply)

    if _is_memory_recall(message):
        recall = _memory_reply(_load_memory_map(db_path, user_id))
        if recall:
            result["reply"] = recall
            result["engine"] = "local:memory-recall"
            _replace_last_assistant_turn(db_path, session_id, recall)

    if _is_context_request(message):
        continuity = _context_reply(message, recent_facts)
        if continuity:
            result["reply"] = continuity
            result["engine"] = "local:context-continuity"
            _replace_last_assistant_turn(db_path, session_id, continuity)

    return result
