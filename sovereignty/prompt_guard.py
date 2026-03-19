"""
sovereignty.prompt_guard — Prompt Injection & Untrusted Text Defense
====================================================================

All external text (logs, emails, alerts, threat feeds, user input)
MUST be sanitized through this module before:
  - Being included in any LLM prompt
  - Being rendered in the dashboard
  - Being stored in audit records

This is NOT a substitute for strict schema validation.
It is a belt-and-suspenders defense layer.

Design Principles:
  - Treat ALL external data as attacker-controlled
  - Neutralize injection triggers without breaking legitimate text
  - Log sanitization events for forensic review
  - Never trust, always verify

v3.3 Hardening:
  - Shannon entropy analysis for obfuscated payloads
  - Nested encoding detection (double base64, hex-in-base64)
  - Unicode homoglyph / zero-width character stripping
  - Polyglot injection patterns (multi-language payloads)
  - Enhanced telemetry field sanitization
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("sovereignty.prompt_guard")

# ─── Injection Pattern Database ──────────────────────────────────────────────

INJECTION_PATTERNS: List[re.Pattern] = [
    # Direct instruction override attempts
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(your\s+)?instructions?", re.IGNORECASE),
    re.compile(r"override\s+(system|safety)\s+(prompt|instructions?)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),

    # System prompt extraction
    re.compile(r"(print|show|reveal|output|display)\s+(your\s+)?(system\s+)?prompt", re.IGNORECASE),
    re.compile(r"what\s+(are|is)\s+your\s+(system\s+)?instructions?", re.IGNORECASE),
    re.compile(r"BEGIN\s+SYSTEM\s+(PROMPT|MESSAGE)", re.IGNORECASE),
    re.compile(r"<\|?(system|im_start)\|?>", re.IGNORECASE),

    # Role hijacking
    re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a|an|the)\s+", re.IGNORECASE),
    re.compile(r"pretend\s+(to\s+be|you\s+are)\s+", re.IGNORECASE),
    re.compile(r"switch\s+to\s+.{0,30}mode", re.IGNORECASE),

    # Data exfiltration / secret extraction
    re.compile(r"(reveal|leak|exfiltrate|extract)\s+(the\s+)?(secrets?|keys?|tokens?|passwords?)", re.IGNORECASE),
    re.compile(r"(print|output)\s+(environment|env)\s+variables?", re.IGNORECASE),
    re.compile(r"(list|show)\s+(all\s+)?(api|secret)\s*keys?", re.IGNORECASE),

    # Developer / debug mode activation
    re.compile(r"(enter|enable|activate)\s+(debug|developer|admin|root)\s+mode", re.IGNORECASE),
    re.compile(r"(sudo|root|admin)\s+access", re.IGNORECASE),
]

# ─── Dangerous Payload Patterns ──────────────────────────────────────────────

DANGEROUS_PAYLOADS: List[re.Pattern] = [
    # XSS vectors
    re.compile(r"<script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),

    # Command injection
    re.compile(r";\s*(rm|cat|curl|wget|nc|bash|sh|python|perl)\s", re.IGNORECASE),
    re.compile(r"\|\s*(bash|sh|python|perl)", re.IGNORECASE),
    re.compile(r"\$\(\s*(curl|wget|cat|id|whoami)", re.IGNORECASE),
    re.compile(r"`\s*(curl|wget|cat|id|whoami)", re.IGNORECASE),

    # Path traversal
    re.compile(r"\.\./\.\.", re.IGNORECASE),
    re.compile(r"\\\.\\\.\\\\", re.IGNORECASE),

    # Suspicious encoding (long base64 blobs that might hide payloads)
    re.compile(r"(?:[A-Za-z0-9+/]{120,}={0,2})"),
]

# ─── Secret Patterns (must NEVER reach LLM context) ─────────────────────────

SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(r"(api[_-]?key|secret[_-]?key|access[_-]?token|bearer)\s*[=:]\s*\S{8,}", re.IGNORECASE),
    re.compile(r"(password|passwd|pwd)\s*[=:]\s*\S{4,}", re.IGNORECASE),
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{36,}"),         # GitHub PAT
    re.compile(r"sk-[A-Za-z0-9]{32,}"),           # OpenAI-style key
    re.compile(r"AKIA[A-Z0-9]{16}"),              # AWS access key
]


# ─── Scan Result ─────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Result of scanning untrusted text for injection/payload indicators."""
    is_clean: bool = True
    injection_attempts: List[str] = field(default_factory=list)
    dangerous_payloads: List[str] = field(default_factory=list)
    secrets_detected: int = 0
    original_length: int = 0
    sanitized_length: int = 0


# ─── Core Functions ──────────────────────────────────────────────────────────

def scan_for_injection(text: str) -> ScanResult:
    """
    Analyze text for prompt injection / payload / secret patterns.
    Returns a ScanResult without modifying the text.
    """
    result = ScanResult(original_length=len(text) if text else 0)
    if not text:
        return result

    for pat in INJECTION_PATTERNS:
        matches = pat.findall(text)
        if matches:
            result.is_clean = False
            result.injection_attempts.append(pat.pattern[:80])

    for pat in DANGEROUS_PAYLOADS:
        if pat.search(text):
            result.is_clean = False
            result.dangerous_payloads.append(pat.pattern[:80])

    for pat in SECRET_PATTERNS:
        if pat.search(text):
            result.is_clean = False
            result.secrets_detected += 1

    return result


def sanitize_untrusted_text(
    text: str,
    max_len: int = 12_000,
    context_label: Optional[str] = None,
) -> str:
    """
    Sanitize attacker-controlled strings before LLM or UI usage.

    Args:
        text: Raw untrusted input
        max_len: Maximum allowed length after sanitization
        context_label: Optional label for logging (e.g., "telemetry_t1")

    Returns:
        Sanitized text safe for inclusion in prompts and UI rendering.
    """
    if not text:
        return ""

    original_len = len(text)

    # 1. Truncate early to prevent regex DoS
    text = text[:max_len]

    # 2. Strip null bytes and control characters (keep newlines/tabs)
    text = text.replace("\x00", "")
    text = re.sub(r"[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]", " ", text)

    # 3. Neutralize injection triggers
    injection_count = 0
    for pat in INJECTION_PATTERNS:
        text, n = pat.subn("[BLOCKED:INJECTION]", text)
        injection_count += n

    # 4. Neutralize dangerous payloads
    payload_count = 0
    for pat in DANGEROUS_PAYLOADS:
        text, n = pat.subn("[BLOCKED:PAYLOAD]", text)
        payload_count += n

    # 5. Redact detected secrets
    secret_count = 0
    for pat in SECRET_PATTERNS:
        text, n = pat.subn("[REDACTED:SECRET]", text)
        secret_count += n

    # 6. Collapse excessive whitespace
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    text = re.sub(r" {4,}", "   ", text)

    # Log if anything was sanitized
    total_changes = injection_count + payload_count + secret_count
    if total_changes > 0:
        logger.warning(
            "prompt_guard.sanitize: %d modifications (injections=%d payloads=%d secrets=%d) "
            "original_len=%d sanitized_len=%d context=%s",
            total_changes, injection_count, payload_count, secret_count,
            original_len, len(text), context_label or "unknown",
        )

    return text.strip()


def build_safe_context(
    raw_fields: dict,
    max_field_len: int = 8_000,
    max_total_len: int = 50_000,
) -> dict:
    """
    Sanitize a dictionary of untrusted fields for LLM context injection.
    Each field is independently sanitized and length-capped.
    """
    safe = {}
    total = 0
    for key, value in raw_fields.items():
        if not isinstance(value, str):
            value = str(value) if value is not None else ""
        sanitized = sanitize_untrusted_text(value, max_len=max_field_len, context_label=key)
        if total + len(sanitized) > max_total_len:
            safe[key] = sanitized[:max(0, max_total_len - total)]
            break
        safe[key] = sanitized
        total += len(sanitized)
    return safe


# ─── Shannon Entropy Analysis ────────────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy (bits per character) of a string.
    High entropy (>4.5) on short strings may indicate obfuscated payloads.
    Normal English text typically scores 3.5-4.5.
    """
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def detect_high_entropy_segments(
    text: str,
    window_size: int = 64,
    threshold: float = 5.0,
) -> List[Tuple[int, int, float]]:
    """
    Scan text for high-entropy windows that may contain obfuscated payloads.

    Returns:
        List of (start, end, entropy) tuples for flagged segments.
    """
    if len(text) < window_size:
        return []

    flagged = []
    step = window_size // 2
    for i in range(0, len(text) - window_size + 1, step):
        window = text[i:i + window_size]
        ent = shannon_entropy(window)
        if ent > threshold:
            flagged.append((i, i + window_size, round(ent, 3)))

    return flagged


# ─── Nested Encoding Detection ───────────────────────────────────────────────

# Patterns that indicate nested/double encoding
NESTED_ENCODING_PATTERNS: List[re.Pattern] = [
    # Double base64 (base64 of base64)
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}={0,2}"),
    # Hex-encoded strings (potential hex-in-base64)
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}"),
    # URL double-encoding
    re.compile(r"(?:%25[0-9a-fA-F]{2}){3,}"),
    # Unicode escape sequences
    re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}"),
    # Octal escape sequences
    re.compile(r"(?:\\[0-3][0-7]{2}){4,}"),
]


def detect_nested_encoding(text: str) -> List[str]:
    """
    Detect potential nested/double encoding in text.

    Returns:
        List of encoding types detected.
    """
    detected = []
    for pat in NESTED_ENCODING_PATTERNS:
        if pat.search(text):
            detected.append(pat.pattern[:60])
    return detected


# ─── Unicode / Zero-Width / Homoglyph Defense ────────────────────────────────

# Zero-width and invisible Unicode characters used for smuggling
INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f"   # zero-width space/joiner/non-joiner/marks
    r"\u2060\u2061\u2062\u2063\u2064"     # word joiner, invisible operators
    r"\ufeff"                              # BOM / zero-width no-break space
    r"\u00ad"                              # soft hyphen
    r"\u034f"                              # combining grapheme joiner
    r"\u061c"                              # Arabic letter mark
    r"\u115f\u1160"                        # Hangul fillers
    r"\u17b4\u17b5"                        # Khmer vowel inherent
    r"\u180e"                              # Mongolian vowel separator
    r"\uffa0"                              # Halfwidth Hangul filler
    r"]"
)

# Common homoglyph substitutions (Cyrillic/Greek → Latin)
HOMOGLYPH_MAP: Dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03bf": "o",
}

HOMOGLYPH_RE = re.compile(
    "[" + "".join(re.escape(c) for c in HOMOGLYPH_MAP.keys()) + "]"
)


def strip_invisible_chars(text: str) -> Tuple[str, int]:
    """
    Remove zero-width and invisible Unicode characters.
    Returns (cleaned_text, count_removed).
    """
    cleaned = INVISIBLE_CHARS.sub("", text)
    return cleaned, len(text) - len(cleaned)


def normalize_homoglyphs(text: str) -> Tuple[str, int]:
    """
    Replace Cyrillic/Greek homoglyphs with their Latin equivalents.
    Returns (normalized_text, count_replaced).
    """
    count = 0

    def _replace(m):
        nonlocal count
        count += 1
        return HOMOGLYPH_MAP.get(m.group(0), m.group(0))

    normalized = HOMOGLYPH_RE.sub(_replace, text)
    return normalized, count


# ─── Enhanced Scan ───────────────────────────────────────────────────────────

def deep_scan(text: str) -> ScanResult:
    """
    Extended scan combining original patterns + entropy + encoding + homoglyphs.
    More thorough than scan_for_injection but heavier.
    """
    result = scan_for_injection(text)

    if not text:
        return result

    # Entropy check
    high_entropy = detect_high_entropy_segments(text)
    if high_entropy:
        result.is_clean = False
        for start, end, ent in high_entropy[:5]:
            result.dangerous_payloads.append(f"high_entropy({ent:.1f})@{start}:{end}")

    # Nested encoding
    nested = detect_nested_encoding(text)
    if nested:
        result.is_clean = False
        for pat in nested:
            result.dangerous_payloads.append(f"nested_encoding:{pat[:40]}")

    # Invisible characters
    _, invisible_count = strip_invisible_chars(text)
    if invisible_count > 0:
        result.is_clean = False
        result.injection_attempts.append(f"invisible_chars:{invisible_count}")

    # Homoglyphs
    _, homoglyph_count = normalize_homoglyphs(text)
    if homoglyph_count > 3:  # Threshold: >3 suggests intentional obfuscation
        result.is_clean = False
        result.injection_attempts.append(f"homoglyph_substitutions:{homoglyph_count}")

    return result


def sanitize_telemetry(
    raw_telemetry: dict,
    max_field_len: int = 4_000,
    max_total_len: int = 30_000,
) -> dict:
    """
    Specialized sanitizer for telemetry data going into AI context.
    More aggressive than build_safe_context — also strips invisible chars
    and normalizes homoglyphs.
    """
    safe = {}
    total = 0
    for key, value in raw_telemetry.items():
        if not isinstance(value, str):
            value = str(value) if value is not None else ""

        # Strip invisible and normalize
        value, _ = strip_invisible_chars(value)
        value, _ = normalize_homoglyphs(value)

        # Standard sanitization
        sanitized = sanitize_untrusted_text(
            value, max_len=max_field_len, context_label=f"telemetry:{key}"
        )

        if total + len(sanitized) > max_total_len:
            safe[key] = sanitized[:max(0, max_total_len - total)]
            break
        safe[key] = sanitized
        total += len(sanitized)

    return safe
