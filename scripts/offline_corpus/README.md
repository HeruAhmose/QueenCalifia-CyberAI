# Offline learning corpus

Feed these files to `scripts/qc_offline_learning.py` (no network required).

## Formats

**JSON array** — one file, top-level list of records:

```json
[
  {"type": "scan", "payload": { "hosts": [ ... ] }},
  {"type": "incident", "payload": { "mitre_techniques": ["T1059"], ... }}
]
```

**JSONL** — one JSON object per line; each object must include `type` and `payload`.

## Record types

| `type`            | `payload` shape |
|-------------------|-----------------|
| `scan`            | Full scan dict with `hosts[]` (see `sample_scan.json`) — uses `EvolutionEngine.learn_from_scan` |
| `completed_scan`  | Summary scan (e.g. `scan_id`, counts, optional `hosts`) — uses `learn_from_completed_scan` |
| `incident`        | Incident dict — `learn_from_incident` |
| `remediation`     | Plan result with `actions[]` — `learn_from_remediation` |

## Privacy

Do not commit customer exports. Add `offline_corpus/private/` to `.gitignore` if you store real data locally.
