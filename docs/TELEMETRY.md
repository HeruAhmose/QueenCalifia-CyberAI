# Telemetry (Operational)

QueenCalifia-CyberAI ships with **optional**, privacy-conscious operational telemetry to support
advanced prediction tuning and troubleshooting.

Telemetry is **disabled by default**.

## What gets emitted

When enabled, the Zero-Day Predictor emits **summarized** events (no raw payloads by default):

- prediction_count
- max_confidence
- layers_triggered
- asset_id (string you supply)

Events are written as JSON lines (JSONL).

## Enable (recommended: file JSONL)

PowerShell:

```powershell
$env:QC_TELEMETRY_ENABLED = "1"
$env:QC_TELEMETRY_SINK = "file"            # file | stdout
$env:QC_TELEMETRY_FILE = ".telemetry/qc_telemetry.jsonl"
```

Linux/macOS:

```sh
export QC_TELEMETRY_ENABLED=1
export QC_TELEMETRY_SINK=file
export QC_TELEMETRY_FILE=.telemetry/qc_telemetry.jsonl
```

## Sampling

```sh
export QC_TELEMETRY_SAMPLE_RATE=0.25
```

## OpenTelemetry (optional)

If you already use OpenTelemetry, the telemetry layer will *try* to bridge into `core/otel.py`
when OTEL env vars are configured (for example `OTEL_EXPORTER_OTLP_ENDPOINT`).
If the OTEL SDK is not installed, the system continues using JSONL events.

