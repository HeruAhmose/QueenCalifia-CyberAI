# Operator file paths and the HTTP trust boundary

Reviewed against `302903d990d4840491f1513b16e01fc96f39b742` after the credential/error-disclosure repairs in PR #184.

## Threat model

HTTP clients, submitted scan targets, feed content and stored user content are untrusted. Deployment configuration and arguments supplied by an operator executing an administration script are trusted configuration. The application does not run these scripts as a privileged service accepting filenames from HTTP callers. Operators may select mounted storage and backup files outside the repository; removing that capability to satisfy a local-input taint heuristic would break supported deployments.

The 33 remaining `py/path-injection` findings trace to `os.environ`, `os.getenv`, `argparse` or `sys.argv`, as listed below. They do not trace to a request path, query parameter, header, JSON body or feed field. Runtime source inspection found no HTTP handler that writes environment variables or passes request dictionaries into these constructors. Rule execution and the local-input threat model remain enabled.

## Reviewed findings

| Alerts | Sink and controlling source | Boundary |
| --- | --- | --- |
| 28, 29, 31, 32 | `core/auth.py`, `backend/core/auth.py`; `QC_API_KEYS_FILE` | File selected by operator; submitted API key is hashed and compared as a credential. |
| 38, 39, 41, 42, 43, 91, 97 | `APIKeyStore` load/persist; `QC_API_KEYS_FILE` passed during application construction | Remote key-generation requests cannot choose the store path. |
| 45, 46, 130 (previously 47) | Readiness audit-directory check; `QC_AUDIT_LOG_FILE` | Public request cannot select the directory; responses no longer expose paths or exception text. |
| 48, 49 | SPKI log read; `QC_SPKI_LOG_FILE` | Authenticated HTTP caller selects only the bounded event count, not the file. |
| 33, 50, 58 | Remediation, incident and vulnerability engine database initialization; `QC_DB_PATH` or constructor configuration | Paths are selected during trusted application composition. |
| 34 | Autonomy-loop initialization; `QC_DB_PATH` passed by `app.py` | Background worker configuration is independent of HTTP data. |
| 35, 36, 37 | Evolution database creation/permissions; `QC_EVOLUTION_DB` | Operator selects local persistence. Backup labels are separately restricted to filename characters and prefixed by the server. |
| 57 | Threat-intelligence database directory; `QC_THREAT_INTEL_DB` / `QC_EVOLUTION_DB` | Feed content and feed URLs do not choose the database location. |
| 54 | Training readiness file check; server settings / `QC_DB_PATH` | Authenticated route takes the path from application settings, never request parameters. |
| 59, 60 | Compliance-evidence file read; `QC_COMPLIANCE_EVIDENCE_FILE` | Evidence file is an operator-configured input; HTTP scan data cannot choose it. |
| 51, 52, 53 | Offline learning corpus and identity database; `argparse` | Local CLI deliberately reads files selected by its invoking operator. |
| 55, 56 | Redis SPKI CLI output; `sys.argv` / `--out` | Local CLI writes the output selected by its invoking operator, with normal OS permissions. |
| 105 | Primary SQLite migration input; `argparse --sqlite` | Local operator selects a source opened read-only; no HTTP entry point. |

## Empirical checks

`tests/test_operator_path_boundaries.py` exercises the boundary rather than merely asserting the presence of validation code:

- Attempts to replace the SPKI filename using query parameters and a header return only events from the configured file.
- A public readiness request cannot redirect or create an audit directory.
- A pathname submitted as an API key is rejected and its file is neither returned nor changed.
- Both migration readers open the exact operator-selected SQLite file, including literal `?`, `#` and `%` in its name; disabling `query_only` still cannot enable writes because the underlying connection uses `mode=ro`.
- Missing migration sources are never created.
- Invalid/nonpositive SPKI limits fail with a controlled 400 response.

The review found and repaired a separate concrete filename bug: interpolating an unescaped filename into a SQLite URI mishandled URI metacharacters. Both migration readers now use `Path.as_uri()` before appending `mode=ro`.

The listed taint paths are false positives under this explicit trust boundary. This disposition must be reopened if an HTTP/job/IPC entry point ever accepts these configuration values from an untrusted caller, if scripts become setuid/privileged wrappers, or if an untrusted actor gains control of deployment configuration. No query exclusions, scanner suppressions, reduced severity thresholds or fabricated check statuses are used.
