"""
Provisioned contact point smoke test.

Validates that Grafana loaded the provisioned `qc-webhook` contact point and that a test
notification reaches the webhook receiver with the correct Authorization header.

Exit codes:
  0 success
  1 failure
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


# ── Module-level constants (read from env with safe defaults) ──────────────
def _bool_env(val, default: bool = False) -> bool:
    if val is None:
        return default
    s = str(val).strip().lower()
    return s in ("1", "true", "yes", "y", "on")


EXPECTED_CP_NAME: str = os.environ.get("QC_GRAFANA_CONTACTPOINT_NAME", "qc-webhook")
EXPECTED_CP_UID: str = os.environ.get("QC_GRAFANA_CONTACTPOINT_UID", "qc-webhook")
EXPECTED_RECEIVER_UIDS: List[str] = [
    u.strip()
    for u in os.environ.get("QC_GRAFANA_RECEIVER_UIDS", "qc-webhook-1").split(",")
    if u.strip()
]
DIFF_WINDOW: int = int(os.environ.get("QC_SMOKETEST_DIFF_WINDOW", "2"))
UID_CASE_INSENSITIVE: bool = _bool_env(os.environ.get("QC_SMOKETEST_UID_CASE_INSENSITIVE", "0"))
MIN_WEBHOOK_RECEIVERS: int = int(os.environ.get("QC_GRAFANA_MIN_WEBHOOK_RECEIVERS", "1"))
ALLOW_EXTRA_WEBHOOKS: bool = _bool_env(os.environ.get("QC_SMOKETEST_ALLOW_EXTRA_WEBHOOKS", "0"))


def _uid_diff(expected: list[str], observed: list[str], window: int | None = None) -> str:
    """
    Returns a compact diff string for list drift with a small context window.
    """
    if window is None:
        window = DIFF_WINDOW
    n = min(len(expected), len(observed))
    for i in range(n):
        if expected[i] != observed[i]:
            lo = max(0, i - window)
            hi = i + window + 1
            exp_w = expected[lo:hi]
            obs_w = observed[lo:hi]
            return (
                f"first_diff_index={i} expected={expected[i]!r} observed={observed[i]!r} "
                f"context_expected[{lo}:{hi}]={exp_w!r} context_observed[{lo}:{hi}]={obs_w!r}"
            )
    if len(expected) != len(observed):
        i = n
        lo = max(0, i - window)
        hi = i + window + 1
        exp_w = expected[lo:hi]
        obs_w = observed[lo:hi]
        return (
            f"length_mismatch at_index={i} expected_len={len(expected)} observed_len={len(observed)} "
            f"context_expected[{lo}:{hi}]={exp_w!r} context_observed[{lo}:{hi}]={obs_w!r}"
        )
    return "no_diff"


def _env(name: str, default: Optional[str] = None, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise SystemExit(f"missing required env: {name}")
    return str(val)


def _basic_auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _http_json(
    method: str,
    url: str,
    auth: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 10.0,
) -> Tuple[int, Dict[str, str], Any]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, method=method, data=data)
    if auth:
        req.add_header("Authorization", auth)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            txt = raw.decode("utf-8", errors="replace")
            parsed: Any = None
            if txt.strip():
                parsed = json.loads(txt)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, parsed
    except urllib.error.HTTPError as e:
        raw = e.read()
        txt = raw.decode("utf-8", errors="replace")
        parsed: Any = None
        if txt.strip():
            try:
                parsed = json.loads(txt)
            except Exception:
                parsed = txt
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, headers, parsed


def wait_for_grafana_health(base_url: str, auth: str, deadline_s: float = 180.0) -> None:
    end = time.time() + deadline_s
    while time.time() < end:
        status, _, data = _http_json("GET", f"{base_url}/api/health", auth, timeout=5.0)
        if status == 200 and isinstance(data, dict) and data.get("database") in ("ok", "Ok", None):
            return
        time.sleep(2)
    raise SystemExit("grafana not ready")


def get_provisioned_contact_point(base_url: str, auth: str, name: str) -> Dict[str, Any]:
    # Uses the Alerting Provisioning HTTP API.
    # https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/alerting_provisioning/
    url = f"{base_url}/api/v1/provisioning/contact-points?name={urllib.parse.quote(name)}"
    status, _, data = _http_json("GET", url, auth)
    if status != 200 or not isinstance(data, list):
        raise SystemExit(f"failed to list contact points: status={status} data={data}")
    for cp in data:
        if isinstance(cp, dict) and cp.get("name") == name:
            return cp
    raise KeyError(name)


def wait_for_contact_point(base_url: str, auth: str, name: str, deadline_s: float = 180.0) -> Dict[str, Any]:
    end = time.time() + deadline_s
    last_err: Optional[str] = None
    while time.time() < end:
        try:
            return get_provisioned_contact_point(base_url, auth, name)
        except KeyError:
            last_err = "not_found"
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
        time.sleep(2)
    raise SystemExit(f"contact point '{name}' not found (last_err={last_err})")



def assert_contact_point_identity(cp: Dict[str, Any]) -> None:
    name = cp.get("name")
    if name != EXPECTED_CP_NAME:
        raise SystemExit(f"contact point name mismatch: expected={EXPECTED_CP_NAME!r} got={name!r}")

    uid = cp.get("uid") or cp.get("UID")
    if not isinstance(uid, str) or not uid:
        if _bool_env(os.environ.get("QC_SMOKETEST_ALLOW_MISSING_UID", "0"), default=False):
            return
        raise SystemExit("contact point uid missing; set QC_SMOKETEST_ALLOW_MISSING_UID=1 to bypass")
    if uid != EXPECTED_CP_UID:
        raise SystemExit(f"contact point uid mismatch: expected={EXPECTED_CP_UID!r} got={uid!r}")


def extract_contact_point_url(cp: Dict[str, Any]) -> str:
    settings = cp.get("settings") if isinstance(cp.get("settings"), dict) else {}
    if isinstance(settings, dict):
        url = settings.get("url") or settings.get("URL")
        if isinstance(url, str) and url:
            return url

    # Fallback: search common nested shapes (defensive against API schema changes)
    if isinstance(cp.get("receivers"), list):
        for r in cp["receivers"]:
            if not isinstance(r, dict):
                continue
            s = r.get("settings")
            if isinstance(s, dict) and isinstance(s.get("url"), str) and s.get("url"):
                return s["url"]

    raise SystemExit(f"unable to extract webhook url from provisioned contact point: keys={list(cp.keys())}")


def assert_receivers_order_and_type(cp: Dict[str, Any]) -> None:
    receivers = cp.get("receivers")
    if not isinstance(receivers, list) or not receivers:
        raise SystemExit("contact point has no receivers")

    observed: List[str] = []
    for r in receivers:
        if not isinstance(r, dict):
            raise SystemExit("invalid receiver entry (not an object)")

        rtype = r.get("type")
        if rtype != "webhook":
            # Allow future expansion (email/slack/pagerduty, etc.) without breaking drift checks.
            continue

        uid = r.get("uid") or r.get("UID")
        if not isinstance(uid, str) or not uid:
            if _bool_env(os.environ.get("QC_SMOKETEST_ALLOW_MISSING_UID", "0"), default=False):
                # Cannot assert ordering without UIDs.
                return
            raise SystemExit("webhook receiver uid missing; set QC_SMOKETEST_ALLOW_MISSING_UID=1 to bypass")
        observed.append(uid)

    expected_cmp = [u.lower() for u in EXPECTED_RECEIVER_UIDS] if UID_CASE_INSENSITIVE else list(EXPECTED_RECEIVER_UIDS)
    observed_cmp = [u.lower() for u in observed] if UID_CASE_INSENSITIVE else list(observed)

    if len(observed_cmp) < MIN_WEBHOOK_RECEIVERS:
        raise SystemExit(
            f"webhook receiver count too low: min={MIN_WEBHOOK_RECEIVERS} got={len(observed_cmp)}"
        )

    if ALLOW_EXTRA_WEBHOOKS:
        if observed_cmp[: len(expected_cmp)] != expected_cmp:
            raise SystemExit(
                "webhook receiver uid prefix mismatch: "
                + _uid_diff(expected_cmp, observed_cmp[: len(expected_cmp)])
                + f" expected_prefix={expected_cmp!r} observed={observed_cmp!r}"
            )
    else:
        if observed_cmp != expected_cmp:
            raise SystemExit(
                "webhook receiver uid ordering mismatch: "
                + _uid_diff(expected_cmp, observed_cmp)
                + f" expected={expected_cmp!r} observed={observed_cmp!r}"
            )


def extract_receiver_config(cp: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns the first webhook receiver config from the provisioned contact point.
    Grafana provisioning API schemas have varied across versions; this is defensive.
    """
    # Newer shape: top-level has "receivers": [{type, uid, settings, disableResolveMessage, ...}]
    receivers = cp.get("receivers")
    if isinstance(receivers, list):
        for r in receivers:
            if isinstance(r, dict) and (r.get("type") == "webhook" or r.get("type") is None):
                return r

    # Alternate shape: top-level may itself be a receiver-like dict
    if isinstance(cp.get("settings"), dict) and (cp.get("type") == "webhook" or "url" in cp.get("settings", {})):
        return cp

    raise SystemExit("unable to locate webhook receiver config in provisioned contact point")


def _get_setting(settings: Dict[str, Any], *keys: str) -> Optional[Any]:
    for k in keys:
        if k in settings:
            return settings.get(k)
    return None


def assert_receiver_parity(receiver: Dict[str, Any], expected_url: str, bearer_required: bool) -> None:
    settings = receiver.get("settings") if isinstance(receiver.get("settings"), dict) else {}
    if not isinstance(settings, dict):
        settings = {}

    # URL exact match
    url = _get_setting(settings, "url", "URL")
    if url != expected_url:
        raise SystemExit(f"provisioned qc-webhook url mismatch: expected={expected_url!r} got={url!r}")

    # Method parity
    expected_method = _env("QC_ALERT_WEBHOOK_METHOD", "POST").upper()
    actual_method = (_get_setting(settings, "httpMethod", "http_method", "method") or "POST")
    if isinstance(actual_method, str):
        actual_method = actual_method.upper()
    if actual_method != expected_method:
        raise SystemExit(f"qc-webhook http method mismatch: expected={expected_method!r} got={actual_method!r}")

    # Resolve message flag parity
    expected_disable = _bool_env(os.environ.get("QC_ALERT_WEBHOOK_DISABLE_RESOLVE", "0"), default=False)
    actual_disable = bool(receiver.get("disableResolveMessage", False))
    if actual_disable != expected_disable:
        raise SystemExit(
            f"qc-webhook disableResolveMessage mismatch: expected={expected_disable!r} got={actual_disable!r}"
        )

    # Auth scheme parity
    scheme = _get_setting(settings, "authorization_scheme", "authorizationScheme")
    if bearer_required:
        if scheme != "Bearer":
            raise SystemExit(f"contact point missing Bearer auth scheme (found={scheme!r})")
        # Credentials may be redacted; accept either secureFields indicator or a non-empty setting.
        creds = _get_setting(settings, "authorization_credentials", "authorizationCredentials")
        secure = receiver.get("secureFields") or receiver.get("secure_fields") or {}
        if not creds and not (
            isinstance(secure, dict)
            and (
                secure.get("authorization_credentials") is True
                or secure.get("authorizationCredentials") is True
                or secure.get("authorization_credentials")
                or secure.get("authorizationCredentials")
            )
        ):
            raise SystemExit("contact point missing authorization credentials (neither settings nor secureFields indicate presence)")
    else:
        if scheme:
            raise SystemExit(f"unexpected auth scheme present (expected none): {scheme!r}")


def run_receivers_test(base_url: str, auth: str, receiver: Dict[str, Any], bearer_token: str) -> None:
    cp_type = receiver.get("type") or "webhook"
    settings = receiver.get("settings") if isinstance(receiver.get("settings"), dict) else {}
    if not isinstance(settings, dict):
        settings = {}

    scheme = settings.get("authorization_scheme") or settings.get("authorizationScheme")
    if scheme != "Bearer":
        raise SystemExit(f"contact point missing Bearer auth scheme (found={scheme!r})")

    # Grafana may redact credentials in provisioning API output; inject them for the test if needed.
    if "authorization_credentials" not in settings and "authorizationCredentials" not in settings:
        settings["authorization_credentials"] = bearer_token
    else:
        key = "authorization_credentials" if "authorization_credentials" in settings else "authorizationCredentials"
        if not settings.get(key):
            settings[key] = bearer_token

    uid = receiver.get("uid") or "qc-webhook-1"

    payload = {
        "receivers": [
            {
                "name": "qc-webhook",
                "grafana_managed_receiver_configs": [
                    {
                        "uid": uid,
                        "name": "qc-webhook",
                        "type": cp_type,
                        "settings": settings,
                        "disableResolveMessage": bool(receiver.get("disableResolveMessage", False)),
                    }
                ],
            }
        ]
    }

    url = f"{base_url}/api/alertmanager/grafana/config/api/v1/receivers/test"
    status, _, data = _http_json("POST", url, auth, body=payload, timeout=20.0)
    if status != 200:
        raise SystemExit(f"receiver test failed: status={status} data={data}")
    if not (isinstance(data, dict) and data.get("status") == "ok"):
        raise SystemExit(f"receiver test did not return ok: {data}")
def wait_for_webhook_seen(last_url: str, deadline_s: float = 120.0) -> Dict[str, Any]:
    end = time.time() + deadline_s
    while time.time() < end:
        try:
            status, _, data = _http_json("GET", last_url, auth="", timeout=5.0)  # no auth
        except Exception:
            status, data = 0, None

        if status == 200 and isinstance(data, dict) and data.get("seen") is True:
            return data
        time.sleep(1)
    raise SystemExit("webhook was not observed")


def main() -> None:
    base_url = _env("GRAFANA_URL", "http://grafana:3000")
    user = _env("GRAFANA_USER", "admin")
    password = _env("GRAFANA_PASS", "admin")
    bearer = _env("QC_ALERT_WEBHOOK_BEARER_TOKEN", required=True)
    expected_url = _env("QC_ALERT_WEBHOOK_URL", required=True)
    last_url = _env("WEBHOOK_LAST_URL", "http://webhook-receiver:8080/last")

    auth = _basic_auth_header(user, password)

    print("[smoketest] waiting for grafana...")
    wait_for_grafana_health(base_url, auth)

    print("[smoketest] waiting for provisioned contact point...")
    cp = wait_for_contact_point(base_url, auth, EXPECTED_CP_NAME)

    assert_contact_point_identity(cp)

    assert_receivers_order_and_type(cp)

    receiver = extract_receiver_config(cp)

    ruid = receiver.get('uid') or receiver.get('UID')
    if not isinstance(ruid, str) or not ruid:
        if not _bool_env(os.environ.get('QC_SMOKETEST_ALLOW_MISSING_UID', '0'), default=False):
            raise SystemExit('receiver uid missing; set QC_SMOKETEST_ALLOW_MISSING_UID=1 to bypass')
    elif ruid != EXPECTED_RECEIVER_UIDS[0]:
        raise SystemExit(f"receiver uid mismatch: expected={EXPECTED_RECEIVER_UIDS[0]!r} got={ruid!r}")

    assert_receiver_parity(receiver, expected_url, bearer_required=True)

    print("[smoketest] forcing contact point test via receivers/test using provisioned receiver config...")
    run_receivers_test(base_url, auth, receiver, bearer)

    print("[smoketest] verifying webhook receiver observed auth header...")
    last = wait_for_webhook_seen(last_url)
    if last.get("auth_ok") is True:
        print("[smoketest] OK")
        return
    raise SystemExit(f"webhook seen but auth mismatch: {last}")


if __name__ == "__main__":
    main()
