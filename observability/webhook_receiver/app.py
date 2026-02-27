"""Minimal webhook receiver for Grafana alerting smoke tests.

Validates Authorization header and exposes /last for inspection.
"""

from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional


_LAST: Dict[str, Any] = {"seen": False}


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "QCWebhookReceiver/1.0"

    def _send(self, status: int, body: Any) -> None:
        data = _json_bytes(body)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(200, {"ok": True})
            return
        if self.path == "/last":
            self._send(200, _LAST)
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/webhook":
            self._send(404, {"ok": False, "error": "not_found"})
            return

        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        auth = self.headers.get("Authorization")

        expected = os.environ.get("QC_WEBHOOK_EXPECTED_AUTH", "")
        auth_ok = bool(expected) and (auth == expected)

        global _LAST  # noqa: PLW0603
        _LAST = {
            "seen": True,
            "ts": int(time.time()),
            "auth": auth,
            "expected": expected if os.environ.get("QC_EXPOSE_EXPECTED", "0") == "1" else None,
            "auth_ok": auth_ok,
            "headers": {k: v for k, v in self.headers.items()},
            "body_len": len(body),
        }

        if not auth_ok:
            self._send(401, {"ok": False, "error": "auth_mismatch", "auth_ok": False})
            return

        self._send(200, {"ok": True, "auth_ok": True})

    def log_message(self, fmt: str, *args: Any) -> None:
        # Keep logs minimal; noisy logs reduce signal in CI.
        return


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
