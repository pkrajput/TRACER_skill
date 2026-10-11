"""HTTP transport to the TRACER Sync service (Firebase Cloud Functions).

One small JSON-over-HTTPS API, identical between the local Firebase emulator
and a deployed project — only the base URL changes. The server never receives
key material or plaintext trace data: pushes carry an already-encrypted age
blob (base64), pulls return it untouched.

API (all JSON; authenticated routes take an ``X-Tracer-Token`` header):

  POST   /v1/entity/create   {entity, entityPassword, adminUsername, adminPassword}
  POST   /v1/login           {entity, entityPassword, username, password} -> {token,…}
  DELETE /v1/session         (logout)
  POST   /v1/users           {username, password, role}          [admin only]
  POST   /v1/keys            {publicKey}
  GET    /v1/keys            -> {keys: [{username, publicKey, fingerprint}]}
  POST   /v1/push            {blob, sha256, message, baseVersion?, recipients}
  GET    /v1/pull[?version=N] -> {version, blob, sha256, …}
  GET    /v1/status          -> {entity, members, latestVersion, versions}
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional


class ApiError(Exception):
    """Server-reported error with HTTP status and machine-readable code."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


class TransportError(Exception):
    """Network-level failure (service unreachable, timeout…)."""


class HttpTransport:
    """Minimal stdlib HTTP client for the sync API."""

    def __init__(self, base_url: str, timeout: float = 60.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[dict] = None,
        token: Optional[str] = None,
        params: Optional[dict] = None,
    ) -> dict[str, Any]:
        if not self.base_url:
            raise TransportError(
                "No sync relay configured. Set TRACER_API_URL or run "
                "'tracer config --set api_base_url=https://your-relay.example/api'. "
                "The public artifact does not provide a hosted sync service."
            )
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            # Deliberately NOT `Authorization: Bearer` — Cloud Run's front end
            # intercepts that header and rejects non-Google tokens with a
            # platform 401 before the function ever runs.
            req.add_header("X-Tracer-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
                err = payload.get("error", {})
                raise ApiError(
                    exc.code,
                    err.get("code", "unknown"),
                    err.get("message", raw.decode(errors="replace")),
                ) from None
            except (json.JSONDecodeError, AttributeError):
                raise ApiError(exc.code, "unknown", raw.decode(errors="replace")) from None
        except urllib.error.URLError as exc:
            raise TransportError(
                f"cannot reach the sync service at {self.base_url} ({exc.reason}). "
                "Is the Firebase emulator running? (see docs/SYNC.md)"
            ) from exc
        try:
            return json.loads(raw) if raw else {}
        except json.JSONDecodeError as exc:
            raise TransportError(f"malformed response from server: {raw[:200]!r}") from exc
