"""In-process reference implementation of the TRACER Sync API.

Mirrors ``firebase/functions/index.js`` route-for-route and error-for-error,
backed by plain dictionaries instead of Firestore + Cloud Storage. Used by
the test suite (no emulator needed) and usable as an offline demo backend.
Because it exposes the same ``request()`` surface as
:class:`~codegraph_trace.sync.transport.HttpTransport`, the whole client
stack — crypto, payload, CLI — runs unchanged against it.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from .crypto import hash_password, verify_password
from .transport import ApiError

SESSION_TTL = timedelta(hours=12)
_KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa) ")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _fingerprint(line: str) -> str:
    parts = line.strip().split()
    if len(parts) < 2:
        raise ApiError(400, "bad_key", "malformed SSH public key")
    digest = hashlib.sha256(base64.b64decode(parts[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def _entity_id(name: str) -> str:
    eid = re.sub(r"[^a-z0-9_-]+", "-", str(name).strip().lower())
    if not eid:
        raise ApiError(400, "bad_entity", "invalid entity name")
    return eid


class MockTransport:
    """Dictionary-backed TRACER Sync server with the HttpTransport interface."""

    def __init__(self) -> None:
        self.entities: dict[str, dict] = {}
        self.sessions: dict[str, dict] = {}
        self.storage: dict[str, bytes] = {}

    # -- plumbing ---------------------------------------------------------
    def request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[dict] = None,
        token: Optional[str] = None,
        params: Optional[dict] = None,
    ) -> dict:
        route = f"{method} {path.rstrip('/')}"
        body = body or {}
        params = params or {}
        if route == "POST /v1/entity/create":
            return self._entity_create(body)
        if route == "POST /v1/login":
            return self._login(body)
        session = self._require_session(token)
        handlers = {
            "DELETE /v1/session": lambda: self._logout(session),
            "POST /v1/users": lambda: self._add_user(body, session),
            "POST /v1/keys": lambda: self._register_key(body, session),
            "GET /v1/keys": lambda: self._list_keys(session),
            "POST /v1/push": lambda: self._push(body, session),
            "GET /v1/pull": lambda: self._pull(params, session),
            "GET /v1/status": lambda: self._status(session),
        }
        if route not in handlers:
            raise ApiError(404, "no_route", f"unknown route: {route}")
        return handlers[route]()

    def _require_session(self, token: Optional[str]) -> dict:
        if not token:
            raise ApiError(401, "no_token", "missing X-Tracer-Token header")
        session = self.sessions.get(token)
        if session is None:
            raise ApiError(401, "bad_token", "invalid or revoked session token — log in again")
        if session["expiresAt"] < _now():
            del self.sessions[token]
            raise ApiError(401, "expired_token", "session expired — log in again")
        return {"token": token, **session}

    @staticmethod
    def _require_fields(body: dict, fields: list[str]) -> None:
        for f in fields:
            if not isinstance(body.get(f), str) or not body[f].strip():
                raise ApiError(400, "missing_field", f"missing or empty field: {f}")

    # -- routes -------------------------------------------------------------
    def _entity_create(self, body: dict) -> dict:
        self._require_fields(body, ["entity", "entityPassword", "adminUsername", "adminPassword"])
        eid = _entity_id(body["entity"])
        if eid in self.entities:
            raise ApiError(409, "entity_exists", f'entity "{body["entity"]}" already exists')
        admin = body["adminUsername"].strip()
        self.entities[eid] = {
            "name": body["entity"].strip(),
            "passHash": hash_password(body["entityPassword"]),
            "latestVersion": 0,
            "users": {
                admin.lower(): {
                    "username": admin,
                    "passHash": hash_password(body["adminPassword"]),
                    "role": "admin",
                    "keys": [],
                }
            },
            "versions": {},
        }
        return {"ok": True, "entity": body["entity"].strip()}

    def _login(self, body: dict) -> dict:
        self._require_fields(body, ["entity", "entityPassword", "username", "password"])
        deny = ApiError(401, "bad_credentials", "invalid entity or user credentials")
        entity = self.entities.get(_entity_id(body["entity"]))
        if entity is None or not verify_password(body["entityPassword"], entity["passHash"]):
            raise deny
        user = entity["users"].get(body["username"].strip().lower())
        if user is None or not verify_password(body["password"], user["passHash"]):
            raise deny
        token = secrets.token_hex(32)
        expires = _now() + SESSION_TTL
        self.sessions[token] = {
            "entity": _entity_id(body["entity"]),
            "username": user["username"],
            "role": user["role"],
            "expiresAt": expires,
        }
        return {"token": token, "role": user["role"], "expiresAt": _iso(expires)}

    def _logout(self, session: dict) -> dict:
        self.sessions.pop(session["token"], None)
        return {"ok": True}

    def _add_user(self, body: dict, session: dict) -> dict:
        if session["role"] != "admin":
            raise ApiError(403, "forbidden", "only admins can add members")
        self._require_fields(body, ["username", "password"])
        role = "admin" if body.get("role") == "admin" else "user"
        entity = self.entities[session["entity"]]
        key = body["username"].strip().lower()
        if key in entity["users"]:
            raise ApiError(409, "user_exists", f'user "{body["username"]}" already exists')
        entity["users"][key] = {
            "username": body["username"].strip(),
            "passHash": hash_password(body["password"]),
            "role": role,
            "keys": [],
        }
        return {"ok": True, "username": body["username"].strip(), "role": role}

    def _register_key(self, body: dict, session: dict) -> dict:
        self._require_fields(body, ["publicKey"])
        line = body["publicKey"].strip()
        if not _KEY_RE.match(line):
            raise ApiError(
                400, "bad_key", "only ssh-ed25519 and ssh-rsa public keys are supported"
            )
        fingerprint = _fingerprint(line)
        user = self.entities[session["entity"]]["users"][session["username"].lower()]
        user["keys"] = [k for k in user["keys"] if k["fingerprint"] != fingerprint]
        user["keys"].append({"publicKey": line, "fingerprint": fingerprint})
        return {"ok": True, "fingerprint": fingerprint}

    def _list_keys(self, session: dict) -> dict:
        keys = []
        for user in self.entities[session["entity"]]["users"].values():
            for k in user["keys"]:
                keys.append(
                    {
                        "username": user["username"],
                        "publicKey": k["publicKey"],
                        "fingerprint": k["fingerprint"],
                    }
                )
        return {"keys": keys}

    def _push(self, body: dict, session: dict) -> dict:
        self._require_fields(body, ["blob", "sha256"])
        blob = base64.b64decode(body["blob"])
        if hashlib.sha256(blob).hexdigest() != body["sha256"]:
            raise ApiError(400, "bad_digest", "sha256 does not match the uploaded blob")
        entity = self.entities[session["entity"]]
        latest = entity["latestVersion"]
        base = body.get("baseVersion")
        if base is not None and int(base) != latest:
            raise ApiError(
                409,
                "version_conflict",
                f"version conflict: you last synced version {base} but the server "
                f"is at {latest}. Pull first, or push with --force.",
            )
        version = latest + 1
        entity["latestVersion"] = version
        # Content-addressed, mirroring the Cloud Function (blob-first ordering).
        path = f"entities/{session['entity']}/blobs/{body['sha256']}.age"
        self.storage[path] = blob
        entity["versions"][version] = {
            "version": version,
            "pushedBy": session["username"],
            "createdAt": _iso(_now()),
            "size": len(blob),
            "sha256": body["sha256"],
            "message": body.get("message", ""),
            "recipients": body.get("recipients", []),
            "storagePath": path,
        }
        return {"ok": True, "version": version}

    def _pull(self, params: dict, session: dict) -> dict:
        entity = self.entities[session["entity"]]
        latest = entity["latestVersion"]
        requested = int(params.get("version", latest) or 0)
        if requested < 1:
            raise ApiError(404, "no_data", "nothing has been pushed for this entity yet")
        meta = entity["versions"].get(requested)
        if meta is None:
            raise ApiError(404, "no_such_version", f"version {requested} does not exist")
        blob = self.storage[meta["storagePath"]]
        return {
            "version": meta["version"],
            "blob": base64.b64encode(blob).decode(),
            "sha256": meta["sha256"],
            "message": meta["message"],
            "pushedBy": meta["pushedBy"],
            "createdAt": meta["createdAt"],
            "recipients": meta["recipients"],
            "latestVersion": latest,
        }

    def _status(self, session: dict) -> dict:
        entity = self.entities[session["entity"]]
        return {
            "entity": entity["name"],
            "role": session["role"],
            "username": session["username"],
            "members": [
                {
                    "username": u["username"],
                    "role": u["role"],
                    "keyCount": len(u["keys"]),
                }
                for u in entity["users"].values()
            ],
            "latestVersion": entity["latestVersion"],
            "versions": [entity["versions"][n] for n in sorted(entity["versions"])],
        }
