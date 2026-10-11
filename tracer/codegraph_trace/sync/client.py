"""High-level TRACER Sync operations, independent of the CLI.

``SyncClient`` glues together local state (``~/.tracer/``), the crypto layer,
the payload archiver and a transport. The transport only ever carries
password strings (for authentication, over TLS in production — the server
stores scrypt hashes) and encrypted age blobs; plaintext trace data and
private keys never pass through it.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import crypto, payload, review, sshkeys
from .state import LocalState, Session, SyncConfig


@dataclass
class PushResult:
    version: int
    size: int
    recipients: list[str]
    sha256: str


@dataclass
class PullResult:
    version: int
    pushed_by: str
    created_at: str
    message: str
    restored_paths: list[str]


class SyncClient:
    def __init__(self, state: LocalState, transport) -> None:
        self.state = state
        self.transport = transport
        self.config: SyncConfig = state.load_config()

    # -- auth ------------------------------------------------------------
    def entity_create(
        self, entity: str, entity_password: str, admin_username: str, admin_password: str
    ) -> None:
        self.transport.request(
            "POST",
            "/v1/entity/create",
            body={
                "entity": entity,
                "entityPassword": entity_password,
                "adminUsername": admin_username,
                "adminPassword": admin_password,
            },
        )

    def login(
        self, entity: str, entity_password: str, username: str, password: str
    ) -> Session:
        resp = self.transport.request(
            "POST",
            "/v1/login",
            body={
                "entity": entity,
                "entityPassword": entity_password,
                "username": username,
                "password": password,
            },
        )
        session = Session(
            entity=entity,
            username=username,
            role=resp["role"],
            token=resp["token"],
            expires_at=resp["expiresAt"],
        )
        self.state.save_session(session)
        return session

    def logout(self) -> None:
        session = self.state.load_session()
        if session is not None:
            try:
                self.transport.request("DELETE", "/v1/session", token=session.token)
            except Exception:
                pass  # best effort — local logout always succeeds
        self.state.clear_session()

    def add_user(self, username: str, password: str, role: str = "user") -> None:
        session = self.state.require_session()
        self.transport.request(
            "POST",
            "/v1/users",
            body={"username": username, "password": password, "role": role},
            token=session.token,
        )

    # -- keys ------------------------------------------------------------
    def register_key(self, keypair: sshkeys.KeyPair) -> str:
        session = self.state.require_session()
        resp = self.transport.request(
            "POST",
            "/v1/keys",
            body={"publicKey": keypair.public_key_line},
            token=session.token,
        )
        return resp.get("fingerprint", keypair.fingerprint)

    def list_keys(self) -> list[dict]:
        session = self.state.require_session()
        resp = self.transport.request("GET", "/v1/keys", token=session.token)
        return resp.get("keys", [])

    # -- data ------------------------------------------------------------
    def push(
        self,
        repo_root: Path,
        *,
        message: str = "",
        base_version: Optional[int] = None,
        force: bool = False,
    ) -> PushResult:
        session = self.state.require_session()
        keys = self.list_keys()
        recipient_lines = [k["publicKey"] for k in keys]
        if not recipient_lines:
            raise crypto.CryptoError(
                "no SSH public keys registered for this entity — run "
                "`tracer keys setup` first (every member who should be able to "
                "pull must register a key before you push)"
            )
        archive = payload.build_archive(
            repo_root,
            self.config.sync_paths,
            pushed_by=session.username,
            entity=session.entity,
            message=message,
        )
        ciphertext = crypto.encrypt_for_recipients(archive, recipient_lines)
        body = {
            "blob": base64.b64encode(ciphertext).decode(),
            "sha256": crypto.sha256_hex(ciphertext),
            "message": message,
            "recipients": [k.get("fingerprint", "") for k in keys],
        }
        if base_version is not None and not force:
            body["baseVersion"] = base_version
        resp = self.transport.request("POST", "/v1/push", body=body, token=session.token)
        return PushResult(
            version=resp["version"],
            size=len(ciphertext),
            recipients=sorted({k["username"] for k in keys}),
            sha256=body["sha256"],
        )

    def pull(
        self,
        repo_root: Path,
        *,
        version: Optional[int] = None,
        keypair: Optional[sshkeys.KeyPair] = None,
    ) -> PullResult:
        session = self.state.require_session()
        if keypair is None:
            keypair = sshkeys.resolve_keypair(self.state.home, self.config.ssh_key)
        params = {"version": version} if version is not None else None
        resp = self.transport.request("GET", "/v1/pull", token=session.token, params=params)
        ciphertext = base64.b64decode(resp["blob"])
        expected = resp.get("sha256")
        if expected and crypto.sha256_hex(ciphertext) != expected:
            raise crypto.CryptoError(
                "integrity check failed: downloaded blob does not match its "
                "recorded SHA-256 (corrupted in transit or tampered at rest)"
            )
        plaintext = crypto.decrypt_with_identity(ciphertext, keypair.private_key_bytes)
        restored = payload.extract_archive(plaintext, repo_root)
        return PullResult(
            version=resp["version"],
            pushed_by=resp.get("pushedBy", "?"),
            created_at=resp.get("createdAt", "?"),
            message=resp.get("message", ""),
            restored_paths=restored,
        )

    def fetch_review_state(self, *, version: Optional[int] = None) -> Optional[dict]:
        """Read the review ledger out of a pushed version without writing to disk.

        The blob is downloaded and decrypted in memory and only
        ``.codegraph-trace/review.json`` is unpacked, so an author can pick up a
        reviewer's verdict without a pull replacing their working tree.
        """
        session = self.state.require_session()
        keypair = sshkeys.resolve_keypair(self.state.home, self.config.ssh_key)
        params = {"version": version} if version is not None else None
        resp = self.transport.request("GET", "/v1/pull", token=session.token, params=params)
        ciphertext = base64.b64decode(resp["blob"])
        plaintext = crypto.decrypt_with_identity(ciphertext, keypair.private_key_bytes)
        raw = payload.read_member(plaintext, review.REVIEW_MEMBER)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def status(self) -> dict:
        session = self.state.require_session()
        return self.transport.request("GET", "/v1/status", token=session.token)
