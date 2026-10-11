"""Local state for TRACER Sync: ``~/.tracer/`` (override with ``TRACER_HOME``).

Layout::

    ~/.tracer/
      config.json    # api_base_url, project_id, ssh_key, sync_paths
      session.json   # entity, username, role, token, expires_at
      keys/          # dedicated ed25519 keypair (default)

No plaintext password is ever written here — only the opaque session token
issued by the sync service after a successful login.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# The public artifact does not select a hosted relay. Configure your own service
# with `tracer config --set api_base_url=...` or the TRACER_API_URL env var.
DEFAULT_PROJECT_ID = "demo-tracer"
DEFAULT_API_BASE_URL = ""
EMULATOR_API_BASE_URL = "http://127.0.0.1:5001/demo-tracer/us-central1/api"
# What gets synced, relative to the repo root. ``.codegraph-trace`` holds the
# full development / prompt / reasoning cycle (trace.db, snapshots, chroma);
# ``artifacts`` holds exported review bundles.
DEFAULT_SYNC_PATHS = [".codegraph-trace", "artifacts"]


def tracer_home() -> Path:
    env = os.environ.get("TRACER_HOME")
    return Path(env).expanduser() if env else Path.home() / ".tracer"


@dataclass
class SyncConfig:
    api_base_url: str = DEFAULT_API_BASE_URL
    project_id: str = DEFAULT_PROJECT_ID
    ssh_key: Optional[str] = None  # None -> ~/.tracer/keys/id_ed25519
    sync_paths: list[str] = field(default_factory=lambda: list(DEFAULT_SYNC_PATHS))

    @classmethod
    def from_dict(cls, data: dict) -> "SyncConfig":
        cfg = cls()
        cfg.api_base_url = data.get("api_base_url", cfg.api_base_url)
        cfg.project_id = data.get("project_id", cfg.project_id)
        cfg.ssh_key = data.get("ssh_key", cfg.ssh_key)
        cfg.sync_paths = data.get("sync_paths", cfg.sync_paths)
        return cfg

    def to_dict(self) -> dict:
        return {
            "api_base_url": self.api_base_url,
            "project_id": self.project_id,
            "ssh_key": self.ssh_key,
            "sync_paths": self.sync_paths,
        }


@dataclass
class Session:
    entity: str
    username: str
    role: str
    token: str
    expires_at: str  # ISO-8601 UTC

    def is_expired(self) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        return datetime.now(timezone.utc) >= expiry


class LocalState:
    """Read/write config and session under the TRACER home directory."""

    def __init__(self, home: Optional[Path] = None) -> None:
        self.home = Path(home) if home else tracer_home()

    # -- paths ---------------------------------------------------------
    @property
    def config_path(self) -> Path:
        return self.home / "config.json"

    @property
    def session_path(self) -> Path:
        return self.home / "session.json"

    def ensure_home(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        try:
            self.home.chmod(0o700)
        except OSError:
            pass

    # -- config --------------------------------------------------------
    def load_config(self) -> SyncConfig:
        cfg = SyncConfig()
        if self.config_path.is_file():
            try:
                cfg = SyncConfig.from_dict(json.loads(self.config_path.read_text()))
            except (json.JSONDecodeError, OSError):
                pass
        # Environment overrides make emulator vs production switching trivial.
        env_url = os.environ.get("TRACER_API_URL")
        if env_url:
            cfg.api_base_url = env_url
        return cfg

    def save_config(self, cfg: SyncConfig) -> None:
        self.ensure_home()
        self.config_path.write_text(json.dumps(cfg.to_dict(), indent=2) + "\n")

    # -- session -------------------------------------------------------
    def load_session(self) -> Optional[Session]:
        if not self.session_path.is_file():
            return None
        try:
            data = json.loads(self.session_path.read_text())
            return Session(**data)
        except (json.JSONDecodeError, TypeError, OSError):
            return None

    def save_session(self, session: Session) -> None:
        self.ensure_home()
        payload = {
            "entity": session.entity,
            "username": session.username,
            "role": session.role,
            "token": session.token,
            "expires_at": session.expires_at,
        }
        self.session_path.write_text(json.dumps(payload, indent=2) + "\n")
        try:
            self.session_path.chmod(0o600)
        except OSError:
            pass

    def clear_session(self) -> None:
        try:
            self.session_path.unlink()
        except FileNotFoundError:
            pass

    def require_session(self) -> Session:
        session = self.load_session()
        if session is None:
            raise NotLoggedIn("not logged in — run `tracer login` first")
        if session.is_expired():
            self.clear_session()
            raise NotLoggedIn("session expired — run `tracer login` again")
        return session


class NotLoggedIn(Exception):
    """No valid local session."""
