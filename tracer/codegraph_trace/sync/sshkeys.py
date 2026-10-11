"""SSH keypair management for TRACER Sync.

TRACER encrypts sync payloads to SSH public keys. Each developer needs an
ed25519 keypair whose *unencrypted* private key stays on their machine:

- by default TRACER generates a dedicated keypair under
  ``~/.tracer/keys/id_ed25519`` (via ``ssh-keygen``), so the user's personal
  ``~/.ssh`` keys are never touched;
- an existing ``~/.ssh/id_ed25519`` can be reused instead (explicit opt-in
  from the CLI), provided it has no passphrase — age identities must be
  loadable without interactive prompts.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .crypto import CryptoError, fingerprint_public_key


class KeyError_(Exception):
    """SSH key setup problem with a user-actionable message."""


@dataclass
class KeyPair:
    private_path: Path
    public_path: Path

    @property
    def public_key_line(self) -> str:
        return self.public_path.read_text(encoding="utf-8").strip()

    @property
    def private_key_bytes(self) -> bytes:
        return self.private_path.read_bytes()

    @property
    def fingerprint(self) -> str:
        return fingerprint_public_key(self.public_key_line)


def default_key_dir(tracer_home: Path) -> Path:
    return tracer_home / "keys"


def default_key_path(tracer_home: Path) -> Path:
    return default_key_dir(tracer_home) / "id_ed25519"


def find_existing_ssh_keys() -> list[Path]:
    """Candidate reusable keys in ``~/.ssh`` (private paths, pub must exist)."""
    ssh_dir = Path.home() / ".ssh"
    candidates = []
    for name in ("id_ed25519", "id_rsa"):
        priv = ssh_dir / name
        if priv.is_file() and priv.with_suffix(".pub").is_file():
            candidates.append(priv)
    return candidates


def is_passphrase_protected(private_path: Path) -> bool:
    """Best-effort check whether an OpenSSH private key needs a passphrase.

    ``ssh-keygen -y -P ''`` exits non-zero for protected keys without
    prompting, which is exactly the signal we need.
    """
    result = subprocess.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(private_path)],
        capture_output=True,
        text=True,
    )
    return result.returncode != 0


def generate_keypair(private_path: Path, comment: str = "tracer-sync") -> KeyPair:
    """Generate a new unencrypted ed25519 keypair at ``private_path``."""
    private_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        private_path.parent.chmod(0o700)
    except OSError:
        pass
    if private_path.exists():
        raise KeyError_(f"refusing to overwrite existing key at {private_path}")
    result = subprocess.run(
        [
            "ssh-keygen",
            "-t",
            "ed25519",
            "-f",
            str(private_path),
            "-N",
            "",
            "-C",
            comment,
            "-q",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise KeyError_(f"ssh-keygen failed: {result.stderr.strip()}")
    return KeyPair(private_path=private_path, public_path=private_path.with_suffix(".pub"))


def load_keypair(private_path: Path) -> KeyPair:
    """Load an existing keypair, validating both halves exist and are usable."""
    private_path = Path(private_path).expanduser()
    public_path = private_path.with_suffix(".pub")
    if not private_path.is_file():
        raise KeyError_(
            f"SSH private key not found at {private_path} — run `tracer keys setup`"
        )
    if not public_path.is_file():
        raise KeyError_(f"SSH public key not found at {public_path}")
    if is_passphrase_protected(private_path):
        raise KeyError_(
            f"the key at {private_path} is passphrase-protected; TRACER needs an "
            "unencrypted key. Run `tracer keys setup` to generate a dedicated one."
        )
    pair = KeyPair(private_path=private_path, public_path=public_path)
    try:
        pair.fingerprint  # validates the public key parses
    except CryptoError as exc:
        raise KeyError_(str(exc)) from exc
    return pair


def resolve_keypair(tracer_home: Path, configured: Optional[str]) -> KeyPair:
    """Load the configured key, else the default TRACER key."""
    path = Path(configured).expanduser() if configured else default_key_path(tracer_home)
    return load_keypair(path)
