"""Crypto layer for TRACER Sync.

Two independent jobs, never mixed:

1. **Password hashing** (authentication only). Entity and user passwords
   authenticate against the sync service; they are *never* used to encrypt
   data. Hashing is scrypt (stdlib) with a random per-credential salt, stored
   as a self-describing string ``scrypt$N$r$p$<salt_b64>$<hash_b64>`` so the
   Node.js Cloud Function and the Python client/mock verify identically.

2. **Payload encryption** (zero-knowledge). Uses the `age file-encryption
   format <https://age-encryption.org/v1>`_ via ``pyrage`` (Rust bindings to
   the reference ``age`` crate) with its native **SSH recipient** support:

   - a fresh random 128-bit file key is generated per push;
   - the payload is encrypted with ChaCha20-Poly1305 (an AEAD — any
     tampering with the ciphertext makes decryption fail);
   - the file key is *wrapped separately for every registered SSH public
     key*: for ``ssh-ed25519`` recipients age converts the Edwards point to
     X25519 and performs an ECDH key agreement, for ``ssh-rsa`` it uses
     RSAES-OAEP;
   - decryption requires one of the recipients' SSH *private* keys, which
     never leave the developer's machine.

   ``pyrage`` was chosen over a hand-rolled ``cryptography``-based scheme
   because the ed25519→X25519 conversion and header MAC layout are subtle and
   already battle-tested in the age crate; over shelling out to an ``age``
   binary because it removes a runtime system dependency (pyrage ships wheels
   for all major platforms).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from typing import Iterable

import pyrage
from pyrage import ssh as pyrage_ssh

# scrypt parameters: interactive-login strength, mirrored in
# firebase/functions/index.js — change both together.
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16


class CryptoError(Exception):
    """Raised for any encryption/decryption failure (including tampering)."""


# ---------------------------------------------------------------------------
# Password hashing (authentication only — never used for data encryption)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Hash ``password`` with scrypt and a fresh random salt.

    Returns a self-describing string; only this string is ever stored on the
    server (Firestore) — never the password itself.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        base64.b64encode(salt).decode(),
        base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of ``password`` against a stored hash."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# ---------------------------------------------------------------------------
# Hybrid payload encryption (age with SSH recipients)
# ---------------------------------------------------------------------------

def parse_recipient(public_key_line: str):
    """Parse an OpenSSH public-key line into an age recipient.

    Accepts ``ssh-ed25519 AAAA... comment`` and ``ssh-rsa AAAA... comment``.
    """
    line = public_key_line.strip()
    if not line:
        raise CryptoError("empty SSH public key")
    try:
        return pyrage_ssh.Recipient.from_str(line)
    except Exception as exc:  # pyrage raises its own error types
        raise CryptoError(f"unsupported or malformed SSH public key: {exc}") from exc


def load_identity(private_key_bytes: bytes):
    """Load an OpenSSH private key (unencrypted) as an age identity."""
    try:
        return pyrage_ssh.Identity.from_buffer(private_key_bytes)
    except Exception as exc:
        raise CryptoError(
            "could not load SSH private key (is it passphrase-protected? "
            f"TRACER needs an unencrypted key — run `tracer keys setup`): {exc}"
        ) from exc


def encrypt_for_recipients(plaintext: bytes, public_key_lines: Iterable[str]) -> bytes:
    """Encrypt ``plaintext`` so that *any one* of the SSH public keys can decrypt.

    A random symmetric file key encrypts the payload (ChaCha20-Poly1305 AEAD);
    that file key is wrapped once per recipient public key. The server that
    stores the result holds no key material and cannot decrypt.
    """
    recipients = [parse_recipient(line) for line in public_key_lines]
    if not recipients:
        raise CryptoError(
            "no recipient public keys — at least one team member must register "
            "an SSH key (`tracer keys setup`) before data can be pushed"
        )
    try:
        return pyrage.encrypt(plaintext, recipients)
    except Exception as exc:
        raise CryptoError(f"encryption failed: {exc}") from exc


def decrypt_with_identity(ciphertext: bytes, private_key_bytes: bytes) -> bytes:
    """Decrypt an age ciphertext with a local SSH private key.

    Raises :class:`CryptoError` when the key is not a recipient **or** when
    the ciphertext was tampered with (AEAD authentication failure).
    """
    identity = load_identity(private_key_bytes)
    try:
        return pyrage.decrypt(ciphertext, [identity])
    except Exception as exc:
        raise CryptoError(
            f"decryption failed (wrong key, corrupted or tampered data): {exc}"
        ) from exc


def sha256_hex(data: bytes) -> str:
    """Integrity fingerprint recorded alongside each pushed version."""
    return hashlib.sha256(data).hexdigest()


def fingerprint_public_key(public_key_line: str) -> str:
    """Stable short fingerprint of an SSH public key (SHA-256 of the blob)."""
    parts = public_key_line.strip().split()
    if len(parts) < 2:
        raise CryptoError("malformed SSH public key line")
    blob = base64.b64decode(parts[1])
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
