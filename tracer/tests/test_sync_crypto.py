"""Crypto layer: scrypt hashing, hybrid encryption round-trips, tampering."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codegraph_trace.sync import crypto


@pytest.fixture(scope="module")
def keypairs(tmp_path_factory) -> list[tuple[bytes, str]]:
    """Three ed25519 keypairs as (private_key_bytes, public_key_line)."""
    base = tmp_path_factory.mktemp("keys")
    pairs = []
    for i in range(3):
        priv = base / f"k{i}"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", str(priv), "-N", "", "-q", "-C", f"dev{i}"],
            check=True,
        )
        pairs.append((priv.read_bytes(), priv.with_suffix(".pub").read_text().strip()))
    return pairs


# -- password hashing (authentication only) ---------------------------------

def test_password_hash_roundtrip():
    stored = crypto.hash_password("hunter2")
    assert stored.startswith("scrypt$16384$8$1$")
    assert crypto.verify_password("hunter2", stored)
    assert not crypto.verify_password("hunter3", stored)


def test_password_hash_is_salted():
    assert crypto.hash_password("same") != crypto.hash_password("same")


def test_verify_rejects_garbage_hashes():
    assert not crypto.verify_password("x", "not-a-hash")
    assert not crypto.verify_password("x", "md5$1$1$1$aaaa$bbbb")
    assert not crypto.verify_password("x", "")


# -- hybrid encryption -------------------------------------------------------

def test_encrypt_decrypt_roundtrip(keypairs):
    priv, pub = keypairs[0]
    ct = crypto.encrypt_for_recipients(b"secret trace data", [pub])
    assert ct != b"secret trace data"
    assert crypto.decrypt_with_identity(ct, priv) == b"secret trace data"


def test_multi_recipient_every_key_unwraps(keypairs):
    payload = b"shared by the whole entity" * 100
    ct = crypto.encrypt_for_recipients(payload, [pub for _, pub in keypairs])
    for priv, _ in keypairs:
        assert crypto.decrypt_with_identity(ct, priv) == payload


def test_non_recipient_cannot_decrypt(keypairs):
    _, pub0 = keypairs[0]
    outsider_priv, _ = keypairs[1]
    ct = crypto.encrypt_for_recipients(b"members only", [pub0])
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_with_identity(ct, outsider_priv)


@pytest.mark.parametrize("offset", [0, 200, -1])
def test_tampered_ciphertext_is_rejected(keypairs, offset):
    priv, pub = keypairs[0]
    ct = bytearray(crypto.encrypt_for_recipients(b"integrity matters" * 50, [pub]))
    ct[offset] ^= 0xFF
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_with_identity(bytes(ct), priv)


def test_truncated_ciphertext_is_rejected(keypairs):
    priv, pub = keypairs[0]
    ct = crypto.encrypt_for_recipients(b"x" * 1000, [pub])
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_with_identity(ct[: len(ct) // 2], priv)


def test_encrypt_requires_at_least_one_recipient():
    with pytest.raises(crypto.CryptoError):
        crypto.encrypt_for_recipients(b"data", [])


def test_malformed_public_key_rejected():
    with pytest.raises(crypto.CryptoError):
        crypto.parse_recipient("ssh-ed25519 not-base64 comment")
    with pytest.raises(crypto.CryptoError):
        crypto.parse_recipient("")


def test_fingerprint_matches_ssh_keygen(keypairs, tmp_path):
    _, pub = keypairs[0]
    pub_file = tmp_path / "k.pub"
    pub_file.write_text(pub + "\n")
    out = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_file)], capture_output=True, text=True, check=True
    )
    assert crypto.fingerprint_public_key(pub) in out.stdout
