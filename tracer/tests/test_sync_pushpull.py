"""End-to-end push/pull between two simulated devices.

The transport is the in-process reference server (same API contract as the
Firebase Cloud Function); everything else — key generation, archiving,
encryption, decryption, session handling — is the real production code path.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codegraph_trace.sync import sshkeys
from codegraph_trace.sync.client import SyncClient
from codegraph_trace.sync.crypto import CryptoError
from codegraph_trace.sync.mock_transport import MockTransport
from codegraph_trace.sync.state import LocalState
from codegraph_trace.sync.transport import ApiError


class Device:
    """One developer's machine: its own ~/.tracer, keypair and repo checkout."""

    def __init__(self, root: Path, server: MockTransport) -> None:
        self.home = root / ".tracer"
        self.repo = root / "repo"
        self.repo.mkdir(parents=True)
        self.state = LocalState(home=self.home)
        self.client = SyncClient(self.state, server)
        self.keypair = sshkeys.generate_keypair(sshkeys.default_key_path(self.home))

    def write_trace(self, content: str) -> None:
        trace = self.repo / ".codegraph-trace"
        trace.mkdir(exist_ok=True)
        (trace / "trace.db").write_text(content)
        (trace / "snapshots").mkdir(exist_ok=True)
        (trace / "snapshots" / "abc123.json").write_text('{"snapshot": "' + content + '"}')
        artifacts = self.repo / "artifacts"
        artifacts.mkdir(exist_ok=True)
        (artifacts / "review.json").write_text('{"review": "' + content + '"}')

    def read_trace(self) -> str:
        return (self.repo / ".codegraph-trace" / "trace.db").read_text()


@pytest.fixture()
def server() -> MockTransport:
    return MockTransport()


@pytest.fixture()
def alice(tmp_path, server) -> Device:
    dev = Device(tmp_path / "alice", server)
    dev.client.entity_create("EpsilonAI", "entity-pass", "alice", "alice-pass")
    dev.client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    dev.client.register_key(dev.keypair)
    return dev


@pytest.fixture()
def bob(tmp_path, server, alice) -> Device:
    alice.client.add_user("bob", "bob-pass")
    dev = Device(tmp_path / "bob", server)
    dev.client.login("EpsilonAI", "entity-pass", "bob", "bob-pass")
    dev.client.register_key(dev.keypair)
    return dev


def test_push_pull_roundtrip_between_devices(alice, bob):
    alice.write_trace("reasoning step 1: added retry logic")
    result = alice.client.push(alice.repo, message="first sync")
    assert result.version == 1
    assert set(result.recipients) == {"alice", "bob"}

    pulled = bob.client.pull(bob.repo)
    assert pulled.version == 1
    assert pulled.pushed_by == "alice"
    assert pulled.message == "first sync"
    assert bob.read_trace() == "reasoning step 1: added retry logic"
    assert (bob.repo / "artifacts" / "review.json").exists()
    assert (bob.repo / ".codegraph-trace" / "snapshots" / "abc123.json").exists()


def test_updated_push_replaces_latest(alice, bob):
    alice.write_trace("v1")
    alice.client.push(alice.repo)
    bob.client.pull(bob.repo)

    bob.write_trace("v2 — bob's changes")
    result = bob.client.push(bob.repo, base_version=1)
    assert result.version == 2

    alice.client.pull(alice.repo)
    assert alice.read_trace() == "v2 — bob's changes"


def test_pull_specific_older_version(alice, bob):
    alice.write_trace("v1")
    alice.client.push(alice.repo)
    alice.write_trace("v2")
    alice.client.push(alice.repo)

    bob.client.pull(bob.repo, version=1)
    assert bob.read_trace() == "v1"
    bob.client.pull(bob.repo)  # latest
    assert bob.read_trace() == "v2"


def test_stale_push_conflicts_and_force_overrides(alice, bob):
    alice.write_trace("v1")
    alice.client.push(alice.repo)
    bob.client.pull(bob.repo)

    alice.write_trace("v2")
    alice.client.push(alice.repo)

    bob.write_trace("bob's stale work")
    with pytest.raises(ApiError) as exc:
        bob.client.push(bob.repo, base_version=1)
    assert exc.value.code == "version_conflict"
    assert exc.value.status == 409

    result = bob.client.push(bob.repo, base_version=1, force=True)
    assert result.version == 3


def test_server_never_sees_plaintext(alice, bob, server):
    secret = "SECRET-REASONING-c9f2a1"
    alice.write_trace(secret)
    alice.client.push(alice.repo, message="visible metadata is fine")
    for path, blob in server.storage.items():
        assert secret.encode() not in blob, f"plaintext leaked into {path}"
    # metadata holds only fingerprints/hashes, never the payload or passwords
    flat = str(server.entities)
    assert secret not in flat
    assert "entity-pass" not in flat


def test_tampered_blob_at_rest_is_detected(alice, bob, server):
    alice.write_trace("authentic data")
    alice.client.push(alice.repo)

    (path, blob), = server.storage.items()
    tampered = bytearray(blob)
    tampered[len(tampered) // 2] ^= 0xFF
    server.storage[path] = bytes(tampered)

    with pytest.raises(CryptoError) as exc:
        bob.client.pull(bob.repo)
    assert "integrity" in str(exc.value) or "tampered" in str(exc.value)

    # even if the attacker also fixes the recorded sha256, AEAD still refuses
    entity = server.entities["epsilonai"]
    entity["versions"][1]["sha256"] = hashlib.sha256(bytes(tampered)).hexdigest()
    with pytest.raises(CryptoError):
        bob.client.pull(bob.repo)


def test_member_without_registered_key_cannot_decrypt_new_pushes(tmp_path, server, alice):
    alice.client.add_user("carol", "carol-pass")
    carol = Device(tmp_path / "carol", server)
    carol.client.login("EpsilonAI", "entity-pass", "carol", "carol-pass")
    # carol has a keypair locally but never registered it
    alice.write_trace("pre-carol data")
    alice.client.push(alice.repo)
    with pytest.raises(CryptoError):
        carol.client.pull(carol.repo)
    # after registering + a fresh push, carol can decrypt
    carol.client.register_key(carol.keypair)
    alice.client.push(alice.repo)
    pulled = carol.client.pull(carol.repo)
    assert pulled.version == 2


def test_pull_replaces_read_only_files(alice, bob):
    """Pulling over an existing checkout must handle read-only files (.git objects)."""
    alice.write_trace("v1")
    alice.client.push(alice.repo)
    bob.client.pull(bob.repo)
    # simulate a git object file: read-only on disk
    ro = bob.repo / ".codegraph-trace" / "trace.db"
    ro.chmod(0o444)

    alice.write_trace("v2")
    alice.client.push(alice.repo)
    bob.client.pull(bob.repo)  # must not raise PermissionError
    assert bob.read_trace() == "v2"


def test_push_refuses_when_no_keys_registered(tmp_path, server):
    dev = Device(tmp_path / "solo", server)
    dev.client.entity_create("Solo", "ep", "sam", "sp")
    dev.client.login("Solo", "ep", "sam", "sp")
    dev.write_trace("data")
    with pytest.raises(CryptoError) as exc:
        dev.client.push(dev.repo)
    assert "keys setup" in str(exc.value)
