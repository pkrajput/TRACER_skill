"""End-to-end sync test against the real Firebase emulator suite.

Skipped unless ``TRACER_EMULATOR_URL`` points at a running emulator API, e.g.::

    cd firebase && npm --prefix functions install && firebase emulators:start &
    TRACER_EMULATOR_URL=http://127.0.0.1:5001/demo-tracer/us-central1/api pytest tests/test_sync_emulator.py

Exercises the actual Cloud Function (Node scrypt, Firestore, Cloud Storage)
with the production Python client — nothing mocked.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from codegraph_trace.sync import sshkeys
from codegraph_trace.sync.client import SyncClient
from codegraph_trace.sync.state import LocalState
from codegraph_trace.sync.transport import ApiError, HttpTransport, TransportError

EMULATOR_URL = os.environ.get("TRACER_EMULATOR_URL")

pytestmark = pytest.mark.skipif(
    not EMULATOR_URL, reason="TRACER_EMULATOR_URL not set (Firebase emulator not running)"
)


def _device(root: Path):
    home = root / ".tracer"
    repo = root / "repo"
    (repo / ".codegraph-trace").mkdir(parents=True)
    state = LocalState(home=home)
    client = SyncClient(state, HttpTransport(EMULATOR_URL, timeout=120))
    keypair = sshkeys.generate_keypair(sshkeys.default_key_path(home))
    return client, repo, keypair


def test_full_cycle_against_emulator(tmp_path):
    entity = f"e2e-{uuid.uuid4().hex[:8]}"
    alice_client, alice_repo, alice_keys = _device(tmp_path / "alice")
    bob_client, bob_repo, bob_keys = _device(tmp_path / "bob")

    try:
        alice_client.entity_create(entity, "entity-pw", "alice", "alice-pw")
    except TransportError as exc:
        pytest.fail(f"emulator unreachable: {exc}")

    # duplicate entity rejected by the real function
    with pytest.raises(ApiError) as exc:
        alice_client.entity_create(entity, "x", "y", "z")
    assert exc.value.code == "entity_exists"

    alice_client.login(entity, "entity-pw", "alice", "alice-pw")
    alice_client.register_key(alice_keys)
    alice_client.add_user("bob", "bob-pw")

    bob_client.login(entity, "entity-pw", "bob", "bob-pw")
    bob_client.register_key(bob_keys)

    # bad credentials rejected by the real scrypt verification
    with pytest.raises(ApiError):
        bob_client.login(entity, "entity-pw", "bob", "WRONG")

    (alice_repo / ".codegraph-trace" / "trace.db").write_text("emulator e2e payload")
    push = alice_client.push(alice_repo, message="via emulator")
    assert push.version == 1

    pulled = bob_client.pull(bob_repo)
    assert pulled.version == 1
    assert pulled.pushed_by == "alice"
    assert (bob_repo / ".codegraph-trace" / "trace.db").read_text() == "emulator e2e payload"

    info = bob_client.status()
    assert info["latestVersion"] == 1
    assert {m["username"] for m in info["members"]} == {"alice", "bob"}

    # second push replaces latest
    (alice_repo / ".codegraph-trace" / "trace.db").write_text("v2")
    assert alice_client.push(alice_repo).version == 2
    assert bob_client.pull(bob_repo).version == 2
