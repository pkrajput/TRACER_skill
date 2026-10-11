"""Entity / user / session logic against the in-process reference server."""

from __future__ import annotations

import pytest

from codegraph_trace.sync.client import SyncClient
from codegraph_trace.sync.mock_transport import MockTransport
from codegraph_trace.sync.state import LocalState, NotLoggedIn
from codegraph_trace.sync.transport import ApiError


@pytest.fixture()
def server() -> MockTransport:
    return MockTransport()


@pytest.fixture()
def state(tmp_path) -> LocalState:
    return LocalState(home=tmp_path / ".tracer")


@pytest.fixture()
def client(server, state) -> SyncClient:
    return SyncClient(state, server)


def _create_entity(client, entity="EpsilonAI"):
    client.entity_create(entity, "entity-pass", "alice", "alice-pass")


def test_entity_create_and_login(client, state):
    _create_entity(client)
    session = client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    assert session.role == "admin"
    assert state.load_session().token == session.token


def test_entity_create_duplicate_rejected(client):
    _create_entity(client)
    with pytest.raises(ApiError) as exc:
        _create_entity(client)
    assert exc.value.code == "entity_exists"
    assert exc.value.status == 409


def test_login_requires_all_four_credentials(client):
    _create_entity(client)
    for entity, epw, user, upw in [
        ("EpsilonAI", "WRONG", "alice", "alice-pass"),  # bad entity password
        ("EpsilonAI", "entity-pass", "alice", "WRONG"),  # bad user password
        ("NoSuchOrg", "entity-pass", "alice", "alice-pass"),  # bad entity
        ("EpsilonAI", "entity-pass", "mallory", "alice-pass"),  # bad user
    ]:
        with pytest.raises(ApiError) as exc:
            client.login(entity, epw, user, upw)
        assert exc.value.code == "bad_credentials"
        assert exc.value.status == 401


def test_server_stores_only_hashes(client, server):
    _create_entity(client)
    entity = server.entities["epsilonai"]
    assert entity["passHash"].startswith("scrypt$")
    assert "entity-pass" not in str(server.entities)
    assert "alice-pass" not in str(server.entities)


def test_admin_can_add_user_and_admin(client, server):
    _create_entity(client)
    client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    client.add_user("bob", "bob-pass", "user")
    client.add_user("carol", "carol-pass", "admin")
    users = server.entities["epsilonai"]["users"]
    assert users["bob"]["role"] == "user"
    assert users["carol"]["role"] == "admin"
    # both can log in with entity + own credentials
    client.login("EpsilonAI", "entity-pass", "bob", "bob-pass")
    client.login("EpsilonAI", "entity-pass", "carol", "carol-pass")


def test_non_admin_cannot_add_users(client):
    _create_entity(client)
    client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    client.add_user("bob", "bob-pass", "user")
    client.login("EpsilonAI", "entity-pass", "bob", "bob-pass")
    with pytest.raises(ApiError) as exc:
        client.add_user("eve", "eve-pass", "admin")
    assert exc.value.code == "forbidden"
    assert exc.value.status == 403


def test_added_admin_can_add_users(client):
    _create_entity(client)
    client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    client.add_user("carol", "carol-pass", "admin")
    client.login("EpsilonAI", "entity-pass", "carol", "carol-pass")
    client.add_user("dave", "dave-pass")  # no exception


def test_duplicate_username_rejected(client):
    _create_entity(client)
    client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    client.add_user("bob", "b1")
    with pytest.raises(ApiError) as exc:
        client.add_user("BOB", "b2")  # case-insensitive
    assert exc.value.code == "user_exists"


def test_logout_revokes_token(client, state, server):
    _create_entity(client)
    session = client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    token = session.token
    client.logout()
    assert state.load_session() is None
    with pytest.raises(ApiError) as exc:
        server.request("GET", "/v1/status", token=token)
    assert exc.value.code == "bad_token"


def test_operations_require_login(client):
    _create_entity(client)
    with pytest.raises(NotLoggedIn):
        client.add_user("bob", "pw")
    with pytest.raises(NotLoggedIn):
        client.status()


def test_status_lists_members(client):
    _create_entity(client)
    client.login("EpsilonAI", "entity-pass", "alice", "alice-pass")
    client.add_user("bob", "bob-pass")
    info = client.status()
    assert info["entity"] == "EpsilonAI"
    assert {m["username"] for m in info["members"]} == {"alice", "bob"}
    assert info["latestVersion"] == 0
