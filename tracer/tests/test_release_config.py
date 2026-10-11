"""The public artifact must never silently select a hosted sync relay."""

import pytest

from codegraph_trace.sync.state import LocalState, SyncConfig
from codegraph_trace.sync.transport import HttpTransport, TransportError


def test_unconfigured_sync_stops_before_a_network_request(monkeypatch):
    def unexpected_request(*args, **kwargs):
        pytest.fail("unconfigured sync attempted a network request")

    monkeypatch.setattr("urllib.request.urlopen", unexpected_request)
    with pytest.raises(TransportError, match="No sync relay configured"):
        HttpTransport(SyncConfig().api_base_url).request("GET", "/v1/status")


def test_relay_environment_override_applies_to_saved_config(tmp_path, monkeypatch):
    state = LocalState(tmp_path)
    state.save_config(SyncConfig(api_base_url="https://old.example/api"))
    monkeypatch.setenv("TRACER_API_URL", "http://127.0.0.1:5001/local/api")
    assert state.load_config().api_base_url == "http://127.0.0.1:5001/local/api"
