from types import SimpleNamespace

import pytest

from opnsense_configurator.client import OPNsenseClient, OPNsenseCredentials
from opnsense_configurator.models import AliasDefinition


def test_upsert_alias_calls_backend_post(monkeypatch):
    calls = {}

    class FakeBackend:
        def __init__(self, **kwargs):
            calls["kwargs"] = kwargs

        def post(self, endpoint, payload):
            calls["endpoint"] = endpoint
            calls["payload"] = payload
            return {"result": "ok"}

    monkeypatch.setattr(
        "importlib.import_module",
        lambda name: SimpleNamespace(OPNsenseClient=FakeBackend) if name == "pyopnsense" else None,
    )

    client = OPNsenseClient(
        base_url="https://fw.example.local/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
    )

    response = client.upsert_alias(
        AliasDefinition(
            name="HQ-Nodes",
            content=["10.0.10.10", "10.0.10.11"],
            description="Hosts im HQ",
        )
    )

    assert response == {"result": "ok"}
    assert calls["endpoint"] == "firewall/alias/setItem"
    assert calls["kwargs"]["base_url"] == "https://fw.example.local"
    assert calls["kwargs"]["api_key"] == "k"
    assert calls["kwargs"]["api_secret"] == "s"
    assert calls["payload"] == {
        "alias": {
            "name": "HQ-Nodes",
            "type": "host",
            "content": "10.0.10.10\n10.0.10.11",
            "description": "Hosts im HQ",
        }
    }


def test_upsert_alias_passes_ssl_verify_to_pyopnsense(monkeypatch):
    calls = {}

    class FakeBackend:
        def __init__(self, **kwargs):
            calls["kwargs"] = kwargs

        def post(self, endpoint, payload):
            return {"result": "ok"}

    monkeypatch.setattr(
        "importlib.import_module",
        lambda name: SimpleNamespace(OPNsenseClient=FakeBackend) if name == "pyopnsense" else None,
    )

    client = OPNsenseClient(
        base_url="https://fw.example.local/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
        ssl_verify=False,
    )

    response = client.upsert_alias(AliasDefinition(name="HQ-Nodes", content=["10.0.10.10"]))

    assert response == {"result": "ok"}
    assert calls["kwargs"]["verify_ssl"] is False


def test_upsert_alias_does_not_duplicate_api_prefix(monkeypatch):
    calls = {}

    class FakeBackend:
        def __init__(self, **kwargs):
            calls["kwargs"] = kwargs

        def post(self, endpoint, payload):
            return {"result": "ok"}

    monkeypatch.setattr(
        "importlib.import_module",
        lambda name: SimpleNamespace(OPNsenseClient=FakeBackend) if name == "pyopnsense" else None,
    )

    client = OPNsenseClient(
        base_url="https://fw.example.local/api/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
    )

    response = client.upsert_alias(AliasDefinition(name="HQ-Nodes", content=["10.0.10.10"]))

    assert response == {"result": "ok"}
    assert calls["kwargs"]["base_url"] == "https://fw.example.local"


def test_client_raises_helpful_error_when_pyopnsense_missing(monkeypatch):
    def fail_import(name):
        raise ModuleNotFoundError(name)

    monkeypatch.setattr("importlib.import_module", fail_import)

    with pytest.raises(RuntimeError, match="pyopnsense ist nicht installiert"):
        OPNsenseClient(
            base_url="https://fw.example.local/",
            credentials=OPNsenseCredentials(key="k", secret="s"),
        )
