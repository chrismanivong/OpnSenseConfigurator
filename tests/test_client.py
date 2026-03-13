import json

from opnsense_configurator.client import OPNsenseClient, OPNsenseCredentials
from opnsense_configurator.models import AliasDefinition


def test_upsert_alias_calls_expected_endpoint(monkeypatch):
    called = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        @staticmethod
        def read():
            return b'{"result":"ok"}'

    def fake_urlopen(req, timeout, context=None):
        called["req"] = req
        called["timeout"] = timeout
        called["context"] = context
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

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
    assert called["timeout"] == 15
    assert called["req"].method == "POST"
    assert called["req"].full_url == "https://fw.example.local/api/firewall/alias/setItem"

    payload = json.loads(called["req"].data.decode())
    assert payload == {
        "alias": {
            "name": "HQ-Nodes",
            "type": "host",
            "content": "10.0.10.10\n10.0.10.11",
            "description": "Hosts im HQ",
        }
    }


def test_upsert_alias_can_disable_ssl_verification(monkeypatch):
    called = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

        @staticmethod
        def read():
            return b'{"result":"ok"}'

    def fake_urlopen(req, timeout, context=None):
        called["context"] = context
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    client = OPNsenseClient(
        base_url="https://fw.example.local/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
        ssl_verify=False,
    )

    response = client.upsert_alias(AliasDefinition(name="HQ-Nodes", content=["10.0.10.10"]))

    assert response == {"result": "ok"}
    assert called["context"] is not None
    assert called["context"].check_hostname is False
