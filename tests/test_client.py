import base64
import importlib

import opnsense_configurator.client as client_module
from opnsense_configurator.client import OPNsenseCredentials, create_client


class _FakeOXLClient:
    def __init__(self, **kwargs):
        self.init_kwargs = kwargs
        self.calls: list[tuple[str, dict]] = []

    def run_module(self, name: str, params: dict, check_mode: bool = False, exit_help: bool = False):
        self.calls.append((name, params))
        return {"error": None, "result": {"changed": True, "module": name, "params": params}}


class _FakeHTTPXResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeHTTPXClient:
    def __init__(self, status_by_path: dict[str, int], **kwargs):
        self._status_by_path = status_by_path
        self.init_kwargs = kwargs

    def post(self, url: str, json=None):
        return _FakeHTTPXResponse(self._status_by_path.get(url, 404))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_create_client_builds_oxl_client_and_allows_run_module(monkeypatch):
    fake_client: _FakeOXLClient | None = None
    alias_mod = None

    def fake_httpx_client(**kwargs):
        # set_item missing, set exists
        return _FakeHTTPXClient(
            {
                "/api/firewall/alias/set_item/00000000-0000-0000-0000-000000000000": 404,
                "/api/firewall/alias/set/00000000-0000-0000-0000-000000000000": 200,
            },
            **kwargs,
        )

    monkeypatch.setattr(client_module.httpx, "Client", fake_httpx_client)

    def fake_import(name: str):
        nonlocal fake_client
        if name == "oxl_opnsense_client":
            class Mod:
                @staticmethod
                def Client(**kwargs):
                    nonlocal fake_client
                    fake_client = _FakeOXLClient(**kwargs)
                    return fake_client

            return Mod

        if name == "oxl_opnsense_client.plugins.module_utils.main.alias":
            class Alias:
                CMDS = {"set": "set_item"}

            nonlocal alias_mod
            alias_mod = type("AliasMod", (), {"Alias": Alias})
            return alias_mod

        raise ModuleNotFoundError(name)

    monkeypatch.setattr(importlib, "import_module", fake_import)

    client = create_client(
        base_url="https://fw.example.local/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
    )

    # auto-detect should have patched set -> set
    assert alias_mod is not None
    assert alias_mod.Alias.CMDS["set"] == "set"

    result = client.run_module(
        "alias",
        params={
            "name": "HQ-Nodes",
            "type": "host",
            "content": ["10.0.10.10", "10.0.10.11"],
            "description": "Hosts im HQ",
            "state": "present",
        },
    )

    assert fake_client is not None
    assert result["result"]["module"] == "alias"
    assert fake_client.calls == [
        (
            "alias",
            {
                "name": "HQ-Nodes",
                "type": "host",
                "content": ["10.0.10.10", "10.0.10.11"],
                "description": "Hosts im HQ",
                "state": "present",
            },
        )
    ]


def test_base_url_parsing_extracts_host_and_port(monkeypatch):
    created: list[_FakeOXLClient] = []
    alias_mod = None

    def fake_httpx_client(**kwargs):
        # set_item exists
        return _FakeHTTPXClient(
            {
                "/api/firewall/alias/set_item/00000000-0000-0000-0000-000000000000": 400,
            },
            **kwargs,
        )

    monkeypatch.setattr(client_module.httpx, "Client", fake_httpx_client)

    def fake_import(name: str):
        if name == "oxl_opnsense_client":
            class Mod:
                @staticmethod
                def Client(**kwargs):
                    created.append(_FakeOXLClient(**kwargs))
                    return created[-1]

            return Mod

        if name == "oxl_opnsense_client.plugins.module_utils.main.alias":
            class Alias:
                CMDS = {"set": "set_item"}

            nonlocal alias_mod
            alias_mod = type("AliasMod", (), {"Alias": Alias})
            return alias_mod

        raise ModuleNotFoundError(name)

    monkeypatch.setattr(importlib, "import_module", fake_import)

    create_client(
        base_url="https://fw.example.local:8443/api/",
        credentials=OPNsenseCredentials(key="k", secret="s"),
        timeout=17,
        ssl_verify=False,
    )

    # If set_item exists, we shouldn't need to import/patch the alias module.
    assert alias_mod is None

    assert len(created) == 1
    assert created[0].init_kwargs["firewall"] == "fw.example.local"
    assert created[0].init_kwargs["port"] == 8443
    assert created[0].init_kwargs["api_timeout"] == 17.0
    assert created[0].init_kwargs["ssl_verify"] is False
