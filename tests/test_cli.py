import pytest

from opnsense_configurator.cli import (
    DEFAULT_API_KEY_DIR,
    DEFAULT_CONFIG_PATH,
    _fqdn_from_filename,
    _aliases_from_config,
    _expand_alias_wildcard,
    _expand_addr_expression,
    _quote_yaml_bang_expressions,
    _load_config,
    _load_targets_from_directory,
    _rules_from_config,
    _resolve_rule_interfaces,
    _ssl_verify_from_firewall_config,
    _unbound_modules_for_target,
    parse_args,
)


class _DummyResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class _DummySession:
    def __init__(self, payload_by_path: dict[str, object]):
        self._payload_by_path = payload_by_path

    def get(self, path: str):
        if path not in self._payload_by_path:
            raise AssertionError(f"Unexpected GET {path}")
        return _DummyResponse(self._payload_by_path[path])


class _DummyClient:
    def __init__(self, payload_by_path: dict[str, object]):
        self.session = type("S", (), {"s": _DummySession(payload_by_path)})()


def test_parse_args_uses_default_paths_in_multi_mode(monkeypatch):
    monkeypatch.setattr("sys.argv", ["prog"])
    args = parse_args()

    assert args.url is None
    assert args.api_key_dir == DEFAULT_API_KEY_DIR
    assert args.config == DEFAULT_CONFIG_PATH


def test_load_targets_uses_firewall_ip_mapping(tmp_path):
    (tmp_path / "opnsense1.domain.local.txt").write_text("key=key-a\nsecret=secret-a\n", encoding="utf-8")
    firewalls = {"opnsense1.domain.local": {"ip": "10.10.0.1"}}

    targets = _load_targets_from_directory(str(tmp_path), firewalls)

    assert [(name, url, ssl_verify) for name, url, _, ssl_verify in targets] == [
        ("opnsense1.domain.local", "https://10.10.0.1", True),
    ]


def test_load_targets_supports_apikey_suffix_filename(tmp_path):
    (tmp_path / "off-opn-01.office.local_root_apikey.txt").write_text(
        "key=key-a\nsecret=secret-a\n", encoding="utf-8"
    )
    firewalls = {"off-opn-01.office.local": {"ip": "10.10.0.1"}}

    targets = _load_targets_from_directory(str(tmp_path), firewalls)

    assert [(name, url, ssl_verify) for name, url, _, ssl_verify in targets] == [
        ("off-opn-01.office.local", "https://10.10.0.1", True),
    ]


def test_load_targets_requires_firewall_mapping(tmp_path):
    (tmp_path / "opnsense1.domain.local.txt").write_text("key=key-a\nsecret=secret-a\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="Firewall-Mapping"):
        _load_targets_from_directory(str(tmp_path), {})


def test_aliases_from_config_reads_network_aliases():
    aliases = _aliases_from_config(
        {
            "aliases": {
                "management_network": {"network": "10.10.0.0/24"},
            }
        }
    )

    assert len(aliases) == 1
    assert aliases[0].name == "management_network"
    assert aliases[0].type == "network"
    assert aliases[0].content == ["10.10.0.0/24"]


def test_aliases_from_config_adds_firewall_ip_as_host_alias():
    aliases = _aliases_from_config(
        {
            "firewalls": {"off-opn-01.office.local": {"ip": "10.10.0.1"}},
            "aliases": {"management_network": {"network": "10.10.0.0/24"}},
        }
    )

    by_name = {alias.name: alias for alias in aliases}
    assert by_name["OFF_OPN_01_OFFICE_LOCAL"].type == "host"
    assert by_name["OFF_OPN_01_OFFICE_LOCAL"].content == ["10.10.0.1"]


def test_aliases_from_config_allows_only_firewalls_without_explicit_aliases():
    aliases = _aliases_from_config(
        {
            "firewalls": {"opnsense1.domain.local": {"ip": "10.10.0.1"}},
        }
    )

    assert len(aliases) == 1
    assert aliases[0].name == "OPNSENSE1_DOMAIN_LOCAL"
    assert aliases[0].type == "host"
    assert aliases[0].content == ["10.10.0.1"]


def test_load_config_requires_configurator_root(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text("foo: bar\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="configurator"):
        _load_config(str(config_file))


def test_quote_yaml_bang_expressions_makes_yaml_loadable():
    yaml = pytest.importorskip("yaml")
    raw = """
configurator:
  rules:
    items:
      - id: test
        source:
          addr: "*_NET" ! *_GUEST_NET
        destination:
          addr: this_firewall
          port: 53
""".lstrip()

    with pytest.raises(Exception):
        yaml.safe_load(raw)

    fixed = _quote_yaml_bang_expressions(raw)
    loaded = yaml.safe_load(fixed)
    assert loaded["configurator"]["rules"]["items"][0]["source"]["addr"] == "*_NET ! *_GUEST_NET"


def test_fqdn_from_filename_falls_back_to_stem_for_legacy_names(tmp_path):
    file_path = tmp_path / "opnsense1.domain.local.txt"

    assert _fqdn_from_filename(file_path) == "opnsense1.domain.local"


def test_load_targets_disables_ssl_verification_when_ssl_is_false(tmp_path):
    (tmp_path / "off-opn-01.office.local.txt").write_text("key=key-a\nsecret=secret-a\n", encoding="utf-8")
    firewalls = {"off-opn-01.office.local": {"ip": "10.10.0.1", "ssl": "false"}}

    targets = _load_targets_from_directory(str(tmp_path), firewalls)

    assert targets[0][3] is False


def test_ssl_verify_supports_misspelled_ssl_verfiy_key():
    assert _ssl_verify_from_firewall_config({"ssl_verfiy": "false"}) is False


def test_unbound_modules_for_target_sets_local_host_override_and_other_domain_overrides():
    firewalls = {
        "off-opn-01.office.local": {"ip": "10.10.0.1"},
        "home-opn-01.home.local": {"ip": "10.10.20.1"},
        "see-opn-01.see.local": {"ip": "10.10.30.1"},
    }

    modules = _unbound_modules_for_target("off-opn-01.office.local", firewalls)

    assert modules[0][0] == "unbound_host"
    assert modules[0][1]["hostname"] == "off-opn-01"
    assert modules[0][1]["domain"] == "office.local"
    assert modules[0][1]["record_type"] == "A"
    assert modules[0][1]["value"] == "10.10.0.1"
    assert modules[0][1]["match_fields"] == ["hostname", "domain", "record_type", "value"]

    domain_overrides = [m for m in modules if m[0] == "unbound_forward"]
    assert {m[1]["domain"]: m[1]["target"] for m in domain_overrides} == {
        "home.local": "10.10.20.1",
        "see.local": "10.10.30.1",
    }

    for _, params in domain_overrides:
        assert params["type"] == "forward"
        assert params["port"] == 53
        assert params["forward_tcp"] is False


def test_unbound_modules_for_target_raises_on_conflicting_other_domains():
    firewalls = {
        "opn-a.office.local": {"ip": "10.10.0.1"},
        "opn-b.office.local": {"ip": "10.10.0.2"},
        "opn-c.other.local": {"ip": "10.10.9.1"},
    }

    # For target in other.local, office.local would have two possible servers.
    with pytest.raises(SystemExit, match="Mehrere Firewalls teilen sich die Domain 'office\\.local'"):
        _unbound_modules_for_target("opn-c.other.local", firewalls)


def test_unbound_modules_for_target_requires_fqdn():
    firewalls = {"opnsense1": {"ip": "10.10.0.1"}}

    with pytest.raises(SystemExit, match="kein FQDN"):
        _unbound_modules_for_target("opnsense1", firewalls)


def test_expand_alias_wildcard_single_star_is_local_only():
    firewalls = {
        "off-opn-01.office.local": {"ip": "10.10.0.1"},
        "opnsense-eze.eze.local": {"ip": "10.10.40.1"},
    }
    # include derived firewall host alias to ensure prefix inference doesn't
    # incorrectly choose generic tokens like OPNSENSE.
    alias_names = {"OFF_MGMT_NET", "EZE_MGMT_NET", "HOME_MGMT_NET", "OPNSENSE_EZE_EZE_LOCAL"}

    assert _expand_alias_wildcard(
        "*_MGMT_NET",
        target_fqdn="off-opn-01.office.local",
        firewalls=firewalls,
        alias_names=alias_names,
    ) == ["OFF_MGMT_NET"]

    assert _expand_alias_wildcard(
        "*_MGMT_NET",
        target_fqdn="opnsense-eze.eze.local",
        firewalls=firewalls,
        alias_names=alias_names,
    ) == ["EZE_MGMT_NET"]


def test_expand_alias_wildcard_double_star_is_global():
    firewalls = {
        "off-opn-01.office.local": {"ip": "10.10.0.1"},
        "opnsense-eze.eze.local": {"ip": "10.10.40.1"},
    }
    alias_names = {"OFF_MGMT_NET", "EZE_MGMT_NET", "HOME_MGMT_NET"}

    assert _expand_alias_wildcard(
        "**_MGMT_NET",
        target_fqdn="off-opn-01.office.local",
        firewalls=firewalls,
        alias_names=alias_names,
    ) == ["EZE_MGMT_NET", "HOME_MGMT_NET", "OFF_MGMT_NET"]


def test_expand_alias_wildcard_explicit_prefix_is_not_local_only():
    firewalls = {
        "off-opn-01.office.local": {"ip": "10.10.0.1"},
        "opnsense-eze.eze.local": {"ip": "10.10.40.1"},
    }
    alias_names = {
        "OFF_MGMT_NET",
        "OFF_USERS_NET",
        "OFF_GUEST_NET",
        "EZE_MGMT_NET",
    }

    assert _expand_alias_wildcard(
        "OFF_*_NET",
        target_fqdn="opnsense-eze.eze.local",
        firewalls=firewalls,
        alias_names=alias_names,
    ) == ["OFF_GUEST_NET", "OFF_MGMT_NET", "OFF_USERS_NET"]


def test_rules_from_config_expands_wildcards_to_multiple_rules():
    config = {
        "firewalls": {
            "off-opn-01.office.local": {"ip": "10.10.0.1"},
        },
        "rules": {
            "defaults": {"direction": "in", "ip_version": "inet", "protocol": "tcp", "action": "pass"},
            "items": [
                {
                    "id": "allow_gui",
                    "description": "GUI access",
                    "interface": "lan",
                    "source": {"addr": "**_MGMT_NET"},
                    "destination": {"addr": "this_firewall", "port": 443},
                }
            ],
        },
    }

    alias_names = {"OFF_MGMT_NET", "EZE_MGMT_NET"}
    params = _rules_from_config(
        config,
        target_fqdn="off-opn-01.office.local",
        firewalls=config["firewalls"],
        alias_names=alias_names,
    )

    assert len(params) == 2
    assert {p["source_net"] for p in params} == {"OFF_MGMT_NET", "EZE_MGMT_NET"}
    assert all(p["destination_net"] == "OFF_OPN_01_OFFICE_LOCAL" for p in params)
    assert all(p["destination_port"] == "443" or p["destination_port"] == 443 for p in params)
    assert all(p["match_fields"] and "description" in p["match_fields"] for p in params)


def test_expand_addr_expression_supports_exclusion_with_bang():
    firewalls = {
        "off-opn-01.office.local": {"ip": "10.10.0.1"},
    }
    alias_names = {
        "OFF_MGMT_NET",
        "OFF_SERVERS_NET",
        "OFF_USERS_NET",
        "OFF_GUEST_NET",
        "OFF_IOT_NET",
        "OFF_SMARTHOME_NET",
    }

    expanded = _expand_addr_expression(
        "OFF_*_NET ! OFF_GUEST_NET",
        target_fqdn="off-opn-01.office.local",
        firewalls=firewalls,
        alias_names=alias_names,
    )

    assert "OFF_GUEST_NET" not in expanded
    assert set(expanded) == {
        "OFF_MGMT_NET",
        "OFF_SERVERS_NET",
        "OFF_USERS_NET",
        "OFF_IOT_NET",
        "OFF_SMARTHOME_NET",
    }


def test_resolve_rule_interfaces_maps_vlan_device_to_opt_value():
    client = _DummyClient(
        {
            "firewall/filter/getInterfaceList": {
                "interfaces": {
                    "label": "Interfaces",
                    "icon": "",
                    "items": [
                        {"value": "lan", "label": "Mgmt"},
                        {"value": "opt5", "label": "Users"},
                    ],
                },
                "groups": {"label": "Groups", "icon": "", "items": []},
                "floating": {"label": "Floating", "icon": "", "items": []},
                "any": {"label": "Any", "icon": "", "items": []},
            },
            "interfaces/overview/export": [
                {"device": "vlan0030", "description": "Users", "addr4": "10.30.0.1/24"},
            ],
        }
    )

    allowed_values = {"lan", "opt5"}
    label_to_value = {"mgmt": "lan", "users": "opt5"}
    device_to_desc = {"vlan0030": "Users"}

    assert (
        _resolve_rule_interfaces(
            ["lan", "vlan0030"],
            allowed_values=allowed_values,
            label_to_value=label_to_value,
            device_to_desc=device_to_desc,
        )
        == ["lan", "opt5"]
    )


def test_resolve_rule_interfaces_accepts_label_names_case_insensitive():
    allowed_values = {"opt4"}
    label_to_value = {"servers": "opt4"}
    device_to_desc = {}

    assert (
        _resolve_rule_interfaces(
            ["servers"],
            allowed_values=allowed_values,
            label_to_value=label_to_value,
            device_to_desc=device_to_desc,
        )
        == ["opt4"]
    )
