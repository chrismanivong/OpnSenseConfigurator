import pytest

from opnsense_configurator.cli import (
    DEFAULT_API_KEY_DIR,
    DEFAULT_CONFIG_PATH,
    _fqdn_from_filename,
    _aliases_from_config,
    _load_config,
    _load_targets_from_directory,
    _ssl_verify_from_firewall_config,
    _unbound_modules_for_target,
    parse_args,
)


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
