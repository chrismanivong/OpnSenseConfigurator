import pytest

from opnsense_configurator.cli import (
    DEFAULT_API_KEY_DIR,
    DEFAULT_CONFIG_PATH,
    _fqdn_from_filename,
    _aliases_from_config,
    _load_config,
    _load_targets_from_directory,
    _ssl_verify_from_firewall_config,
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
