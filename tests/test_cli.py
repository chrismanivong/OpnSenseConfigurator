import pytest

from opnsense_configurator.cli import (
    DEFAULT_API_KEY_DIR,
    DEFAULT_CONFIG_PATH,
    _aliases_from_config,
    _load_config,
    _load_targets_from_directory,
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

    assert [(name, url) for name, url, _ in targets] == [
        ("opnsense1.domain.local", "https://10.10.0.1"),
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
