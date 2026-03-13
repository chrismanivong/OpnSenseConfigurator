"""Einfache CLI für einen ersten Smoke-Test gegen OPNsense."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from .client import OPNsenseClient, OPNsenseCredentials
from .models import AliasDefinition

DEFAULT_API_KEY_DIR = "./firewall-keys"
DEFAULT_CONFIG_PATH = "./config.yaml"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OPNsense Alias per API ausrollen")

    parser.add_argument("--url", help="Basis-URL einer einzelnen OPNsense Instanz")
    parser.add_argument(
        "--api-key-dir",
        default=DEFAULT_API_KEY_DIR,
        help=(
            "Verzeichnis mit OPNsense API-Key-Dateien je Firewall "
            f"(Standard: {DEFAULT_API_KEY_DIR}). Dateiformat: 'key=...' und 'secret=...'."
        ),
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"YAML-Konfigurationsdatei für Firewalls und Aliase (Standard: {DEFAULT_CONFIG_PATH})",
    )

    parser.add_argument("--name", help="Alias-Name (Single-Target-Modus)")
    parser.add_argument("--ip", action="append", default=[], help="IP-Eintrag (mehrfach möglich, Single-Target)")
    parser.add_argument("--description", default="", help="Beschreibung für den Alias (Single-Target)")
    return parser.parse_args()


def _single_target_credentials() -> tuple[str, OPNsenseCredentials]:
    key = os.environ.get("OPNSENSE_API_KEY")
    secret = os.environ.get("OPNSENSE_API_SECRET")

    if not key or not secret:
        raise SystemExit("Bitte OPNSENSE_API_KEY und OPNSENSE_API_SECRET setzen.")

    return "single-target", OPNsenseCredentials(key=key, secret=secret)


def _parse_key_file(file_path: Path) -> OPNsenseCredentials:
    values: dict[str, str] = {}
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip().lower()] = value.strip()

    if "key" not in values or "secret" not in values:
        raise SystemExit(f"Datei {file_path.name} ist unvollständig. Erwartet 'key' und 'secret'.")

    return OPNsenseCredentials(key=values["key"], secret=values["secret"])


def _fqdn_from_filename(file_path: Path) -> str:
    stem = file_path.stem
    match = re.match(r"^(?P<fqdn>.+?)_[^_]+_apikey$", stem)
    if match:
        return match.group("fqdn")
    return stem


def _parse_simple_yaml(text: str) -> dict:
    root: dict = {}
    stack: list[tuple[int, dict]] = [(-1, root)]

    for raw_line in text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()
        if ":" not in stripped:
            raise SystemExit(f"Ungültige YAML-Zeile: {stripped}")

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()

        current = stack[-1][1]
        if value == "":
            new_node: dict = {}
            current[key] = new_node
            stack.append((indent, new_node))
        else:
            current[key] = value

    return root


def _load_config(config_file: str) -> dict:
    data = _parse_simple_yaml(Path(config_file).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "configurator" not in data:
        raise SystemExit("Ungültige YAML-Konfiguration: 'configurator' fehlt.")
    return data["configurator"]


def _load_targets_from_directory(
    directory: str,
    firewall_mapping: dict[str, dict],
) -> list[tuple[str, str, OPNsenseCredentials]]:
    key_dir = Path(directory)
    if not key_dir.is_dir():
        raise SystemExit(f"API-Key-Verzeichnis nicht gefunden: {directory}")

    files = sorted(p for p in key_dir.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"Keine API-Key-Dateien in {directory} gefunden.")

    targets: list[tuple[str, str, OPNsenseCredentials]] = []
    for file_path in files:
        fqdn = _fqdn_from_filename(file_path)
        if fqdn not in firewall_mapping or "ip" not in firewall_mapping[fqdn]:
            raise SystemExit(f"Firewall-Mapping für {fqdn} fehlt oder hat keine 'ip'.")

        credentials = _parse_key_file(file_path)
        targets.append((fqdn, f"https://{firewall_mapping[fqdn]['ip']}", credentials))

    return targets


def _aliases_from_config(config: dict) -> list[AliasDefinition]:
    aliases = config.get("aliases", {})
    if not aliases:
        raise SystemExit("Keine Aliase in der YAML-Konfiguration gefunden.")

    result: list[AliasDefinition] = []
    for alias_name, alias_data in aliases.items():
        network = alias_data.get("network") if isinstance(alias_data, dict) else None
        if not network:
            raise SystemExit(f"Alias {alias_name} muss ein Feld 'network' enthalten.")
        result.append(AliasDefinition(name=alias_name, type="network", content=[network]))

    return result


def main() -> None:
    args = parse_args()

    if args.url:
        if not args.name:
            raise SystemExit("Bitte --name im Single-Target-Modus angeben.")
        target_name, credentials = _single_target_credentials()
        targets = [(target_name, args.url, credentials)]
        aliases = [AliasDefinition(name=args.name, content=args.ip, description=args.description)]
    else:
        config = _load_config(args.config)
        firewalls = config.get("firewalls", {})
        if not firewalls:
            raise SystemExit("Keine Firewalls in der YAML-Konfiguration gefunden.")

        targets = _load_targets_from_directory(args.api_key_dir, firewalls)
        aliases = _aliases_from_config(config)

    for target_name, url, credentials in targets:
        client = OPNsenseClient(url, credentials)
        for alias in aliases:
            result = client.upsert_alias(alias)
            print(f"[{target_name}] {alias.name}: {result}")


if __name__ == "__main__":
    main()
