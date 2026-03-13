"""Einfache CLI für einen ersten Smoke-Test gegen OPNsense."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
from pathlib import Path

from .client import OPNsenseCredentials, create_client
from .models import AliasDefinition

DEFAULT_API_KEY_DIR = "./firewall-keys"
DEFAULT_CONFIG_PATH = "./config.yaml"
DEFAULT_LOG_LEVEL = "INFO"

LOGGER = logging.getLogger(__name__)


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
    parser.add_argument(
        "--log-level",
        default=DEFAULT_LOG_LEVEL,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help=(
            "Log-Level für die Ausgabe (Standard: INFO). "
            "Mögliche Werte: DEBUG, INFO, WARNING, ERROR, CRITICAL."
        ),
    )
    return parser.parse_args()


def configure_logging(log_level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _single_target_credentials() -> tuple[str, OPNsenseCredentials]:
    LOGGER.debug("Lese Single-Target-Zugangsdaten aus Umgebungsvariablen.")
    key = os.environ.get("OPNSENSE_API_KEY")
    secret = os.environ.get("OPNSENSE_API_SECRET")

    if not key or not secret:
        raise SystemExit("Bitte OPNSENSE_API_KEY und OPNSENSE_API_SECRET setzen.")

    return "single-target", OPNsenseCredentials(key=key, secret=secret)


def _parse_key_file(file_path: Path) -> OPNsenseCredentials:
    LOGGER.debug("Lese API-Key-Datei: %s", file_path)
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
    LOGGER.debug("Parse YAML-Konfiguration mit vereinfachtem Parser.")
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
    LOGGER.info("Lade Konfiguration aus %s", config_file)
    data = _parse_simple_yaml(Path(config_file).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "configurator" not in data:
        raise SystemExit("Ungültige YAML-Konfiguration: 'configurator' fehlt.")
    return data["configurator"]


def _to_bool(value: object, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off"}:
            return False
    return default


def _ssl_verify_from_firewall_config(firewall_config: dict) -> bool:
    if not isinstance(firewall_config, dict):
        return True

    if "ssl_verify" in firewall_config:
        return _to_bool(firewall_config["ssl_verify"], default=True)
    if "ssl_verfiy" in firewall_config:
        return _to_bool(firewall_config["ssl_verfiy"], default=True)
    if "ssl" in firewall_config:
        return _to_bool(firewall_config["ssl"], default=True)
    return True


def _load_targets_from_directory(
    directory: str,
    firewall_mapping: dict[str, dict],
) -> list[tuple[str, str, OPNsenseCredentials, bool]]:
    LOGGER.info("Lade Firewall-Targets aus API-Key-Verzeichnis: %s", directory)
    key_dir = Path(directory)
    if not key_dir.is_dir():
        raise SystemExit(f"API-Key-Verzeichnis nicht gefunden: {directory}")

    files = sorted(p for p in key_dir.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"Keine API-Key-Dateien in {directory} gefunden.")

    targets: list[tuple[str, str, OPNsenseCredentials, bool]] = []
    for file_path in files:
        fqdn = _fqdn_from_filename(file_path)
        if fqdn not in firewall_mapping or "ip" not in firewall_mapping[fqdn]:
            raise SystemExit(f"Firewall-Mapping für {fqdn} fehlt oder hat keine 'ip'.")

        credentials = _parse_key_file(file_path)
        firewall_config = firewall_mapping[fqdn]
        LOGGER.debug("Target erkannt: %s (%s)", fqdn, firewall_config["ip"])
        targets.append((fqdn, f"https://{firewall_config['ip']}", credentials, _ssl_verify_from_firewall_config(firewall_config)))

    return targets


def _normalize_firewall_alias_name(fqdn: str) -> str:
    name = re.sub(r"[^A-Za-z0-9]+", "_", fqdn).strip("_")
    if not name:
        return "FIREWALL"
    if name[0].isdigit():
        name = f"FW_{name}"
    return name.upper()


def _aliases_from_config(config: dict) -> list[AliasDefinition]:
    aliases = config.get("aliases", {})
    firewalls = config.get("firewalls", {})

    by_name: dict[str, AliasDefinition] = {}

    if isinstance(aliases, dict):
        for alias_name, alias_data in aliases.items():
            network = alias_data.get("network") if isinstance(alias_data, dict) else None
            if not network:
                raise SystemExit(f"Alias {alias_name} muss ein Feld 'network' enthalten.")
            description = alias_data.get("description") if isinstance(alias_data, dict) else None
            LOGGER.debug("Alias aus Konfiguration geladen: %s -> %s", alias_name, network)
            by_name[str(alias_name)] = AliasDefinition(
                name=str(alias_name),
                type="network",
                content=[str(network)],
                description=str(description) if description else None,
            )

    if isinstance(firewalls, dict):
        for fqdn, firewall_config in firewalls.items():
            ip = firewall_config.get("ip") if isinstance(firewall_config, dict) else None
            if not ip:
                continue
            derived_name = _normalize_firewall_alias_name(str(fqdn))
            if derived_name in by_name:
                LOGGER.debug(
                    "Überspringe abgeleiteten Firewall-Alias %s (bereits explizit definiert).",
                    derived_name,
                )
                continue
            LOGGER.debug("Leite Firewall-Alias ab: %s -> %s", derived_name, ip)
            by_name[derived_name] = AliasDefinition(
                name=derived_name,
                type="host",
                content=[str(ip)],
                description=f"Firewall {fqdn}",
            )

    if not by_name:
        raise SystemExit("Keine Aliase in der YAML-Konfiguration gefunden.")

    return list(by_name.values())


def _split_fqdn(fqdn: str) -> tuple[str, str]:
    if "." not in fqdn:
        raise SystemExit(
            f"Firewall-Name '{fqdn}' ist kein FQDN. Für Unbound Overrides wird ein Name wie 'fw.example.local' benötigt."
        )
    hostname, domain = fqdn.split(".", 1)
    if not hostname or not domain:
        raise SystemExit(
            f"Firewall-Name '{fqdn}' ist ungültig. Für Unbound Overrides wird ein Name wie 'fw.example.local' benötigt."
        )
    return hostname, domain


def _unbound_record_type_for_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SystemExit(f"Firewall-IP '{ip}' ist keine gültige IP-Adresse.") from exc
    return "AAAA" if addr.version == 6 else "A"


def _unbound_modules_for_target(target_fqdn: str, firewalls: dict[str, dict]) -> list[tuple[str, dict]]:
    if target_fqdn not in firewalls or not isinstance(firewalls[target_fqdn], dict):
        raise SystemExit(f"Firewall-Konfiguration für '{target_fqdn}' fehlt.")
    target_ip = firewalls[target_fqdn].get("ip")
    if not target_ip:
        raise SystemExit(f"Firewall '{target_fqdn}' hat keine 'ip' in der Konfiguration.")

    hostname, domain = _split_fqdn(target_fqdn)
    record_type = _unbound_record_type_for_ip(str(target_ip))

    modules: list[tuple[str, dict]] = [
        (
            "unbound_host",
            {
                "hostname": hostname,
                "domain": domain,
                "record_type": record_type,
                "value": str(target_ip),
                "description": f"Firewall {target_fqdn}",
                # OXL's default match_fields includes `prio`, but for A/AAAA
                # records OPNsense typically stores prio as an empty string.
                # That mismatch leads to duplicates on repeated runs.
                "match_fields": ["hostname", "domain", "record_type", "value"],
                "enabled": True,
                "state": "present",
            },
        )
    ]

    domain_to_server: dict[str, str] = {}
    for other_fqdn, other_cfg in firewalls.items():
        if other_fqdn == target_fqdn:
            continue
        if not isinstance(other_cfg, dict):
            continue
        other_ip = other_cfg.get("ip")
        if not other_ip:
            continue

        _, other_domain = _split_fqdn(str(other_fqdn))

        # Skip our own domain; Unbound will already be authoritative for local data.
        if other_domain == domain:
            continue

        existing = domain_to_server.get(other_domain)
        if existing and existing != str(other_ip):
            raise SystemExit(
                f"Mehrere Firewalls teilen sich die Domain '{other_domain}' (z.B. {existing} und {other_ip}). "
                "Unbound Domain Overrides unterstützen hier nur einen Server; bitte Domain-Zuordnung eindeutig machen."
            )
        domain_to_server[other_domain] = str(other_ip)

    for other_domain, server_ip in sorted(domain_to_server.items()):
        modules.append(
            (
                "unbound_forward",
                {
                    "domain": other_domain,
                    "target": server_ip,
                    "type": "forward",
                    "port": 53,
                    "forward_tcp": False,
                    "description": f"Forward {other_domain} -> {server_ip}",
                    "enabled": True,
                    "state": "present",
                },
            )
        )

    return modules


def main() -> None:
    args = parse_args()
    configure_logging(args.log_level)
    LOGGER.info("Starte OPNsense Configurator mit Log-Level %s", args.log_level)

    if args.url:
        LOGGER.info("Single-Target-Modus aktiv für URL: %s", args.url)
        if not args.name:
            raise SystemExit("Bitte --name im Single-Target-Modus angeben.")
        target_name, credentials = _single_target_credentials()
        targets = [(target_name, args.url, credentials, True)]
        aliases = [AliasDefinition(name=args.name, content=args.ip, description=args.description)]
    else:
        LOGGER.info("Multi-Target-Modus aktiv.")
        config = _load_config(args.config)
        firewalls = config.get("firewalls", {})
        if not firewalls:
            raise SystemExit("Keine Firewalls in der YAML-Konfiguration gefunden.")

        targets = _load_targets_from_directory(args.api_key_dir, firewalls)
        aliases = _aliases_from_config(config)

    for target_name, url, credentials, ssl_verify in targets:
        LOGGER.info("Verbinde mich gleich zur OPNsense API unter %s (%s)", url, target_name)
        client = create_client(url, credentials, ssl_verify=ssl_verify)

        if not args.url:
            for module_name, params in _unbound_modules_for_target(target_name, firewalls):
                LOGGER.debug("Rolle Unbound '%s' auf '%s' aus", module_name, target_name)
                response = client.run_module(module_name, params=params)
                if response.get("error"):
                    raise SystemExit(f"[{target_name}] {module_name}: {response['error']}")
                print(f"[{target_name}] {module_name}: {response['result']}")

        for alias in aliases:
            LOGGER.debug("Rolle Alias '%s' auf '%s' aus", alias.name, target_name)
            response = client.run_module(
                "alias",
                params={
                    "name": alias.name,
                    "type": alias.type,
                    "content": list(alias.content),
                    "description": alias.description or "",
                    "state": "present",
                },
            )
            if response.get("error"):
                raise SystemExit(f"[{target_name}] {alias.name}: {response['error']}")

            print(f"[{target_name}] {alias.name}: {response['result']}")


if __name__ == "__main__":
    main()
