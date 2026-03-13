"""Einfache CLI für einen ersten Smoke-Test gegen OPNsense."""

from __future__ import annotations

import argparse
import ipaddress
import fnmatch
import logging
import os
import re
import socket
from pathlib import Path

from .client import OPNsenseCredentials, create_client
from .models import AliasDefinition

DEFAULT_API_KEY_DIR = "./firewall-keys"
DEFAULT_CONFIG_PATH = "./config.yaml"
DEFAULT_LOG_LEVEL = "INFO"

LOGGER = logging.getLogger(__name__)


class _TargetUnreachable(RuntimeError):
    pass


def _is_unreachable_message(message: str) -> bool:
    msg = str(message).lower()
    needles = [
        "name or service not known",
        "nodename nor servname provided",
        "temporary failure in name resolution",
        "failed to resolve",
        "getaddrinfo failed",
        "connection refused",
        "connection error",
        "connecterror",
        "connect timeout",
        "read timeout",
        "timed out",
        "timeout",
        "network is unreachable",
        "no route to host",
        "host is unreachable",
        "unreachable",
        "tls",
        "ssl",
        "certificate verify failed",
    ]
    return any(n in msg for n in needles)


def _is_unreachable_exception(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, ConnectionError, socket.gaierror, OSError)):
        msg = str(exc)
        if _is_unreachable_message(msg):
            return True
        # Some OS errors don't carry a friendly message.
        if isinstance(exc, OSError) and getattr(exc, "errno", None) in {101, 110, 111, 113}:
            # 101 ENETUNREACH, 110 ETIMEDOUT, 111 ECONNREFUSED, 113 EHOSTUNREACH
            return True

    # Optional: requests/httpx exceptions if installed.
    try:  # pragma: no cover
        import requests  # type: ignore

        if isinstance(
            exc,
            (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.SSLError,
            ),
        ):
            return True
    except Exception:
        pass

    try:  # pragma: no cover
        import httpx

        if isinstance(
            exc,
            (
                httpx.ConnectError,
                httpx.ConnectTimeout,
                httpx.ReadTimeout,
                httpx.RemoteProtocolError,
                httpx.NetworkError,
                httpx.HTTPError,
            ),
        ):
            # httpx.HTTPError is broad; only treat as unreachable if message suggests it.
            return _is_unreachable_message(str(exc))
    except Exception:
        pass

    return _is_unreachable_message(str(exc))


def _format_module_result(result: object) -> str:
    if isinstance(result, dict) and "changed" in result:
        return "changed" if bool(result.get("changed")) else "ok"
    if result is None:
        return "ok"
    return "ok"


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
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Keep third-party HTTP client noise down: httpx logs every request at INFO.
    # Users typically care about our own INFO output; DEBUG can stay verbose.
    third_party_level = logging.WARNING if level <= logging.INFO else level
    for logger_name in ("httpx", "httpcore"):
        logging.getLogger(logger_name).setLevel(third_party_level)


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


def _quote_yaml_wildcard_scalars(raw: str) -> str:
    """Quote wildcard scalars like *_FOO or **_FOO so PyYAML won't treat them as YAML aliases.

    This is only applied as a recovery path when PyYAML fails with
    "found undefined alias".
    """

    def _quote(match: re.Match[str]) -> str:
        prefix = match.group("prefix")
        value = match.group("value")
        if value.startswith("\"") or value.startswith("'"):
            return match.group(0)
        return f"{prefix}\"{value}\""

    # Examples to fix:
    #   addr: *_MGMT_NET
    #   - **_MGMT_NET
    pattern = re.compile(
        r"(?P<prefix>^\s*(?:-[ ]+)?(?:[^#\n:]+:[ ]+)?)"
        r"(?P<value>\*\*?[^\s#]+)",
        flags=re.MULTILINE,
    )
    return pattern.sub(_quote, raw)


def _quote_yaml_bang_expressions(raw: str) -> str:
    """Quote scalar values containing ' ! ' so YAML won't treat '!' as a tag.

    Example to fix:
        addr: OFF_*_NET ! OFF_GUEST_NET
        addr: "*_NET" ! *_GUEST_NET
    """

    def _fix_line(line: str) -> str:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            return line

        # Preserve comments (naive, but values here don't contain '#').
        value_part, hash_mark, comment_part = line.partition("#")
        if " ! " not in value_part:
            return line

        # Only rewrite when there's a key/value separator or a list item.
        if ":" not in value_part and not stripped.startswith("-"):
            return line

        if ":" in value_part:
            prefix, _, rhs = value_part.partition(":")
            # Keep the ':' and original spacing after it.
            after_colon = rhs
            rhs_stripped = after_colon.strip()
            # If already a single quoted scalar, leave it alone.
            if (rhs_stripped.startswith('"') and rhs_stripped.endswith('"')) or (
                rhs_stripped.startswith("'") and rhs_stripped.endswith("'")
            ):
                return line

            # Remove per-token quotes like "*_NET".
            rhs_clean = re.sub(r'"([^\"]*)"', r"\1", rhs_stripped)
            rhs_clean = re.sub(r"'([^']*)'", r"\1", rhs_clean)
            rhs_clean = rhs_clean.replace('"', '\\"')
            fixed = f"{prefix}: \"{rhs_clean}\""
        else:
            # list item like: - OFF_*_NET ! OFF_GUEST_NET
            indent = line[: len(line) - len(stripped)]
            item = stripped
            if item.startswith("- "):
                item_value = item[2:].strip()
                if (item_value.startswith('"') and item_value.endswith('"')) or (
                    item_value.startswith("'") and item_value.endswith("'")
                ):
                    return line
                item_clean = re.sub(r'"([^\"]*)"', r"\1", item_value)
                item_clean = re.sub(r"'([^']*)'", r"\1", item_clean)
                item_clean = item_clean.replace('"', '\\"')
                fixed = f"{indent}- \"{item_clean}\""
            else:
                return line

        if hash_mark:
            # Keep original comment spacing.
            return f"{fixed}  #{comment_part}"
        return fixed

    return "\n".join(_fix_line(line) for line in raw.splitlines())


def _load_config(config_file: str) -> dict:
    LOGGER.info("Lade Konfiguration aus %s", config_file)
    raw = Path(config_file).read_text(encoding="utf-8")

    data: dict
    try:
        import yaml  # type: ignore

        fixed = raw
        applied_wildcards = False
        applied_bang = False

        while True:
            try:
                loaded = yaml.safe_load(fixed)
                break
            except Exception as exc:  # pragma: no cover
                # Recovery for configs that use wildcard strings like "*_MGMT_NET"
                # without quotes. YAML interprets leading '*' as alias syntax.
                msg = str(exc)
                updated = fixed
                applied_any = False

                if (not applied_wildcards) and "found undefined alias" in msg:
                    LOGGER.warning(
                        "YAML contains unquoted wildcard values (e.g. *_MGMT_NET). "
                        "Auto-quoting those scalars; consider quoting them in config.yaml."
                    )
                    updated = _quote_yaml_wildcard_scalars(updated)
                    applied_wildcards = True
                    applied_any = True

                # '!' inside an unquoted scalar can be parsed as YAML tag syntax.
                if (not applied_bang) and (
                    "found '<tag>'" in msg or "expected <block end>, but found '<tag>'" in msg
                ):
                    LOGGER.warning(
                        "YAML contains addr-expressions with '!'. Auto-quoting those values; "
                        "consider quoting them in config.yaml (e.g. \"OFF_*_NET ! OFF_GUEST_NET\")."
                    )
                    updated = _quote_yaml_bang_expressions(updated)
                    applied_bang = True
                    applied_any = True

                # If we didn't apply anything new, or changes don't affect the input, give up.
                if (not applied_any) or updated == fixed:
                    raise

                fixed = updated
        if not isinstance(loaded, dict):
            raise SystemExit("Ungültige YAML-Konfiguration: Root ist kein Mapping.")
        data = loaded
    except ModuleNotFoundError:
        # Fallback for environments without PyYAML.
        data = _parse_simple_yaml(raw)

    if "configurator" not in data:
        raise SystemExit("Ungültige YAML-Konfiguration: 'configurator' fehlt.")
    if not isinstance(data["configurator"], dict):
        raise SystemExit("Ungültige YAML-Konfiguration: 'configurator' muss ein Mapping sein.")
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


def _local_alias_prefix_for_target(
    target_fqdn: str,
    firewalls: dict[str, dict],
    alias_names: set[str],
) -> str:
    cfg = firewalls.get(target_fqdn, {})
    if isinstance(cfg, dict):
        explicit = cfg.get("alias_prefix") or cfg.get("site")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip().upper()

    hostname, domain = _split_fqdn(target_fqdn)

    alias_prefixes = {
        name.split("_", 1)[0]
        for name in alias_names
        if isinstance(name, str) and "_" in name and name.split("_", 1)[0].isalpha()
    }

    candidates: list[str] = []
    candidates.extend([t for t in re.split(r"[-_]", hostname) if t])
    candidates.extend([t for t in re.split(r"[._-]", domain) if t])

    generic_tokens = {
        "OPNSENSE",
        "FIREWALL",
        "FW",
        "ROUTER",
        "GATEWAY",
        "GW",
    }

    for token in candidates:
        upper = token.upper()
        if upper in generic_tokens:
            continue
        if upper in alias_prefixes:
            return upper

    raise SystemExit(
        f"Konnte keinen lokalen Alias-Prefix für '{target_fqdn}' ableiten. "
        "Lege in configurator.firewalls.<fqdn>.alias_prefix (z.B. OFF/EZE) fest."
    )


def _expand_alias_wildcard(
    raw: str,
    *,
    target_fqdn: str,
    firewalls: dict[str, dict],
    alias_names: set[str],
) -> list[str]:
    if raw.lower() == "any":
        return ["any"]
    if "*" not in raw:
        return [raw]

    is_global = "**" in raw
    # Local-only semantics are only for patterns that *start* with a single '*'
    # (e.g. '*_MGMT_NET'). If the user specifies an explicit prefix like
    # 'OFF_*_NET', we treat it as explicitly scoped and do not filter by the
    # target's local prefix.
    is_local_only = raw.startswith("*") and not raw.startswith("**")
    pattern = raw.replace("**", "*")

    matches = sorted({name for name in alias_names if fnmatch.fnmatchcase(name, pattern)})
    if not matches:
        raise SystemExit(f"Wildcard '{raw}' matched keinen Alias in der Konfiguration.")

    if is_global or not is_local_only:
        return matches

    prefix = _local_alias_prefix_for_target(target_fqdn, firewalls, alias_names)
    local = [m for m in matches if m.startswith(prefix + "_")]
    if not local:
        raise SystemExit(
            f"Wildcard '{raw}' matched keinen lokalen Alias für '{target_fqdn}'. "
            f"(Prefix='{prefix}') Gefundene Matches: {matches}"
        )
    return local


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _expand_addr_expression(
    expr: str,
    *,
    target_fqdn: str,
    firewalls: dict[str, dict],
    alias_names: set[str],
) -> list[str]:
    """Expands addr expressions like:

    - "OFF_*_NET" -> all matching aliases
    - "*_MGMT_NET" -> local-only matching aliases
    - "**_MGMT_NET" -> global matching aliases
    - "OFF_*_NET ! OFF_GUEST_NET" -> include minus exclude

    Notes:
      - Tokens are whitespace-separated.
      - '!' negates the *next* token.
    """

    tokens = [t for t in str(expr).split() if t]
    if not tokens:
        return ["any"]

    include: list[str] = []
    exclude: set[str] = set()
    negate_next = False

    for token in tokens:
        if token == "!":
            negate_next = True
            continue

        expanded = _expand_alias_wildcard(
            token,
            target_fqdn=target_fqdn,
            firewalls=firewalls,
            alias_names=alias_names,
        )

        if negate_next:
            exclude.update(expanded)
            negate_next = False
        else:
            include.extend(expanded)

    if negate_next:
        raise SystemExit(f"Ungültiger addr-Ausdruck '{expr}': '!' ohne folgenden Token.")

    include = _dedupe_preserve_order(include)
    result = [v for v in include if v not in exclude]
    if not result:
        raise SystemExit(f"Addr-Ausdruck '{expr}' ergibt keine Werte nach Ausschlüssen.")
    return result


def _rules_from_config(
    config: dict,
    *,
    target_fqdn: str,
    firewalls: dict[str, dict],
    alias_names: set[str],
) -> list[dict]:
    rules_cfg = config.get("rules")
    if not isinstance(rules_cfg, dict):
        return []

    defaults = rules_cfg.get("defaults", {})
    if not isinstance(defaults, dict):
        defaults = {}

    items = rules_cfg.get("items", [])
    if items is None:
        items = []
    if not isinstance(items, list):
        raise SystemExit("configurator.rules.items muss eine Liste sein.")

    derived_fw_alias = _normalize_firewall_alias_name(target_fqdn)

    expanded: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        # Optional targeting
        apply_to = item.get("apply_to")
        if isinstance(apply_to, dict):
            include = apply_to.get("include")
            exclude = apply_to.get("exclude")
            if isinstance(include, list) and include:
                if not any(fnmatch.fnmatchcase(target_fqdn, str(p)) for p in include):
                    continue
            if isinstance(exclude, list) and exclude:
                if any(fnmatch.fnmatchcase(target_fqdn, str(p)) for p in exclude):
                    continue

        rule_id = str(item.get("id") or "")
        if not rule_id:
            raise SystemExit("Jede Regel braucht ein Feld 'id'.")

        description = str(item.get("description") or "")
        interface = item.get("interface", defaults.get("interface", "lan"))
        if isinstance(interface, str):
            interfaces = [interface]
        elif isinstance(interface, list):
            interfaces = [str(i) for i in interface]
        else:
            raise SystemExit(f"Regel {rule_id}: 'interface' muss String oder Liste sein.")

        action = str(item.get("action", defaults.get("action", "pass")))
        protocol = str(item.get("protocol", defaults.get("protocol", "any")))
        direction = str(item.get("direction", defaults.get("direction", "in")))
        ip_protocol = str(item.get("ip_version", defaults.get("ip_version", "inet")))
        enabled = _to_bool(item.get("enabled", defaults.get("enabled", True)), default=True)
        log_enabled = _to_bool(item.get("log", defaults.get("log", False)), default=False)
        quick = _to_bool(item.get("quick", defaults.get("quick", True)), default=True)

        source = item.get("source", {})
        destination = item.get("destination", {})
        if not isinstance(source, dict) or not isinstance(destination, dict):
            raise SystemExit(f"Regel {rule_id}: 'source' und 'destination' müssen Mappings sein.")

        src_addr_raw = str(source.get("addr", "any"))
        dst_addr_raw = str(destination.get("addr", "any"))
        if dst_addr_raw == "this_firewall":
            dst_addr_raw = derived_fw_alias

        src_ports = str(source.get("port", ""))
        dst_ports = str(destination.get("port", ""))

        src_addrs = _expand_addr_expression(
            src_addr_raw,
            target_fqdn=target_fqdn,
            firewalls=firewalls,
            alias_names=alias_names,
        )
        dst_addrs = _expand_addr_expression(
            dst_addr_raw,
            target_fqdn=target_fqdn,
            firewalls=firewalls,
            alias_names=alias_names,
        )

        for src_addr in src_addrs:
            for dst_addr in dst_addrs:
                suffix = ""
                if len(src_addrs) > 1:
                    suffix += f" src={src_addr}"
                if len(dst_addrs) > 1:
                    suffix += f" dst={dst_addr}"

                expanded.append(
                    {
                        "interface": interfaces,
                        "action": action,
                        "protocol": protocol,
                        "direction": direction,
                        "ip_protocol": ip_protocol,
                        "enabled": enabled,
                        "log": log_enabled,
                        "quick": quick,
                        "source_net": src_addr,
                        "source_port": src_ports,
                        "destination_net": dst_addr,
                        "destination_port": dst_ports,
                        "description": f"{rule_id}: {description}{suffix}".strip(),
                        "match_fields": [
                            "action",
                            "interface",
                            "direction",
                            "ip_protocol",
                            "protocol",
                            "source_net",
                            "source_port",
                            "destination_net",
                            "destination_port",
                            "description",
                        ],
                        "state": "present",
                    }
                )

    # Provide deterministic sequences but do not match on them.
    for i, params in enumerate(expanded, start=1):
        params.setdefault("sequence", 1000 + i)

    return expanded


def _fetch_rule_interface_options(client) -> tuple[set[str], dict[str, str]]:
    """Fetch valid interface option values for firewall filter rules.

    Returns:
        (allowed_values, label_to_value)
    """

    def norm_label(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    r = client.session.s.get("firewall/filter/getInterfaceList")
    data = r.json()
    if not isinstance(data, dict):
        raise SystemExit("Konnte Interface-Liste von OPNsense nicht lesen (unerwartetes Format).")

    items: list[tuple[str, str]] = []
    for section in ("interfaces", "groups", "floating", "any"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        block_items = block.get("items", [])
        if not isinstance(block_items, list):
            continue
        for it in block_items:
            if not isinstance(it, dict):
                continue
            value = it.get("value")
            label = it.get("label")
            if value in (None, "") or label in (None, ""):
                continue
            items.append((str(value), str(label)))

    allowed_values = {v.lower() for v, _ in items}
    label_to_value: dict[str, str] = {}
    for value, label in items:
        key = norm_label(label)
        label_to_value.setdefault(key, value.lower())

    return allowed_values, label_to_value


def _fetch_device_descriptions(client) -> dict[str, str]:
    """Fetch device -> description mapping from interface overview.

    This endpoint returns a JSON array of device info objects (despite a text/html
    content-type on some versions).
    """

    r = client.session.s.get("interfaces/overview/export")
    data = r.json()
    if not isinstance(data, list):
        return {}

    mapping: dict[str, str] = {}
    for it in data:
        if not isinstance(it, dict):
            continue
        dev = it.get("device")
        desc = it.get("description")
        if not dev:
            continue
        if not desc:
            continue
        mapping[str(dev).strip().lower()] = str(desc).strip()

    return mapping


def _resolve_rule_interfaces(
    interfaces: list[str],
    *,
    allowed_values: set[str],
    label_to_value: dict[str, str],
    device_to_desc: dict[str, str],
) -> list[str]:
    """Resolve config-provided interfaces to values accepted by filter rules.

    Supported inputs:
        - Exact option values: lan, wan, opt5, __any, ...
        - Interface label names: Users, Servers, ...
        - Device names: vlan0030, vtnet2, ... (resolved via device description)
    """

    def norm_label(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip().lower())

    resolved: list[str] = []
    for raw in interfaces:
        token = str(raw).strip()
        if not token:
            continue

        low = token.lower()
        if low in allowed_values:
            resolved.append(low)
            continue

        # Allow using a label directly (e.g. "Users").
        key = norm_label(token)
        if key in label_to_value:
            resolved.append(label_to_value[key])
            continue

        # Allow device names (e.g. vlan0030) by mapping device -> description -> option label.
        desc = device_to_desc.get(low)
        if desc:
            desc_key = norm_label(desc)
            if desc_key in label_to_value:
                resolved.append(label_to_value[desc_key])
                continue

        hint = ""
        if desc:
            hint = f" (Gerät '{token}' hat Beschreibung '{desc}', aber keine passende Regel-Interface-Option gefunden)"

        raise SystemExit(
            f"Ungültiges Interface '{token}' für Firewall-Regeln{hint}. "
            "Nutze z.B. 'lan', 'wan', 'optX' oder einen gültigen Interface-Label."
        )

    return _dedupe_preserve_order(resolved)


def _build_rule_interface_resolver(client):
    allowed_values, label_to_value = _fetch_rule_interface_options(client)
    device_to_desc = _fetch_device_descriptions(client)

    def _resolver(interfaces: list[str]) -> list[str]:
        return _resolve_rule_interfaces(
            interfaces,
            allowed_values=allowed_values,
            label_to_value=label_to_value,
            device_to_desc=device_to_desc,
        )

    return _resolver


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
        alias_names = {a.name for a in aliases}

    multi_mode = args.url is None

    for target_name, url, credentials, ssl_verify in targets:
        LOGGER.info("Verbinde mich gleich zur OPNsense API unter %s (%s)", url, target_name)
        try:
            client = create_client(url, credentials, ssl_verify=ssl_verify)
        except Exception as exc:
            if multi_mode and _is_unreachable_exception(exc):
                LOGGER.error("[%s] Firewall nicht erreichbar (%s). Überspringe.", target_name, exc)
                continue
            raise

        def _run_module(module_name: str, params: dict) -> dict:
            try:
                response = client.run_module(module_name, params=params)
            except Exception as exc:
                if multi_mode and _is_unreachable_exception(exc):
                    raise _TargetUnreachable(str(exc)) from exc
                raise

            if response.get("error"):
                err = str(response.get("error"))
                if multi_mode and _is_unreachable_message(err):
                    raise _TargetUnreachable(err)
                raise SystemExit(f"[{target_name}] {module_name}: {err}")

            return response

        try:
            if not args.url:
                for module_name, params in _unbound_modules_for_target(target_name, firewalls):
                    LOGGER.debug("Rolle Unbound '%s' auf '%s' aus", module_name, target_name)
                    response = _run_module(module_name, params=params)
                    print(f"[{target_name}] {module_name}: {_format_module_result(response.get('result'))}")

            for alias in aliases:
                LOGGER.debug("Rolle Alias '%s' auf '%s' aus", alias.name, target_name)
                response = _run_module(
                    "alias",
                    params={
                        "name": alias.name,
                        "type": alias.type,
                        "content": list(alias.content),
                        "description": alias.description or "",
                        "state": "present",
                    },
                )
                print(f"[{target_name}] {alias.name}: {_format_module_result(response.get('result'))}")

            if not args.url:
                resolve_interfaces = _build_rule_interface_resolver(client)
                for params in _rules_from_config(
                    config,
                    target_fqdn=target_name,
                    firewalls=firewalls,
                    alias_names=alias_names,
                ):
                    # Normalize/resolve interface tokens like vlan0030 -> optX.
                    if "interface" in params and isinstance(params["interface"], list):
                        params["interface"] = resolve_interfaces(params["interface"])
                    LOGGER.debug(
                        "Rolle Firewall-Regel '%s' auf '%s' aus",
                        params.get("description"),
                        target_name,
                    )
                    response = _run_module("rule", params=params)
                    print(f"[{target_name}] rule: {_format_module_result(response.get('result'))}")
        except _TargetUnreachable as exc:
            LOGGER.error("[%s] Firewall nicht erreichbar (%s). Überspringe.", target_name, exc)
            continue


if __name__ == "__main__":
    main()
