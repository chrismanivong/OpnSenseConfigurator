"""Einfache CLI für einen ersten Smoke-Test gegen OPNsense."""

from __future__ import annotations

import argparse
import os

from .client import OPNsenseClient, OPNsenseCredentials
from .models import AliasDefinition


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="OPNsense Alias per API ausrollen")
    parser.add_argument("--url", required=True, help="Basis-URL der OPNsense Instanz")
    parser.add_argument("--name", required=True, help="Alias-Name")
    parser.add_argument("--ip", action="append", default=[], help="IP-Eintrag (mehrfach möglich)")
    parser.add_argument("--description", default="", help="Beschreibung für den Alias")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    key = os.environ.get("OPNSENSE_API_KEY")
    secret = os.environ.get("OPNSENSE_API_SECRET")

    if not key or not secret:
        raise SystemExit("Bitte OPNSENSE_API_KEY und OPNSENSE_API_SECRET setzen.")

    client = OPNsenseClient(args.url, OPNsenseCredentials(key=key, secret=secret))
    alias = AliasDefinition(name=args.name, content=args.ip, description=args.description)
    result = client.upsert_alias(alias)
    print(result)


if __name__ == "__main__":
    main()
