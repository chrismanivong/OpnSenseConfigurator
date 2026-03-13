"""Minimaler API-Client für OPNsense."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import json
import ssl
from urllib import request

from .models import AliasDefinition


@dataclass(slots=True)
class OPNsenseCredentials:
    key: str
    secret: str


class OPNsenseClient:
    """Kapselt den Zugriff auf die OPNsense API.

    Die Implementierung fokussiert zunächst Aliases. Firewall-Regeln folgen
    im nächsten Schritt, sobald das Datenmodell finalisiert ist.
    """

    def __init__(
        self,
        base_url: str,
        credentials: OPNsenseCredentials,
        timeout: int = 15,
        ssl_verify: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.credentials = credentials
        self.timeout = timeout
        self.ssl_verify = ssl_verify

    def _request(self, method: str, endpoint: str, json_data: dict | None = None) -> dict:
        url = f"{self.base_url}/api/{endpoint.lstrip('/')}"
        raw_auth = f"{self.credentials.key}:{self.credentials.secret}".encode()
        auth_header = base64.b64encode(raw_auth).decode()

        payload = json.dumps(json_data).encode() if json_data else None
        req = request.Request(
            url=url,
            method=method,
            data=payload,
            headers={
                "Authorization": f"Basic {auth_header}",
                "Content-Type": "application/json",
            },
        )

        context = None
        if not self.ssl_verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with request.urlopen(req, timeout=self.timeout, context=context) as response:
            return json.loads(response.read().decode())

    def upsert_alias(self, alias: AliasDefinition) -> dict:
        """Legt einen Alias an oder aktualisiert ihn per setItem-Endpoint."""

        payload = {
            "alias": {
                "name": alias.name,
                "type": alias.type,
                "content": "\n".join(alias.content),
                "description": alias.description or "",
            }
        }
        return self._request("POST", "firewall/alias/setItem", json_data=payload)
