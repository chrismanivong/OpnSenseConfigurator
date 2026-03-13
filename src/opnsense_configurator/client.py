"""OPNsense-Client auf Basis von pyopnsense."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import logging
from typing import Any

from .models import AliasDefinition

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class OPNsenseCredentials:
    key: str
    secret: str


class OPNsenseClient:
    """Kapselt den Zugriff auf die OPNsense API via pyopnsense."""

    def __init__(
        self,
        base_url: str,
        credentials: OPNsenseCredentials,
        timeout: int = 15,
        ssl_verify: bool = True,
    ) -> None:
        normalized_base_url = base_url.rstrip("/")
        if normalized_base_url.endswith("/api"):
            normalized_base_url = normalized_base_url[: -len("/api")]

        self.base_url = normalized_base_url
        self.credentials = credentials
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        self._backend = self._create_backend()

    def _create_backend(self) -> Any:
        try:
            module = importlib.import_module("pyopnsense")
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "pyopnsense ist nicht installiert. Bitte `pip install pyopnsense` ausführen."
            ) from exc

        backend_cls = getattr(module, "OPNsenseClient", None) or getattr(module, "Client", None)
        if backend_cls is None:
            raise RuntimeError("Konnte in pyopnsense keine Client-Klasse finden (OPNsenseClient/Client).")

        attempts = [
            {"base_url": self.base_url, "api_key": self.credentials.key, "api_secret": self.credentials.secret, "verify_ssl": self.ssl_verify, "timeout": self.timeout},
            {"url": self.base_url, "key": self.credentials.key, "secret": self.credentials.secret, "verify_ssl": self.ssl_verify, "timeout": self.timeout},
            {"base_url": self.base_url, "key": self.credentials.key, "secret": self.credentials.secret, "ssl_verify": self.ssl_verify, "timeout": self.timeout},
        ]

        for kwargs in attempts:
            try:
                return backend_cls(**kwargs)
            except TypeError:
                continue

        try:
            return backend_cls(self.base_url, self.credentials.key, self.credentials.secret)
        except TypeError as exc:
            raise RuntimeError("Konnte pyopnsense Client nicht initialisieren. Bitte Versionskompatibilität prüfen.") from exc

    def upsert_alias(self, alias: AliasDefinition) -> dict:
        payload = {
            "alias": {
                "name": alias.name,
                "type": alias.type,
                "content": "\n".join(alias.content),
                "description": alias.description or "",
            }
        }

        endpoint = "firewall/alias/setItem"
        backend = self._backend

        if hasattr(backend, "post"):
            LOGGER.debug("Sende Alias-Update via pyopnsense.post an %s", endpoint)
            return backend.post(endpoint, payload)

        if hasattr(backend, "request"):
            LOGGER.debug("Sende Alias-Update via pyopnsense.request an %s", endpoint)
            return backend.request("POST", endpoint, json=payload)

        raise RuntimeError("pyopnsense Backend bietet weder post() noch request() für API-Aufrufe an.")
