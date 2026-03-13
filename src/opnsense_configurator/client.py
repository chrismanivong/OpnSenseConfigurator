"""Minimaler API-Client für OPNsense."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import logging
from urllib.parse import urlparse

import httpx

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class OPNsenseCredentials:
    key: str
    secret: str


def _format_host_for_url(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _detect_alias_set_command(
    *,
    host: str,
    port: int,
    credentials: OPNsenseCredentials,
    ssl_verify: bool,
    timeout: float,
) -> str | None:
    """Detect which alias update command is supported.

    Some OPNsense versions expose `POST /api/firewall/alias/set/<uuid>` instead of
    `POST /api/firewall/alias/set_item/<uuid>`.

    Returns:
        - "set_item" if the set_item route exists
        - "set" if the set route exists
        - None if detection failed
    """

    dummy_uuid = "00000000-0000-0000-0000-000000000000"
    base = f"https://{_format_host_for_url(host)}:{port}"

    try:
        with httpx.Client(
            base_url=base,
            auth=(credentials.key, credentials.secret),
            verify=ssl_verify,
            timeout=httpx.Timeout(timeout=timeout, connect=min(2.0, timeout)),
        ) as session:
            # If route exists we expect anything except 404 (likely 400/500/200 depending on validations).
            r = session.post(f"/api/firewall/alias/set_item/{dummy_uuid}", json={})
            if r.status_code != 404:
                return "set_item"

            r = session.post(f"/api/firewall/alias/set/{dummy_uuid}", json={})
            if r.status_code != 404:
                return "set"

    except httpx.HTTPError as exc:
        LOGGER.warning("Alias endpoint auto-detect failed: %s", exc)

    return None


def create_client(
    base_url: str,
    credentials: OPNsenseCredentials,
    *,
    timeout: int = 15,
    ssl_verify: bool = True,
):
    """Erzeugt einen `oxl-opnsense-client` Client aus URL + Credentials.

    Diese Funktion hält die Integration bewusst klein und "pythonic".
    """

    try:
        oxl_module = importlib.import_module("oxl_opnsense_client")
        oxl_client_type = getattr(oxl_module, "Client")
    except ModuleNotFoundError as exc:  # pragma: no cover
        raise RuntimeError(
            "oxl-opnsense-client ist nicht installiert. "
            "Installiere es oder nutze ein Environment, in dem es verfügbar ist."
        ) from exc

    parsed = urlparse(base_url if "://" in base_url else f"https://{base_url}")
    host = parsed.hostname or base_url
    port = parsed.port or (443 if parsed.scheme in {"https", ""} else 80)

    # Compatibility: Auto-detect which alias update endpoint exists and patch
    # OXL's alias command mapping only when needed.
    detected_command = _detect_alias_set_command(
        host=host,
        port=port,
        credentials=credentials,
        ssl_verify=ssl_verify,
        timeout=float(timeout),
    )
    if detected_command == "set":
        try:
            alias_module = importlib.import_module(
                "oxl_opnsense_client.plugins.module_utils.main.alias"
            )
            OXLAlias = getattr(alias_module, "Alias")
            if isinstance(getattr(OXLAlias, "CMDS", None), dict):
                OXLAlias.CMDS["set"] = "set"
        except ModuleNotFoundError:
            pass

    LOGGER.debug("Erzeuge OXL Client für %s:%s", host, port)
    return oxl_client_type(
        firewall=host,
        port=port,
        token=credentials.key,
        secret=credentials.secret,
        ssl_verify=ssl_verify,
        api_timeout=float(timeout),
        shell=False,
    )
