"""Basis-Paket für den OPNsense Konfigurator."""

from .client import OPNsenseCredentials, create_client

__all__ = ["OPNsenseCredentials", "create_client"]
