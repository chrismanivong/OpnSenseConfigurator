"""Domänenmodelle für OPNsense Konfigurationen."""

from dataclasses import dataclass, field


@dataclass(slots=True)
class AliasDefinition:
    """Definition eines OPNsense-Alias."""

    name: str
    type: str = "host"
    content: list[str] = field(default_factory=list)
    description: str | None = None


@dataclass(slots=True)
class FirewallRuleDefinition:
    """Definition einer Firewall-Regel."""

    interface: str
    source: str
    destination: str
    action: str = "pass"
    description: str | None = None
