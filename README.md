# OpnSenseConfigurator

Ein Python-Projekt für die zentrale Verwaltung von OPNsense-Konfigurationen (zunächst Aliases und Firewall-Regeln) über die OPNsense API.

## Zielbild

- Mehrere Standorte zentral ausrollen und konsistent halten.
- Bestehende WireGuard-Tunnel als Basis für die Standortvernetzung nutzen.
- Änderungen deklarativ definieren und reproduzierbar deployen.

## Aktueller Stand

Das Repository enthält ein erstes Grundgerüst mit:

- `OPNsenseClient` für API-Aufrufe.
- Domänenmodelle für Aliases und Firewall-Regeln.
- Einfache CLI zum Hochladen eines Alias.
- Unit-Test für den Alias-API-Call.

## Lokale Einrichtung

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Beispiel: Alias ausrollen

```bash
export OPNSENSE_API_KEY="..."
export OPNSENSE_API_SECRET="..."
python -m opnsense_configurator.cli \
  --url "https://opnsense.example.local" \
  --name "branch-office-hosts" \
  --ip "10.10.20.10" \
  --ip "10.10.20.11" \
  --description "Hosts Standort B"
```

## Nächste Schritte

1. Firewall-Regel-Deployment (`filter_base`-Endpoints) ergänzen.
2. Konfigurationsdatei (YAML/JSON) für Multi-Site Rollouts einführen.
3. Dry-Run und Diff-Ausgabe implementieren.
4. Optionale GitOps-Pipeline (z. B. per CI/CD) anbinden.
