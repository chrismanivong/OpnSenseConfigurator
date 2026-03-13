# OpnSenseConfigurator

Ein Python-Projekt für die zentrale Verwaltung von OPNsense-Konfigurationen (zunächst Aliases und Firewall-Regeln) über die OPNsense API.

## Zielbild

- Mehrere Standorte zentral ausrollen und konsistent halten.
- Bestehende WireGuard-Tunnel als Basis für die Standortvernetzung nutzen.
- Änderungen deklarativ definieren und reproduzierbar deployen.

## Lokale Einrichtung

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Single-Target (wie bisher)

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

## Multi-Firewall mit Verzeichnis + YAML

### 1) API-Key-Dateien im Verzeichnis

Lege pro Firewall **eine** OPNsense-Keydatei ab (Exportformat):

```text
key=...
secret=...
```

Der Dateiname enthält den FQDN, z. B. `opnsense1.domain.local.txt`.

### 2) YAML-Konfiguration

```yaml
configurator:
  firewalls:
    opnsense1.domain.local:
      ip: 10.10.0.1

  aliases:
    management_network:
      network: 10.10.0.0/24
```

### 3) Ausrollen

Wenn `--api-key-dir` oder `--config` nicht gesetzt sind, werden automatisch
`./firewall-keys` und `./config.yaml` verwendet.

```bash
python -m opnsense_configurator.cli \
  --api-key-dir ./firewall-keys \
  --config ./config.yaml
```

Du kannst deshalb auch einfach starten mit:

```bash
python -m opnsense_configurator.cli
```

## Logging

Das Logging ist über `--log-level` konfigurierbar (z. B. `DEBUG`, `INFO`, `WARNING`).

```bash
python -m opnsense_configurator.cli --log-level DEBUG
```

API-Verbindungen werden informell mit der Ziel-URL angekündigt.
