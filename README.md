# MX-Map — E-Mail-Provider deutscher Gemeinden

Eine interaktive Karte, die zeigt, wo deutsche Gemeinden ihre E-Mail hosten — ob bei US-Hyperscalern (Microsoft, Google, AWS) oder bei deutschen Anbietern (IONOS, Strato, Hetzner, Telekom) oder eigenständigen Lösungen.

**[Zur Karte](https://mx-map.de)**

Fork von [mxmap.ch](https://mxmap.ch) (Schweizer Version).

## Wie es funktioniert

Die Daten-Pipeline hat drei Schritte:

1. **Preprocess** — Ruft alle ~10.800 deutschen Gemeinden von Wikidata ab, führt MX- und SPF-DNS-Lookups auf deren offiziellen Domains durch und klassifiziert den E-Mail-Provider jeder Gemeinde.
2. **Postprocess** — Wendet manuelle Korrekturen für Sonderfälle an, wiederholt DNS für ungelöste Domains, prüft SMTP-Banner und durchsucht Webseiten nach E-Mail-Adressen.
3. **Validate** — Kreuzvalidiert MX- und SPF-Records, vergibt einen Konfidenz-Score (0-100) und erstellt einen Validierungsbericht.

## Quick Start

```bash
uv sync

uv run preprocess
uv run postprocess
uv run validate

# Karte lokal starten
python -m http.server
```

## Entwicklung

```bash
uv sync --group dev

# Tests mit Coverage
uv run pytest --cov --cov-report=term-missing

# Linting
uv run ruff check src tests
uv run ruff format src tests
```

## Test-Script

Zum Testen mit einer kleinen Gemeinde-Liste (10 Gemeinden):

```bash
uv run python scripts/test_sample.py
```

## Verwandte Projekte

* [mxmap.ch](https://mxmap.ch) — Original für die Schweiz (~2.100 Gemeinden)

## Beitragen

Fehlklassifizierung gefunden? Bitte ein Issue mit der AGS-Nummer und dem korrekten Provider erstellen.
Für Gemeinden, bei denen die automatische Erkennung fehlschlägt, können Korrekturen in `MANUAL_OVERRIDES` in `src/mail_sovereignty/postprocess.py` hinzugefügt werden.
