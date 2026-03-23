import json
from unittest.mock import AsyncMock, patch

import httpx
import respx

from mail_sovereignty.preprocess import (
    fetch_wikidata,
    guess_domains,
    run,
    scan_municipality,
    url_to_domain,
)


# ── url_to_domain() ─────────────────────────────────────────────────


class TestUrlToDomain:
    def test_full_url_with_path(self):
        assert url_to_domain("https://www.berlin.de/some/path") == "berlin.de"

    def test_no_scheme(self):
        assert url_to_domain("berlin.de") == "berlin.de"

    def test_strips_www(self):
        assert url_to_domain("https://www.example.de") == "example.de"

    def test_empty_string(self):
        assert url_to_domain("") is None

    def test_none(self):
        assert url_to_domain(None) is None

    def test_bare_domain(self):
        assert url_to_domain("example.de") == "example.de"

    def test_http_scheme(self):
        assert url_to_domain("http://example.de/page") == "example.de"


# ── guess_domains() ─────────────────────────────────────────────────


class TestGuessDomains:
    def test_simple_name(self):
        domains = guess_domains("Berlin")
        assert "berlin.de" in domains
        assert "gemeinde-berlin.de" in domains

    def test_umlaut(self):
        domains = guess_domains("München")
        assert "muenchen.de" in domains

    def test_parenthetical_stripped(self):
        domains = guess_domains("Neustadt (Hessen)")
        assert any("neustadt" in d for d in domains)
        assert not any("Hessen" in d for d in domains)

    def test_stadt_prefix(self):
        domains = guess_domains("Berlin")
        assert "stadt-berlin.de" in domains

    def test_eszett(self):
        domains = guess_domains("Großbeeren")
        assert "grossbeeren.de" in domains


# ── fetch_wikidata() ─────────────────────────────────────────────────


class TestFetchWikidata:
    @respx.mock
    async def test_success(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "11000000"},
                                "itemLabel": {"value": "Berlin"},
                                "website": {"value": "https://www.berlin.de"},
                                "stateLabel": {"value": "Berlin"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert "11000000" in result
        assert result["11000000"]["name"] == "Berlin"

    @respx.mock
    async def test_deduplication(self):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "11000000"},
                                "itemLabel": {"value": "Berlin"},
                                "website": {"value": "https://www.berlin.de"},
                                "stateLabel": {"value": "Berlin"},
                            },
                            {
                                "ags": {"value": "11000000"},
                                "itemLabel": {"value": "Berlin"},
                                "website": {"value": "https://www.berlin.de/alt"},
                                "stateLabel": {"value": "Berlin"},
                            },
                        ]
                    }
                },
            )
        )

        result = await fetch_wikidata()
        assert len(result) == 1


# ── scan_municipality() ──────────────────────────────────────────────


class TestScanMunicipality:
    async def test_website_domain_mx_found(self):
        m = {
            "ags": "05315000",
            "name": "Köln",
            "state": "Nordrhein-Westfalen",
            "website": "https://www.stadt-koeln.de",
            "lat": "",
            "lon": "",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["domain"] == "stadt-koeln.de"

    async def test_no_website_guesses_domain(self):
        m = {"ags": "99999999", "name": "Berlin", "state": "Berlin", "website": "", "lat": "", "lon": ""}
        sem = __import__("asyncio").Semaphore(10)

        async def fake_lookup_mx(domain):
            if domain == "berlin.de":
                return ["mail.berlin.de"]
            return []

        with (
            patch("mail_sovereignty.preprocess.lookup_mx", side_effect=fake_lookup_mx),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "eigener-server"
        assert result["domain"] == "berlin.de"

    async def test_no_mx_unknown(self):
        m = {"ags": "99999999", "name": "Zzz", "state": "Test", "website": "", "lat": "", "lon": ""}
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "unknown"

    async def test_gateway_detected_and_stored(self):
        m = {
            "ags": "08111000",
            "name": "Stuttgart",
            "state": "Baden-Württemberg",
            "website": "https://www.stuttgart.de",
            "lat": "",
            "lon": "",
        }
        sem = __import__("asyncio").Semaphore(10)

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["customer.seppmail.cloud"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await scan_municipality(m, sem)

        assert result["provider"] == "microsoft"
        assert result["gateway"] == "seppmail"


# ── run() ────────────────────────────────────────────────────────────


class TestPreprocessRun:
    @respx.mock
    async def test_writes_output(self, tmp_path):
        respx.post("https://query.wikidata.org/sparql").mock(
            return_value=httpx.Response(
                200,
                json={
                    "results": {
                        "bindings": [
                            {
                                "ags": {"value": "11000000"},
                                "itemLabel": {"value": "Berlin"},
                                "website": {"value": "https://www.berlin.de"},
                                "stateLabel": {"value": "Berlin"},
                            },
                        ]
                    }
                },
            )
        )

        with (
            patch(
                "mail_sovereignty.preprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mx.berlin.de"],
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.resolve_spf_includes",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.preprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            output = tmp_path / "data.json"
            await run(output)

        assert output.exists()
        data = json.loads(output.read_text())
        assert data["total"] == 1
        assert "11000000" in data["municipalities"]
