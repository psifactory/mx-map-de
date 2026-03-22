import asyncio
import json
from unittest.mock import AsyncMock, patch

from mail_sovereignty.postprocess import (
    MANUAL_OVERRIDES,
    build_urls,
    decrypt_typo3,
    extract_email_domains,
    process_unknown,
    run,
    scrape_email_domains,
)


# ── decrypt_typo3() ──────────────────────────────────────────────────


class TestDecryptTypo3:
    def test_known_encrypted(self):
        # Each char reversed through +2 offset on TYPO3 ranges:
        # k->m, y->a, g->i, j->l, r->t, m->o, 8->:, y->a, Y->@, z->b, ,->., a->c, f->h
        encrypted = "kygjrm8yYz,af"
        decrypted = decrypt_typo3(encrypted)
        assert decrypted == "mailto:a@b.ch"

    def test_empty_string(self):
        assert decrypt_typo3("") == ""

    def test_non_range_passthrough(self):
        assert decrypt_typo3(" ") == " "

    def test_custom_offset(self):
        result = decrypt_typo3("a", offset=1)
        assert result == "b"

    def test_wrap_around(self):
        # 'z' is 0x7A (end of range), offset 2 wraps to 0x61 + 1 = 'b'
        result = decrypt_typo3("z", offset=2)
        assert result == "b"


# ── extract_email_domains() ──────────────────────────────────────────


class TestExtractEmailDomains:
    def test_plain_email(self):
        html = "Contact us at info@gemeinde.de for more info."
        assert "gemeinde.de" in extract_email_domains(html)

    def test_mailto_link(self):
        html = '<a href="mailto:contact@town.de">Email</a>'
        assert "town.de" in extract_email_domains(html)

    def test_typo3_obfuscated(self):
        html = """linkTo_UnCryptMailto('kygjrm8yYz,af')"""
        domains = extract_email_domains(html)
        assert "b.ch" in domains

    def test_skip_domains_filtered(self):
        html = "admin@example.com test@sentry.io"
        domains = extract_email_domains(html)
        assert "example.com" not in domains
        assert "sentry.io" not in domains

    def test_multiple_sources_combined(self):
        html = 'info@town.de <a href="mailto:admin@city.de">x</a>'
        domains = extract_email_domains(html)
        assert "town.de" in domains
        assert "city.de" in domains

    def test_no_emails(self):
        html = "<html><body>No contact here</body></html>"
        assert extract_email_domains(html) == set()


# ── build_urls() ─────────────────────────────────────────────────────


class TestBuildUrls:
    def test_bare_domain(self):
        urls = build_urls("example.de")
        assert "https://www.example.de/" in urls
        assert "https://example.de/" in urls
        assert any("/kontakt" in u for u in urls)

    def test_www_prefix(self):
        urls = build_urls("www.example.de")
        assert "https://www.example.de/" in urls
        assert "https://example.de/" in urls

    def test_https_prefix_stripped(self):
        urls = build_urls("https://example.de")
        assert "https://www.example.de/" in urls

    def test_includes_contact_paths(self):
        urls = build_urls("example.de")
        assert any("/kontakt" in u for u in urls)
        assert any("/impressum" in u for u in urls)


# ── MANUAL_OVERRIDES ─────────────────────────────────────────────────


class TestManualOverrides:
    def test_all_entries_have_required_keys(self):
        for ags, entry in MANUAL_OVERRIDES.items():
            assert "domain" in entry, f"AGS {ags} missing 'domain'"
            assert "provider" in entry, f"AGS {ags} missing 'provider'"

    def test_overrides_empty(self):
        assert len(MANUAL_OVERRIDES) == 0


# ── Async functions ──────────────────────────────────────────────────


class TestScrapeEmailDomains:
    async def test_empty_domain(self):
        result = await scrape_email_domains(None, "")
        assert result == set()

    async def test_with_emails_found(self):
        class FakeResponse:
            status_code = 200
            text = "Contact us at info@gemeinde.de"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "gemeinde.de")
        assert "gemeinde.de" in result


class TestProcessUnknown:
    async def test_no_domain_returns_unchanged(self):
        m = {"ags": "99999999", "name": "Test", "domain": "", "provider": "unknown"}
        sem = asyncio.Semaphore(10)
        client = AsyncMock()

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"

    async def test_resolves_via_email_scraping(self):
        m = {"ags": "99999999", "name": "Test", "domain": "test.de", "provider": "unknown"}
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "Contact us at info@test.de"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["mail.test.de"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            result = await process_unknown(client, sem, m)

        assert result["provider"] == "independent"

    async def test_no_email_domains_found(self):
        m = {"ags": "99999999", "name": "Test", "domain": "test.de", "provider": "unknown"}
        sem = asyncio.Semaphore(10)

        class FakeResponse:
            status_code = 200
            text = "<html>No emails here</html>"

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await process_unknown(client, sem, m)
        assert result["provider"] == "unknown"


class TestScrapeEmailDomainsNoEmails:
    async def test_non_200_skipped(self):
        class FakeResponse:
            status_code = 404
            text = ""

        client = AsyncMock()
        client.get = AsyncMock(return_value=FakeResponse())

        result = await scrape_email_domains(client, "test.de")
        assert result == set()

    async def test_exception_handled(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("connection error"))

        result = await scrape_email_domains(client, "test.de")
        assert result == set()


class TestDnsRetryStep:
    async def test_recovers_unknown_with_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "1234": {
                    "ags": "1234",
                    "name": "Testingen",
                    "state": "Niedersachsen",
                    "domain": "testingen.de",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with (
            patch(
                "mail_sovereignty.postprocess.lookup_mx",
                new_callable=AsyncMock,
                return_value=["testingen-de.mail.protection.outlook.com"],
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_spf",
                new_callable=AsyncMock,
                return_value="v=spf1 include:spf.protection.outlook.com -all",
            ),
            patch(
                "mail_sovereignty.postprocess.lookup_autodiscover",
                new_callable=AsyncMock,
                return_value={},
            ),
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1234"]["provider"] == "microsoft"

    async def test_skips_unknown_without_domain(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"unknown": 1},
            "municipalities": {
                "9999": {
                    "ags": "9999",
                    "name": "NoDomain",
                    "state": "Test",
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["9999"]["provider"] == "unknown"


class TestSmtpBannerStep:
    async def test_reclassifies_independent_via_smtp(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "1000": {
                    "ags": "1000",
                    "name": "SmtpTown",
                    "state": "Test",
                    "domain": "smtptown.de",
                    "mx": ["mail.smtptown.de"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service ready",
                "ehlo": "250 ready",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1000"]["provider"] == "microsoft"
        assert "smtp_banner" in result["municipalities"]["1000"]

    async def test_leaves_independent_when_banner_is_postfix(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "1001": {
                    "ags": "1001",
                    "name": "PostfixTown",
                    "state": "Test",
                    "domain": "postfixtown.de",
                    "mx": ["mail.postfixtown.de"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.postfixtown.de ESMTP Postfix",
                "ehlo": "250 mail.postfixtown.de",
            },
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["1001"]["provider"] == "independent"
        assert "smtp_banner" in result["municipalities"]["1001"]

    async def test_skips_already_classified(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"microsoft": 1},
            "municipalities": {
                "1002": {
                    "ags": "1002",
                    "name": "AlreadyKnown",
                    "state": "Test",
                    "domain": "known.de",
                    "mx": ["mail.protection.outlook.com"],
                    "spf": "v=spf1 include:spf.protection.outlook.com -all",
                    "provider": "microsoft",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
        ) as mock_fetch:
            await run(path)
            mock_fetch.assert_not_called()

    async def test_deduplicates_mx_hosts(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 2,
            "counts": {"independent": 2},
            "municipalities": {
                "2000": {
                    "ags": "2000",
                    "name": "Town1",
                    "state": "Test",
                    "domain": "town1.de",
                    "mx": ["shared-mx.example.de"],
                    "spf": "",
                    "provider": "independent",
                },
                "2001": {
                    "ags": "2001",
                    "name": "Town2",
                    "state": "Test",
                    "domain": "town2.de",
                    "mx": ["shared-mx.example.de"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={
                "banner": "220 mail.protection.outlook.com Microsoft ESMTP MAIL Service",
                "ehlo": "250 ready",
            },
        ) as mock_fetch:
            await run(path)
            # Should only be called once for the shared MX host
            assert mock_fetch.call_count == 1

        result = json.loads(path.read_text())
        assert result["municipalities"]["2000"]["provider"] == "microsoft"
        assert result["municipalities"]["2001"]["provider"] == "microsoft"

    async def test_empty_banner_no_change(self, tmp_path):
        data = {
            "generated": "2025-01-01",
            "total": 1,
            "counts": {"independent": 1},
            "municipalities": {
                "3000": {
                    "ags": "3000",
                    "name": "NoConnect",
                    "state": "Test",
                    "domain": "noconnect.de",
                    "mx": ["mail.noconnect.de"],
                    "spf": "",
                    "provider": "independent",
                },
            },
        }
        path = tmp_path / "data.json"
        path.write_text(json.dumps(data))

        with patch(
            "mail_sovereignty.postprocess.fetch_smtp_banner",
            new_callable=AsyncMock,
            return_value={"banner": "", "ehlo": ""},
        ):
            await run(path)

        result = json.loads(path.read_text())
        assert result["municipalities"]["3000"]["provider"] == "independent"
        assert "smtp_banner" not in result["municipalities"]["3000"]


class TestPostprocessRun:
    async def test_manual_overrides_empty(self):
        assert len(MANUAL_OVERRIDES) == 0
