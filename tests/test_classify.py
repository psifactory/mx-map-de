from mail_sovereignty.classify import (
    classify,
    classify_from_autodiscover,
    classify_from_mx,
    classify_from_smtp_banner,
    classify_from_spf,
    detect_gateway,
    spf_mentions_providers,
)


# ── classify() ──────────────────────────────────────────────────────


class TestClassify:
    def test_microsoft_mx(self):
        assert classify(["koeln-de.mail.protection.outlook.com"], "") == ("microsoft", None)

    def test_google_mx(self):
        assert (
            classify(["aspmx.l.google.com", "alt1.aspmx.l.google.com"], "") == ("google", None)
        )

    def test_ionos_mx(self):
        assert classify(["mx01.kundenserver.de"], "") == ("ionos", None)

    def test_strato_mx(self):
        assert classify(["smtp.strato.de"], "") == ("strato", None)

    def test_hetzner_mx(self):
        assert classify(["mail.your-server.de"], "") == ("hetzner", None)

    def test_aws_mx(self):
        assert classify(["inbound-smtp.us-east-1.amazonaws.com"], "") == ("aws", None)

    def test_independent_mx(self):
        assert classify(["mail.example.de"], "") == ("independent", None)

    def test_spf_fallback_when_no_mx(self):
        assert (
            classify([], "v=spf1 include:spf.protection.outlook.com -all")
            == ("microsoft", None)
        )

    def test_no_mx_no_spf(self):
        assert classify([], "") == ("unknown", None)

    def test_mx_takes_precedence_over_spf(self):
        result = classify(
            ["mail.example.de"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == ("independent", None)

    def test_cname_detects_microsoft(self):
        result = classify(
            ["mail.example.de"],
            "",
            mx_cnames={"mail.example.de": "mail.protection.outlook.com"},
        )
        assert result == ("microsoft", None)

    def test_cname_none_stays_independent(self):
        assert classify(["mail.example.de"], "", mx_cnames=None) == ("independent", None)

    def test_cname_empty_stays_independent(self):
        assert classify(["mail.example.de"], "", mx_cnames={}) == ("independent", None)

    def test_german_isp_asn(self):
        result = classify(
            ["mail1.example.de"],
            "",
            mx_asns={3320},
        )
        assert result == ("german-isp", None)

    def test_german_isp_with_autodiscover_microsoft(self):
        result = classify(
            ["mail1.example.de"],
            "",
            mx_asns={3320},
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == ("microsoft", None)

    def test_german_isp_without_autodiscover_stays_german_isp(self):
        result = classify(
            ["mail1.example.de"],
            "",
            mx_asns={3320},
            autodiscover=None,
        )
        assert result == ("german-isp", None)

    def test_seppmail_gateway_with_microsoft_spf(self):
        result = classify(
            ["customer.seppmail.cloud"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == ("microsoft", None)

    def test_gateway_no_hyperscaler_spf_stays_independent(self):
        result = classify(
            ["filter.seppmail.cloud"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result == ("independent", None)

    def test_gateway_autodiscover_reveals_microsoft(self):
        """Hornetsecurity is a visible gateway, so it becomes the provider with MS backend."""
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 ip4:1.2.3.4 -all",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == ("hornetsecurity", None)

    def test_non_gateway_independent_uses_autodiscover_fallback(self):
        result = classify(
            ["mail.example.de"],
            "",
            autodiscover={"autodiscover_cname": "autodiscover.outlook.com"},
        )
        assert result == ("microsoft", None)

    def test_non_gateway_independent_no_autodiscover_stays_independent(self):
        result = classify(
            ["mail.example.de"],
            "",
            autodiscover=None,
        )
        assert result == ("independent", None)

    def test_spf_only_resolved_fallback(self):
        result = classify(
            [],
            "v=spf1 include:custom.de -all",
            resolved_spf="v=spf1 include:custom.de -all v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == ("microsoft", None)

    def test_spf_only_no_resolved_stays_unknown(self):
        result = classify(
            [],
            "v=spf1 ip4:1.2.3.4 -all",
            resolved_spf=None,
        )
        assert result == ("unknown", None)

    # ── New: kommunal / gateway / backend tests ──

    def test_kommunal_mx(self):
        result = classify(["mail.ekom21.de"], "")
        assert result == ("kommunal", None)

    def test_kommunal_with_ms365_backend_spf(self):
        result = classify(
            ["mail.kvnbw.de"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == ("kommunal", "microsoft")

    def test_kommunal_with_ms365_backend_dkim(self):
        result = classify(
            ["mail.bayern.de"],
            "",
            dkim_selectors=["selector1", "selector2"],
        )
        assert result == ("kommunal", "microsoft")

    def test_hornetsecurity_visible_gateway(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 ip4:1.2.3.4 -all",
        )
        assert result == ("hornetsecurity", None)

    def test_hornetsecurity_with_ms365_backend(self):
        result = classify(
            ["mx01.hornetsecurity.com"],
            "v=spf1 include:spf.protection.outlook.com -all",
        )
        assert result == ("hornetsecurity", "microsoft")

    def test_sophos_visible_gateway(self):
        result = classify(
            ["mx.hydra.sophos.com"],
            "",
        )
        assert result == ("sophos", None)

    def test_barracuda_visible_gateway(self):
        result = classify(
            ["mx.barracudanetworks.com"],
            "",
        )
        assert result == ("barracuda", None)

    def test_barracuda_with_ms365_dkim(self):
        result = classify(
            ["mx.barracudanetworks.com"],
            "",
            dkim_selectors=["selector1", "selector2", "default"],
        )
        assert result == ("barracuda", "microsoft")

    def test_mimecast_visible_gateway(self):
        result = classify(
            ["eu.mimecast.com"],
            "",
        )
        assert result == ("mimecast", None)

    def test_antispameurope_visible_gateway(self):
        result = classify(
            ["mx.antispameurope.com"],
            "",
        )
        assert result == ("antispameurope", None)

    def test_proofpoint_visible_gateway(self):
        result = classify(
            ["mx.ppe-hosted.com"],
            "",
        )
        assert result == ("proofpoint", None)


# ── classify_from_autodiscover() ────────────────────────────────────


class TestClassifyFromAutodiscover:
    def test_none_returns_none(self):
        assert classify_from_autodiscover(None) is None

    def test_empty_dict_returns_none(self):
        assert classify_from_autodiscover({}) is None

    def test_microsoft_cname(self):
        assert (
            classify_from_autodiscover(
                {"autodiscover_cname": "autodiscover.outlook.com"}
            )
            == "microsoft"
        )


# ── detect_gateway() ────────────────────────────────────────────────


class TestDetectGateway:
    def test_seppmail(self):
        assert detect_gateway(["customer.seppmail.cloud"]) == "seppmail"

    def test_barracuda(self):
        assert detect_gateway(["mail.barracudanetworks.com"]) == "barracuda"

    def test_hornetsecurity(self):
        assert detect_gateway(["mx01.hornetsecurity.com"]) == "hornetsecurity"

    def test_retarus(self):
        assert detect_gateway(["mx.retarus.de"]) == "retarus"

    def test_antispameurope(self):
        assert detect_gateway(["mx.antispameurope.com"]) == "antispameurope"

    def test_no_gateway(self):
        assert detect_gateway(["mail.example.de"]) is None

    def test_empty_list(self):
        assert detect_gateway([]) is None


# ── classify_from_mx() ──────────────────────────────────────────────


class TestClassifyFromMx:
    def test_empty_returns_none(self):
        assert classify_from_mx([]) is None

    def test_microsoft(self):
        assert classify_from_mx(["mail.protection.outlook.com"]) == "microsoft"

    def test_unrecognized_returns_independent(self):
        assert classify_from_mx(["mail.custom.de"]) == "independent"


# ── classify_from_spf() ─────────────────────────────────────────────


class TestClassifyFromSpf:
    def test_empty_returns_none(self):
        assert classify_from_spf("") is None

    def test_microsoft(self):
        assert (
            classify_from_spf("v=spf1 include:spf.protection.outlook.com -all")
            == "microsoft"
        )


# ── spf_mentions_providers() ─────────────────────────────────────────


class TestSpfMentionsProviders:
    def test_empty_returns_empty(self):
        assert spf_mentions_providers("") == set()

    def test_single_provider(self):
        result = spf_mentions_providers(
            "v=spf1 include:spf.protection.outlook.com -all"
        )
        assert result == {"microsoft"}

    def test_foreign_sender_not_in_classify(self):
        assert classify([], "v=spf1 include:spf.mandrillapp.com -all") == ("unknown", None)


# ── classify_from_smtp_banner() ────────────────────────────────────


class TestClassifyFromSmtpBanner:
    def test_empty_returns_none(self):
        assert classify_from_smtp_banner("") is None

    def test_microsoft_banner(self):
        assert (
            classify_from_smtp_banner(
                "220 BL02EPF0001CA17.mail.protection.outlook.com "
                "Microsoft ESMTP MAIL Service ready"
            )
            == "microsoft"
        )

    def test_google_banner(self):
        assert classify_from_smtp_banner("220 mx.google.com ESMTP ready") == "google"

    def test_ionos_banner(self):
        assert classify_from_smtp_banner("220 mx.kundenserver.de ESMTP") == "ionos"

    def test_postfix_returns_none(self):
        assert classify_from_smtp_banner("220 mail.example.de ESMTP Postfix") is None
