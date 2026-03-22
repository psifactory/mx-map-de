from mail_sovereignty.constants import (
    MICROSOFT_KEYWORDS,
    GOOGLE_KEYWORDS,
    AWS_KEYWORDS,
    IONOS_KEYWORDS,
    STRATO_KEYWORDS,
    HETZNER_KEYWORDS,
    TELEKOM_KEYWORDS,
    PROVIDER_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    SKIP_DOMAINS,
    GERMAN_ISP_ASNS,
)


def test_keyword_lists_non_empty():
    assert MICROSOFT_KEYWORDS
    assert GOOGLE_KEYWORDS
    assert AWS_KEYWORDS
    assert IONOS_KEYWORDS
    assert STRATO_KEYWORDS
    assert HETZNER_KEYWORDS
    assert TELEKOM_KEYWORDS


def test_provider_keywords_has_all_providers():
    expected = {
        "microsoft", "google", "aws", "ionos", "strato", "hetzner",
        "telekom", "posteo", "mailbox.org", "tutanota", "open-xchange",
    }
    assert expected == set(PROVIDER_KEYWORDS.keys())


def test_foreign_sender_keywords_non_empty():
    assert FOREIGN_SENDER_KEYWORDS
    assert "mailchimp" in FOREIGN_SENDER_KEYWORDS
    assert "sendgrid" in FOREIGN_SENDER_KEYWORDS
    assert "smtp2go" in FOREIGN_SENDER_KEYWORDS
    assert "nl2go" in FOREIGN_SENDER_KEYWORDS
    assert "hubspot" in FOREIGN_SENDER_KEYWORDS
    assert "knowbe4" in FOREIGN_SENDER_KEYWORDS
    assert "hornetsecurity" in FOREIGN_SENDER_KEYWORDS
    assert set(FOREIGN_SENDER_KEYWORDS.keys()).isdisjoint(set(PROVIDER_KEYWORDS.keys()))


def test_skip_domains_contains_expected():
    assert "example.com" in SKIP_DOMAINS
    assert "example.de" in SKIP_DOMAINS
    assert "sentry.io" in SKIP_DOMAINS
    assert "schema.org" in SKIP_DOMAINS


def test_german_isp_asns_contains_key_providers():
    assert 3320 in GERMAN_ISP_ASNS  # Deutsche Telekom
    assert 8560 in GERMAN_ISP_ASNS  # IONOS
    assert 24940 in GERMAN_ISP_ASNS  # Hetzner
    assert 6724 in GERMAN_ISP_ASNS  # Strato


def test_german_isp_asns_minimum_count():
    assert len(GERMAN_ISP_ASNS) >= 10
