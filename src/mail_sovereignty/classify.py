from mail_sovereignty.constants import (
    AWS_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    GATEWAY_KEYWORDS,
    GERMAN_ISP_ASNS,
    GOOGLE_KEYWORDS,
    HETZNER_KEYWORDS,
    IONOS_KEYWORDS,
    KOMMUNAL_KEYWORDS,
    MAILBOX_ORG_KEYWORDS,
    MANAGED_HOSTING_KEYWORDS,
    MICROSOFT_KEYWORDS,
    OPEN_XCHANGE_KEYWORDS,
    POSTEO_KEYWORDS,
    PROVIDER_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
    STRATO_KEYWORDS,
    TELEKOM_KEYWORDS,
    TUTANOTA_KEYWORDS,
    VISIBLE_GATEWAYS,
    WEBSITE_BUILDER_KEYWORDS,
)


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for provider keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def _check_mx_blob_for_provider(mx_blob: str) -> str | None:
    """Check MX blob against all provider keywords. Return provider or None."""
    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return "microsoft"
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return "google"
    if any(k in mx_blob for k in IONOS_KEYWORDS):
        return "ionos"
    if any(k in mx_blob for k in STRATO_KEYWORDS):
        return "strato"
    if any(k in mx_blob for k in HETZNER_KEYWORDS):
        return "hetzner"
    if any(k in mx_blob for k in TELEKOM_KEYWORDS):
        return "telekom"
    if any(k in mx_blob for k in POSTEO_KEYWORDS):
        return "posteo"
    if any(k in mx_blob for k in MAILBOX_ORG_KEYWORDS):
        return "mailbox.org"
    if any(k in mx_blob for k in TUTANOTA_KEYWORDS):
        return "tutanota"
    if any(k in mx_blob for k in OPEN_XCHANGE_KEYWORDS):
        return "open-xchange"
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return "aws"
    return None


def _detect_ms365_backend(
    spf_record: str | None,
    resolved_spf: str | None,
    dkim_selectors: list[str] | None,
) -> str | None:
    """Detect Microsoft 365 behind a gateway via SPF/DKIM signals."""
    spf_blob = ((spf_record or "") + " " + (resolved_spf or "")).lower()
    if "spf.protection.outlook.com" in spf_blob:
        return "microsoft"
    if dkim_selectors and "selector1" in dkim_selectors and "selector2" in dkim_selectors:
        return "microsoft"
    return None


def _sub_classify_independent(
    mx_records: list[str],
    domain: str | None,
) -> str:
    """Sub-classify what was previously 'independent' into finer categories."""
    mx_blob = " ".join(mx_records).lower()

    # Managed hosting providers
    if any(k in mx_blob for k in MANAGED_HOSTING_KEYWORDS):
        return "managed-hosting"

    # Website builders
    if any(k in mx_blob for k in WEBSITE_BUILDER_KEYWORDS):
        return "website-builder"

    # Eigener Server: MX host is the municipality domain or a subdomain of it
    if domain:
        d = domain.lower().rstrip(".")
        for mx in mx_records:
            mx_lower = mx.lower().rstrip(".")
            if mx_lower == d or mx_lower.endswith("." + d):
                return "eigener-server"

    return "sonstige"


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
    domain: str | None = None,
    dkim_selectors: list[str] | None = None,
) -> dict:
    """Classify email provider based on MX, CNAME targets, SPF, and DKIM.

    Returns dict with keys: provider, backend (optional), gateway (optional).
    """
    mx_blob = " ".join(mx_records).lower()
    gateway = detect_gateway(mx_records) if mx_records else None
    result: dict = {}

    if gateway:
        result["gateway"] = gateway

    # 1. Kommunale Rechenzentren (MX-based)
    if any(k in mx_blob for k in KOMMUNAL_KEYWORDS):
        backend = _detect_ms365_backend(spf_record, resolved_spf, dkim_selectors)
        result["provider"] = "kommunal"
        if backend:
            result["backend"] = backend
        return result

    # 2. Visible gateways become the provider, with optional backend
    if gateway and gateway in VISIBLE_GATEWAYS:
        backend = _detect_ms365_backend(spf_record, resolved_spf, dkim_selectors)
        result["provider"] = gateway
        if backend:
            result["backend"] = backend
        return result

    # 3. Direct provider from MX
    provider = _check_mx_blob_for_provider(mx_blob)
    if provider:
        result["provider"] = provider
        return result

    # 4. CNAME resolution of MX hosts
    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        cname_provider = _check_mx_blob_for_provider(cname_blob)
        if cname_provider:
            result["provider"] = cname_provider
            return result

    # 5. Non-visible gateways: look through to find real provider via SPF
    if mx_records and gateway:
        spf_blob = (spf_record or "").lower()
        provider = _check_spf_for_provider(spf_blob)
        if not provider and resolved_spf:
            provider = _check_spf_for_provider(resolved_spf.lower())
        if provider:
            result["provider"] = provider
            return result
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            result["provider"] = ad_provider
            return result

    # 6. German ISP / sub-classified independent
    if mx_records:
        if mx_asns and mx_asns & GERMAN_ISP_ASNS.keys():
            ad_provider = classify_from_autodiscover(autodiscover)
            if ad_provider:
                result["provider"] = ad_provider
                return result
            result["provider"] = "german-isp"
            return result
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            result["provider"] = ad_provider
            return result
        result["provider"] = _sub_classify_independent(mx_records, domain)
        return result

    # 7. SPF-only fallback
    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    if provider:
        result["provider"] = provider
        return result

    result["provider"] = "unknown"
    return result


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found
