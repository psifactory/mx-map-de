import asyncio
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import (
    classify,
    classify_from_smtp_banner,
    detect_gateway,
)
from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    CONCURRENCY_SMTP,
    EMAIL_RE,
    SKIP_DOMAINS,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)
from mail_sovereignty.smtp import fetch_smtp_banner


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                n = code + offset
                if n > end:
                    n = start + (n - end - 1)
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def extract_email_domains(html: str) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    domains = set()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS:
            domains.add(domain)

    for email in __import__("re").findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        decoded = decrypt_typo3(encoded)
        decoded = decoded.replace("mailto:", "")
        if "@" in decoded:
            domain = decoded.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    return domains


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


async def scrape_email_domains(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Scrape a municipality website for email domains."""
    if not domain:
        return set()

    all_domains = set()
    urls = build_urls(domain)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                continue
            domains = extract_email_domains(r.text)
            all_domains |= domains
            if all_domains:
                return all_domains
        except Exception:
            continue

    return all_domains


async def process_unknown(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, m: dict[str, Any]
) -> dict[str, Any]:
    """Try to resolve an unknown municipality by scraping its website."""
    async with semaphore:
        ags = m["ags"]
        name = m["name"]
        domain = m.get("domain", "")

        if not domain:
            print(f"  SKIP     {ags:>8} {name:<30} (no domain)")
            return m

        email_domains = await scrape_email_domains(client, domain)

        for email_domain in sorted(email_domains):
            mx = await lookup_mx(email_domain)
            if mx:
                spf = await lookup_spf(email_domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(email_domain)
                provider, backend = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                print(
                    f"  RESOLVED {ags:>8} {name:<30} "
                    f"email_domain={email_domain} -> {provider}"
                )
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                if backend:
                    m["backend"] = backend
                m["domain"] = email_domain
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                return m

        print(
            f"  UNKNOWN  {ags:>8} {name:<30} "
            f"(scraped email domains: {email_domains or 'none'})"
        )
        return m


# Manual overrides for edge cases (to be populated as needed)
MANUAL_OVERRIDES: dict[str, dict[str, Any]] = {}


async def run(data_path: Path) -> None:
    with open(data_path, encoding="utf-8") as f:
        data = json.load(f)

    muni = data["municipalities"]

    # Step 1: Apply manual overrides
    if MANUAL_OVERRIDES:
        print("Applying manual overrides...")
        dns_relookup = []  # (ags, domain) pairs needing MX/SPF re-lookup
        for ags, override in MANUAL_OVERRIDES.items():
            if ags not in muni and "name" in override:
                muni[ags] = {
                    "ags": ags,
                    "name": override["name"],
                    "state": override.get("state", ""),
                    "domain": "",
                    "mx": [],
                    "spf": "",
                    "provider": "unknown",
                }
                print(
                    f"  {ags:>8} {override['name']:<30} (added missing municipality)"
                )
            if ags not in muni:
                continue
            if ags in muni:
                if "domain" in override:
                    muni[ags]["domain"] = override["domain"]
                if "provider" in override:
                    muni[ags]["provider"] = override["provider"]
                if "gateway" in override:
                    muni[ags]["gateway"] = override["gateway"]
                if "mx" in override:
                    muni[ags]["mx"] = override["mx"]
                if "spf" in override:
                    muni[ags]["spf"] = override["spf"]
                if override.get("provider") == "merged":
                    muni[ags]["mx"] = []
                    muni[ags]["spf"] = ""
                # Domain-only override: need to re-lookup MX/SPF from DNS
                if (
                    "domain" in override
                    and override["domain"]
                    and "mx" not in override
                    and "provider" not in override
                ):
                    dns_relookup.append((ags, override["domain"]))
                else:
                    print(
                        f"  {ags:>8} {muni[ags]['name']:<30} -> {override.get('provider', '?')}"
                    )

        if dns_relookup:

            async def _relookup(ags, domain):
                mx = await lookup_mx(domain)
                spf = await lookup_spf(domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx) if mx else {}
                mx_asns = await resolve_mx_asns(mx) if mx else set()
                autodiscover = await lookup_autodiscover(domain)
                provider, backend = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx) if mx else None
                return (
                    ags,
                    mx,
                    spf,
                    spf_resolved,
                    mx_cnames,
                    mx_asns,
                    provider,
                    backend,
                    gateway,
                    autodiscover,
                )

            results = await asyncio.gather(
                *[_relookup(a, d) for a, d in dns_relookup]
            )
            for (
                ags,
                mx,
                spf,
                spf_resolved,
                mx_cnames,
                mx_asns,
                provider,
                backend,
                gateway,
                autodiscover,
            ) in results:
                muni[ags]["mx"] = mx
                muni[ags]["spf"] = spf
                muni[ags]["provider"] = provider
                if backend:
                    muni[ags]["backend"] = backend
                if spf_resolved and spf_resolved != spf:
                    muni[ags]["spf_resolved"] = spf_resolved
                if gateway:
                    muni[ags]["gateway"] = gateway
                if mx_cnames:
                    muni[ags]["mx_cnames"] = mx_cnames
                if mx_asns:
                    muni[ags]["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    muni[ags]["autodiscover"] = autodiscover
                print(
                    f"  {ags:>8} {muni[ags]['name']:<30} -> {provider} (DNS re-lookup)"
                )

    # Step 2: Retry DNS for unknowns that have a domain
    dns_retry_candidates = [
        m for m in muni.values() if m["provider"] == "unknown" and m.get("domain")
    ]
    if dns_retry_candidates:
        print(f"\nRetrying DNS for {len(dns_retry_candidates)} unknown domains...")
        for m in dns_retry_candidates:
            mx = await lookup_mx(m["domain"])
            if mx:
                spf = await lookup_spf(m["domain"])
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(m["domain"])
                provider, backend = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                if backend:
                    m["backend"] = backend
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                print(
                    f"  RECOVERED {m['ags']:>8} {m['name']:<30} -> {provider}"
                )

    # Step 2.5: SMTP banner check for independent/unknown with MX records
    smtp_candidates = [
        m
        for m in muni.values()
        if m["provider"] in ("independent", "unknown") and m.get("mx")
    ]
    if smtp_candidates:
        # Deduplicate: map each unique MX host -> list of AGS numbers
        mx_host_to_ags: dict[str, list[str]] = {}
        for m in smtp_candidates:
            primary_mx = m["mx"][0]
            mx_host_to_ags.setdefault(primary_mx, []).append(m["ags"])

        print(
            f"\nSMTP banner check: {len(smtp_candidates)} entries, "
            f"{len(mx_host_to_ags)} unique MX hosts..."
        )
        smtp_semaphore = asyncio.Semaphore(CONCURRENCY_SMTP)

        async def _fetch_banner(mx_host: str) -> tuple[str, dict[str, str]]:
            async with smtp_semaphore:
                res = await fetch_smtp_banner(mx_host)
                return mx_host, res

        banner_results = await asyncio.gather(
            *[_fetch_banner(host) for host in mx_host_to_ags]
        )

        smtp_reclassified = 0
        for mx_host, result in banner_results:
            banner = result.get("banner", "")
            ehlo = result.get("ehlo", "")
            if not banner:
                continue
            provider = classify_from_smtp_banner(banner, ehlo)
            for ags in mx_host_to_ags[mx_host]:
                muni[ags]["smtp_banner"] = banner
                if provider and muni[ags]["provider"] in ("independent", "unknown"):
                    old = muni[ags]["provider"]
                    muni[ags]["provider"] = provider
                    smtp_reclassified += 1
                    print(
                        f"  SMTP     {ags:>8} {muni[ags]['name']:<30} "
                        f"{old} -> {provider} ({mx_host})"
                    )

        print(f"  SMTP reclassified: {smtp_reclassified}")

    # Step 3: Scrape remaining unknowns
    unknowns = [m for m in muni.values() if m["provider"] == "unknown"]
    print(f"\n{len(unknowns)} unknown municipalities to investigate\n")

    if unknowns:
        semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)
        async with httpx.AsyncClient(
            headers={
                "User-Agent": "mx-map.de/1.0 (https://github.com/sebbo/mx-map-de)"
            },
            follow_redirects=True,
        ) as client:
            tasks = [process_unknown(client, semaphore, m) for m in unknowns]
            results = await asyncio.gather(*tasks)

        resolved = 0
        for m in results:
            muni[m["ags"]] = m
            if m["provider"] != "unknown":
                resolved += 1
        print(f"\nResolved {resolved}/{len(unknowns)} via scraping")

    # Recompute counts
    counts = {}
    for m in muni.values():
        counts[m["provider"]] = counts.get(m["provider"], 0) + 1
    data["counts"] = dict(sorted(counts.items()))
    data["total"] = len(muni)
    data["municipalities"] = dict(sorted(muni.items(), key=lambda kv: kv[0]))

    remaining = counts.get("unknown", 0)
    print(f"\nFinal counts: {json.dumps(counts)}")

    if remaining > 0:
        print(f"\nStill unknown ({remaining}, for manual review):")
        for m in sorted(muni.values(), key=lambda x: x["ags"]):
            if m["provider"] == "unknown":
                print(
                    f"  {m['ags']:>8}  {m['name']:<30} {m['state']:<20} domain={m['domain']}"
                )

    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"\nUpdated {data_path}")
