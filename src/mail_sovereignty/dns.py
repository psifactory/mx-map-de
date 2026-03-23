import asyncio
import logging
import re
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from mail_sovereignty.constants import (
    CMS_HEADER_PATTERNS,
    CMS_URL_PATTERNS,
    CONSENT_PATTERNS,
    HOSTING_PROVIDER_ASNS,
    TRACKER_PATTERNS,
)

logger = logging.getLogger(__name__)

_resolvers = None

_RETRYABLE = (dns.exception.Timeout, dns.resolver.NoAnswer, dns.resolver.NoNameservers)


def make_resolvers() -> list[dns.asyncresolver.Resolver]:
    """Create a list of async resolvers pointing to different DNS servers."""
    resolvers = []
    for nameservers in [None, ["8.8.8.8", "8.8.4.4"], ["1.1.1.1", "1.0.0.1"]]:
        r = dns.asyncresolver.Resolver()
        if nameservers:
            r.nameservers = nameservers
        r.timeout = 10
        r.lifetime = 15
        resolvers.append(r)
    return resolvers


def get_resolvers() -> list[dns.asyncresolver.Resolver]:
    global _resolvers
    if _resolvers is None:
        _resolvers = make_resolvers()
    return _resolvers


async def lookup_mx(domain: str) -> list[str]:
    """Return list of MX exchange hostnames."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "MX")
            return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "MX %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("MX %s: all resolvers failed", domain)
    return []


async def lookup_spf(domain: str) -> str:
    """Return the SPF TXT record if found."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, "TXT")
            spf_records = []
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if txt.lower().startswith("v=spf1"):
                    spf_records.append(txt)
            if spf_records:
                return sorted(spf_records)[0]
            return ""
        except dns.resolver.NXDOMAIN:
            return ""
        except _RETRYABLE as e:
            logger.debug(
                "SPF %s: %s on resolver %d, retrying", domain, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("SPF %s: all resolvers failed", domain)
    return ""


_SPF_INCLUDE_RE = re.compile(r"\binclude:(\S+)", re.IGNORECASE)
_SPF_REDIRECT_RE = re.compile(r"\bredirect=(\S+)", re.IGNORECASE)


async def resolve_spf_includes(spf_record: str, max_lookups: int = 10) -> str:
    """Recursively resolve include: and redirect= directives in an SPF record.

    Returns the original SPF text concatenated with all resolved SPF texts.
    Uses BFS to follow nested includes. Tracks visited domains for loop
    detection and enforces a lookup limit.
    """
    if not spf_record:
        return ""

    initial_domains = _SPF_INCLUDE_RE.findall(spf_record) + _SPF_REDIRECT_RE.findall(
        spf_record
    )
    if not initial_domains:
        return spf_record

    visited: set[str] = set()
    parts = [spf_record]
    queue = list(initial_domains)
    lookups = 0

    while queue and lookups < max_lookups:
        domain = queue.pop(0).lower().rstrip(".")
        if domain in visited:
            continue
        visited.add(domain)
        lookups += 1
        resolved = await lookup_spf(domain)
        if resolved:
            parts.append(resolved)
            nested = _SPF_INCLUDE_RE.findall(resolved) + _SPF_REDIRECT_RE.findall(
                resolved
            )
            queue.extend(nested)

    return " ".join(parts)


async def lookup_cname_chain(hostname: str, max_hops: int = 10) -> list[str]:
    """Follow CNAME chain for hostname. Return list of targets (empty if no CNAME)."""
    resolvers = get_resolvers()
    chain = []
    current = hostname

    for _ in range(max_hops):
        resolved = False
        for i, resolver in enumerate(resolvers):
            try:
                answers = await resolver.resolve(current, "CNAME")
                target = str(list(answers)[0].target).rstrip(".").lower()
                chain.append(target)
                current = target
                resolved = True
                break
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                break
            except _RETRYABLE as e:
                logger.debug(
                    "CNAME %s: %s on resolver %d, retrying",
                    current,
                    type(e).__name__,
                    i,
                )
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        if not resolved:
            break

    return chain


async def resolve_mx_cnames(mx_hosts: list[str]) -> dict[str, str]:
    """For each MX host, follow CNAME chain. Return mapping of host -> final target (only for hosts with CNAMEs)."""
    result = {}
    for host in mx_hosts:
        chain = await lookup_cname_chain(host)
        if chain:
            result[host] = chain[-1]
    return result


async def lookup_a(hostname: str) -> list[str]:
    """Resolve hostname to IPv4 addresses via A record query."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(hostname, "A")
            return [str(r) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "A %s: %s on resolver %d, retrying", hostname, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("A %s: all resolvers failed", hostname)
    return []


async def lookup_asn_cymru(ip: str) -> int | None:
    """Query Team Cymru DNS for ASN number of an IP address."""
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.origin.asn.cymru.com"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(query, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                # Format: "3303 | 193.135.252.0/24 | CH | ripencc | ..."
                asn_str = txt.split("|")[0].strip()
                return int(asn_str)
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("ASN %s: %s on resolver %d, retrying", ip, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("ASN %s: all resolvers failed", ip)
    return None


async def lookup_srv(name: str) -> list[tuple[str, int]]:
    """Return list of (target, port) from SRV records."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(name, "SRV")
            return [(str(r.target).rstrip(".").lower(), r.port) for r in answers]
        except dns.resolver.NXDOMAIN:
            return []
        except _RETRYABLE as e:
            logger.debug(
                "SRV %s: %s on resolver %d, retrying", name, type(e).__name__, i
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("SRV %s: all resolvers failed", name)
    return []


async def lookup_autodiscover(domain: str) -> dict[str, str]:
    """Check autodiscover DNS records. Returns dict of record_type -> target."""
    cname_coro = lookup_cname_chain(f"autodiscover.{domain}", max_hops=1)
    srv_coro = lookup_srv(f"_autodiscover._tcp.{domain}")

    cname_result, srv_result = await asyncio.gather(cname_coro, srv_coro)

    result: dict[str, str] = {}
    if cname_result:
        result["autodiscover_cname"] = cname_result[-1]
    if srv_result:
        result["autodiscover_srv"] = srv_result[0][0]
    return result


async def resolve_mx_asns(mx_hosts: list[str]) -> set[int]:
    """Resolve all MX hosts to IPs, look up ASNs, return set of unique ASNs."""
    asns = set()
    for host in mx_hosts:
        ips = await lookup_a(host)
        for ip in ips:
            asn = await lookup_asn_cymru(ip)
            if asn is not None:
                asns.add(asn)
    return asns


_DMARC_TAG_RE = re.compile(r";\s*")


async def lookup_dmarc(domain: str) -> dict[str, Any] | None:
    """Query _dmarc.{domain} TXT and parse policy, rua, pct."""
    qname = f"_dmarc.{domain}"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(qname, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if not txt.lower().startswith("v=dmarc1"):
                    continue
                tags = {}
                for part in _DMARC_TAG_RE.split(txt):
                    if "=" in part:
                        k, _, v = part.partition("=")
                        tags[k.strip().lower()] = v.strip()
                return {
                    "policy": tags.get("p", ""),
                    "rua": tags.get("rua", ""),
                    "pct": tags.get("pct", ""),
                    "raw": txt,
                }
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("DMARC %s: %s on resolver %d, retrying", domain, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("DMARC %s: all resolvers failed", domain)
    return None


async def lookup_dkim(domain: str, selectors: list[str]) -> list[dict[str, str]]:
    """Probe common DKIM selectors and return list of found ones."""
    found = []

    async def _check(selector: str) -> dict[str, str] | None:
        qname = f"{selector}._domainkey.{domain}"
        resolvers = get_resolvers()
        for i, resolver in enumerate(resolvers):
            try:
                answers = await resolver.resolve(qname, "TXT")
                txt = b"".join(list(answers)[0].strings).decode("utf-8", errors="ignore")
                return {"selector": selector, "value": txt}
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return None
            except _RETRYABLE:
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        return None

    results = await asyncio.gather(*[_check(s) for s in selectors])
    for r in results:
        if r is not None:
            found.append(r)
    return found


async def lookup_dane(domain: str, mx_hosts: list[str]) -> bool:
    """Check if any MX host has a TLSA record at _25._tcp.{mx_host}."""
    resolvers = get_resolvers()

    async def _check(mx_host: str) -> bool:
        qname = f"_25._tcp.{mx_host}"
        for i, resolver in enumerate(resolvers):
            try:
                await resolver.resolve(qname, dns.rdatatype.RdataType.TLSA)
                return True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except _RETRYABLE:
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        return False

    results = await asyncio.gather(*[_check(h) for h in mx_hosts])
    return any(results)


async def lookup_bimi(domain: str) -> dict[str, str] | None:
    """Query default._bimi.{domain} TXT for a BIMI record."""
    qname = f"default._bimi.{domain}"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(qname, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=bimi1" in txt.lower():
                    logo = ""
                    for part in txt.split(";"):
                        part = part.strip()
                        if part.lower().startswith("l="):
                            logo = part[2:].strip()
                    return {"logo": logo} if logo else {"logo": ""}
            return None
        except dns.resolver.NXDOMAIN:
            return None
        except _RETRYABLE as e:
            logger.debug("BIMI %s: %s on resolver %d, retrying", domain, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("BIMI %s: all resolvers failed", domain)
    return None


async def lookup_srv_records(domain: str) -> dict[str, bool]:
    """Check well-known SRV records for collaboration services."""
    srv_checks = {
        "teams": f"_sipfederationtls._tcp.{domain}",
        "sip": f"_sip._tls.{domain}",
        "caldav": f"_caldavs._tcp.{domain}",
        "carddav": f"_carddavs._tcp.{domain}",
        "autodiscover": f"_autodiscover._tcp.{domain}",
    }

    async def _check(key: str, qname: str) -> tuple[str, bool]:
        result = await lookup_srv(qname)
        return key, len(result) > 0

    results = await asyncio.gather(*[_check(k, q) for k, q in srv_checks.items()])
    found = {k: v for k, v in results if v}
    return found


async def check_dnssec(domain: str) -> bool:
    """Check if DNSSEC is active for a domain by querying for DNSKEY records."""
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(domain, dns.rdatatype.RdataType.DNSKEY)
            if answers:
                return True
            return False
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer,):
            return False
        except _RETRYABLE as e:
            logger.debug(
                "DNSSEC %s: %s on resolver %d, retrying",
                domain,
                type(e).__name__,
                i,
            )
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("DNSSEC %s: all resolvers failed", domain)
    return False


async def check_ipv6_mx(mx_hosts: list[str]) -> bool:
    """Check if at least one MX host has an AAAA (IPv6) record."""
    resolvers = get_resolvers()

    async def _check(host: str) -> bool:
        for i, resolver in enumerate(resolvers):
            try:
                answers = await resolver.resolve(host, "AAAA")
                if answers:
                    return True
                return False
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except _RETRYABLE:
                await asyncio.sleep(0.5)
                continue
            except Exception:
                continue
        return False

    results = await asyncio.gather(*[_check(h) for h in mx_hosts])
    return any(results)


def detect_spf_strictness(spf: str) -> str:
    """Parse SPF record and return strictness level."""
    if not spf:
        return "none"
    spf_lower = spf.strip().lower()
    if spf_lower.endswith("-all"):
        return "strict"
    if spf_lower.endswith("~all"):
        return "softfail"
    if spf_lower.endswith("?all"):
        return "neutral"
    if spf_lower.endswith("+all"):
        return "open"
    # Check with regex for cases like '-all' not at the very end
    if re.search(r"\s-all\b", spf_lower):
        return "strict"
    if re.search(r"\s~all\b", spf_lower):
        return "softfail"
    if re.search(r"\s\?all\b", spf_lower):
        return "neutral"
    if re.search(r"\s\+all\b", spf_lower):
        return "open"
    return "none"


async def lookup_mta_sts(domain: str) -> bool:
    """Check if _mta-sts.{domain} TXT record exists."""
    qname = f"_mta-sts.{domain}"
    resolvers = get_resolvers()
    for i, resolver in enumerate(resolvers):
        try:
            answers = await resolver.resolve(qname, "TXT")
            for r in answers:
                txt = b"".join(r.strings).decode("utf-8", errors="ignore")
                if "v=ststs" in txt.lower().replace(" ", ""):
                    return True
            return False
        except dns.resolver.NXDOMAIN:
            return False
        except _RETRYABLE as e:
            logger.debug("MTA-STS %s: %s on resolver %d, retrying", domain, type(e).__name__, i)
            await asyncio.sleep(0.5)
            continue
        except Exception:
            continue
    logger.info("MTA-STS %s: all resolvers failed", domain)
    return False


def _detect_cms(headers: dict[str, str], body: str) -> str:
    """Detect CMS from HTTP response headers and body."""
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    # Check headers (Server, X-Powered-By, X-Generator)
    for cms, patterns in CMS_HEADER_PATTERNS.items():
        for p in patterns:
            if p in combined:
                return cms

    # Check HTML meta generator
    body_lower = body.lower()
    gen_match = re.search(
        r'<meta\s[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        body_lower,
    )
    if not gen_match:
        gen_match = re.search(
            r'<meta\s[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
            body_lower,
        )
    if gen_match:
        gen_val = gen_match.group(1)
        for cms, patterns in CMS_HEADER_PATTERNS.items():
            for p in patterns:
                if p in gen_val:
                    return cms

    # Check URL patterns in body
    for cms, patterns in CMS_URL_PATTERNS.items():
        for p in patterns:
            if p in body_lower:
                return cms

    return "unbekannt"


def _detect_trackers(body: str) -> list[str]:
    """Detect analytics/tracker scripts in HTML body."""
    found = []
    body_lower = body.lower()
    for tracker, patterns in TRACKER_PATTERNS.items():
        for p in patterns:
            if p.lower() in body_lower:
                found.append(tracker)
                break
    return found if found else []


def _detect_consent(body: str) -> str:
    """Detect cookie consent banner in HTML body."""
    body_lower = body.lower()
    for consent, patterns in CONSENT_PATTERNS.items():
        for p in patterns:
            if p.lower() in body_lower:
                return consent
    return ""


async def scan_website(domain: str) -> dict[str, Any] | None:
    """Scan a domain's website for hosting provider, CMS, trackers, and consent.

    Returns None if the website is unreachable.
    """
    if not domain:
        return None

    result: dict[str, Any] = {}

    # 1. Hosting provider from A record → ASN
    ips = await lookup_a(domain)
    if ips:
        asn = await lookup_asn_cymru(ips[0])
        if asn is not None:
            provider = HOSTING_PROVIDER_ASNS.get(asn, "sonstige")
            result["website_hosting"] = {
                "provider": provider,
                "ip": ips[0],
                "asn": asn,
            }
        else:
            result["website_hosting"] = {"provider": "sonstige", "ip": ips[0], "asn": None}
    else:
        result["website_hosting"] = {"provider": "sonstige", "ip": "", "asn": None}

    # 2-4. HTTP request for CMS, trackers, consent
    try:
        async with httpx.AsyncClient(
            timeout=10,
            follow_redirects=True,
            max_redirects=3,
            headers={"User-Agent": "mx-map.de/1.0 (DNS Transparency Project)"},
            verify=True,
        ) as client:
            resp = await client.get(f"https://{domain}/")
            result["website_https"] = True
            result["website_server"] = resp.headers.get("server", "")
            body = resp.text
            headers = dict(resp.headers)
    except Exception:
        # Try HTTP fallback
        try:
            async with httpx.AsyncClient(
                timeout=10,
                follow_redirects=True,
                max_redirects=3,
                headers={"User-Agent": "mx-map.de/1.0 (DNS Transparency Project)"},
                verify=False,
            ) as client:
                resp = await client.get(f"http://{domain}/")
                result["website_https"] = False
                result["website_server"] = resp.headers.get("server", "")
                body = resp.text
                headers = dict(resp.headers)
        except Exception:
            return result if result.get("website_hosting") else None

    result["website_cms"] = _detect_cms(headers, body)
    result["website_analytics"] = _detect_trackers(body)
    result["website_consent"] = _detect_consent(body)

    return result
