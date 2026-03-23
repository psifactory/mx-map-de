import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import classify
from mail_sovereignty.constants import (
    CONCURRENCY,
    CONCURRENCY_WEBSITE,
    DKIM_SELECTORS,
    SPARQL_QUERY,
    SPARQL_QUERY_COUNTIES,
    SPARQL_URL,
)
from mail_sovereignty.dns import (
    check_dnssec,
    check_ipv6_mx,
    detect_spf_strictness,
    lookup_autodiscover,
    lookup_bimi,
    lookup_dane,
    lookup_dkim,
    lookup_dmarc,
    lookup_mta_sts,
    lookup_mx,
    lookup_spf,
    lookup_srv_records,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
    scan_website,
)


def url_to_domain(url: str | None) -> str | None:
    """Extract the base domain from a URL."""
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def guess_domains(name: str) -> list[str]:
    """Generate a small set of plausible domain guesses for a German municipality."""
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    # German umlaut transliteration
    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
    de = de.replace("\u00df", "ss")

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slugs = {slugify(de), slugify(raw)} - {""}
    candidates = set()
    for slug in slugs:
        candidates.add(f"{slug}.de")
        candidates.add(f"gemeinde-{slug}.de")
        candidates.add(f"stadt-{slug}.de")
    return sorted(candidates)


async def fetch_wikidata() -> dict[str, dict[str, Any]]:
    """Query Wikidata for all German municipalities."""
    print("Querying Wikidata for German municipalities...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap-DE/1.0 (https://github.com/sebbo/mx-map-de)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            SPARQL_URL,
            data={"query": SPARQL_QUERY},
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()

    municipalities = {}
    for row in data["results"]["bindings"]:
        ags = row["ags"]["value"]
        name = row.get("itemLabel", {}).get("value", f"AGS-{ags}")
        website = row.get("website", {}).get("value", "")
        state = row.get("stateLabel", {}).get("value", "")

        # Extract coordinates if available
        coord = row.get("coord", {}).get("value", "")
        lat, lon = "", ""
        if coord:
            # Format: Point(lon lat)
            match = re.match(r"Point\(([-\d.]+)\s+([-\d.]+)\)", coord)
            if match:
                lon, lat = match.group(1), match.group(2)

        if ags not in municipalities:
            municipalities[ags] = {
                "ags": ags,
                "name": name,
                "website": website,
                "state": state,
                "lat": lat,
                "lon": lon,
            }
        elif not municipalities[ags]["website"] and website:
            municipalities[ags]["website"] = website

    print(
        f"  Found {len(municipalities)} municipalities, "
        f"{sum(1 for m in municipalities.values() if m['website'])} with websites"
    )
    return municipalities


async def fetch_wikidata_counties() -> dict[str, dict[str, Any]]:
    """Query Wikidata for all German counties (Landkreise) and independent cities (kreisfreie Städte)."""
    print("Querying Wikidata for German counties...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap-DE/1.0 (https://github.com/sebbo/mx-map-de)",
    }
    async with httpx.AsyncClient(timeout=120) as client:
        r = await client.post(
            SPARQL_URL,
            data={"query": SPARQL_QUERY_COUNTIES},
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()

    counties: dict[str, dict[str, Any]] = {}
    for row in data["results"]["bindings"]:
        ags = row["ags"]["value"]
        name = row.get("itemLabel", {}).get("value", f"AGS-{ags}")
        website = row.get("website", {}).get("value", "")
        state = row.get("stateLabel", {}).get("value", "")
        type_label = row.get("typeLabel", {}).get("value", "")

        coord = row.get("coord", {}).get("value", "")
        lat, lon = "", ""
        if coord:
            match = re.match(r"Point\(([-\d.]+)\s+([-\d.]+)\)", coord)
            if match:
                lon, lat = match.group(1), match.group(2)

        county_type = "Kreisfreie Stadt" if "kreisfrei" in type_label.lower() else "Landkreis"

        if ags not in counties:
            counties[ags] = {
                "ags": ags,
                "name": name,
                "website": website,
                "state": state,
                "type": county_type,
                "lat": lat,
                "lon": lon,
            }
        elif not counties[ags]["website"] and website:
            counties[ags]["website"] = website

    print(
        f"  Found {len(counties)} counties/independent cities, "
        f"{sum(1 for c in counties.values() if c['website'])} with websites"
    )
    return counties


def guess_county_domains(name: str, county_type: str) -> list[str]:
    """Generate plausible domain guesses for a German county or independent city."""
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)

    de = raw.replace("\u00fc", "ue").replace("\u00e4", "ae").replace("\u00f6", "oe")
    de = de.replace("\u00df", "ss")

    def slugify(s: str) -> str:
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slugs = {slugify(de), slugify(raw)} - {""}
    candidates: set[str] = set()
    for slug in slugs:
        candidates.add(f"{slug}.de")
        if county_type == "Landkreis":
            candidates.add(f"landkreis-{slug}.de")
            candidates.add(f"kreis-{slug}.de")
            candidates.add(f"lk-{slug}.de")
        else:
            candidates.add(f"stadt-{slug}.de")
    return sorted(candidates)


async def scan_county(
    c: dict[str, Any], semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """Scan a single county/independent city for email provider info."""
    async with semaphore:
        domain = url_to_domain(c.get("website", ""))
        mx, spf = [], ""

        if domain:
            mx = await lookup_mx(domain)
            if mx:
                spf = await lookup_spf(domain)

        if not mx:
            for guess in guess_county_domains(c["name"], c.get("type", "")):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                if mx:
                    domain = guess
                    spf = await lookup_spf(guess)
                    break

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}

        if domain:
            coros: list[Any] = [
                lookup_dmarc(domain),
                lookup_dkim(domain, DKIM_SELECTORS),
                lookup_dane(domain, mx) if mx else _noop(False),
                lookup_bimi(domain),
                lookup_mta_sts(domain),
                lookup_srv_records(domain),
                check_dnssec(domain),
                check_ipv6_mx(mx) if mx else _noop(False),
            ]
            dmarc, dkim_results, dane, bimi, mta_sts, srv_records, dnssec, ipv6_mx = (
                await asyncio.gather(*coros)
            )
        else:
            dmarc, dkim_results, dane, bimi, mta_sts = None, [], False, None, False
            srv_records, dnssec, ipv6_mx = {}, False, False

        dkim_sels = [d["selector"] for d in dkim_results] if dkim_results else None
        cls = classify(
            mx,
            spf,
            mx_cnames=mx_cnames,
            mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None,
            autodiscover=autodiscover or None,
            domain=domain or None,
            dkim_selectors=dkim_sels,
        )
        provider = cls["provider"]
        backend = cls.get("backend")
        gateway = cls.get("gateway")
        spf_strictness = detect_spf_strictness(spf)

        entry: dict[str, Any] = {
            "ags": c["ags"],
            "name": c["name"],
            "type": c.get("type", ""),
            "state": c.get("state", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
        }
        if backend:
            entry["backend"] = backend
        if c.get("lat") and c.get("lon"):
            entry["lat"] = float(c["lat"])
            entry["lon"] = float(c["lon"])
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        if dmarc:
            entry["dmarc"] = dmarc
        if dkim_results:
            entry["dkim_selectors"] = [d["selector"] for d in dkim_results]
        if dane:
            entry["dane"] = True
        if bimi:
            entry["bimi"] = bimi
        if mta_sts:
            entry["mta_sts"] = True
        if srv_records:
            entry["srv_records"] = srv_records
        if dnssec:
            entry["dnssec"] = True
        if ipv6_mx:
            entry["ipv6_mx"] = True
        if spf_strictness != "none":
            entry["spf_strictness"] = spf_strictness
        return entry


async def _noop(value: Any) -> Any:
    """Return a static value as a coroutine (for asyncio.gather placeholders)."""
    return value


async def scan_municipality(
    m: dict[str, Any], semaphore: asyncio.Semaphore
) -> dict[str, Any]:
    """Scan a single municipality for email provider info."""
    async with semaphore:
        domain = url_to_domain(m.get("website", ""))
        mx, spf = [], ""

        if domain:
            mx = await lookup_mx(domain)
            if mx:
                spf = await lookup_spf(domain)

        if not mx:
            for guess in guess_domains(m["name"]):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                if mx:
                    domain = guess
                    spf = await lookup_spf(guess)
                    break

        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}

        # Security checks (run in parallel)
        if domain:
            coros: list[Any] = [
                lookup_dmarc(domain),
                lookup_dkim(domain, DKIM_SELECTORS),
                lookup_dane(domain, mx) if mx else _noop(False),
                lookup_bimi(domain),
                lookup_mta_sts(domain),
                lookup_srv_records(domain),
                check_dnssec(domain),
                check_ipv6_mx(mx) if mx else _noop(False),
            ]
            dmarc, dkim_results, dane, bimi, mta_sts, srv_records, dnssec, ipv6_mx = (
                await asyncio.gather(*coros)
            )
        else:
            dmarc, dkim_results, dane, bimi, mta_sts = None, [], False, None, False
            srv_records, dnssec, ipv6_mx = {}, False, False

        dkim_sels = [d["selector"] for d in dkim_results] if dkim_results else None
        cls = classify(
            mx,
            spf,
            mx_cnames=mx_cnames,
            mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None,
            autodiscover=autodiscover or None,
            domain=domain or None,
            dkim_selectors=dkim_sels,
        )
        provider = cls["provider"]
        backend = cls.get("backend")
        gateway = cls.get("gateway")
        spf_strictness = detect_spf_strictness(spf)

        entry: dict[str, Any] = {
            "ags": m["ags"],
            "name": m["name"],
            "state": m.get("state", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
        }
        if backend:
            entry["backend"] = backend
        if m.get("lat") and m.get("lon"):
            entry["lat"] = float(m["lat"])
            entry["lon"] = float(m["lon"])
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        if dmarc:
            entry["dmarc"] = dmarc
        if dkim_results:
            entry["dkim_selectors"] = [d["selector"] for d in dkim_results]
        if dane:
            entry["dane"] = True
        if bimi:
            entry["bimi"] = bimi
        if mta_sts:
            entry["mta_sts"] = True
        if srv_records:
            entry["srv_records"] = srv_records
        if dnssec:
            entry["dnssec"] = True
        if ipv6_mx:
            entry["ipv6_mx"] = True
        if spf_strictness != "none":
            entry["spf_strictness"] = spf_strictness
        return entry


async def _scan_websites_batch(
    label: str,
    results: dict[str, Any],
    log_interval: int = 100,
) -> None:
    """Scan websites for all entries with domains, adding hosting/CMS/tracker data."""
    entries_with_domains = [e for e in results.values() if e.get("domain")]
    total = len(entries_with_domains)
    if not total:
        return
    print(f"\nScanning {total} {label} websites for hosting/CMS/trackers...")

    semaphore = asyncio.Semaphore(CONCURRENCY_WEBSITE)
    done = 0

    async def _scan_one(entry: dict[str, Any]) -> None:
        nonlocal done
        async with semaphore:
            await asyncio.sleep(0.1)  # 100ms rate limit
            ws = await scan_website(entry["domain"])
            if ws:
                for k, v in ws.items():
                    entry[k] = v
            done += 1
            if done % log_interval == 0 or done == total:
                print(f"  [{done:5d}/{total}] websites scanned")

    await asyncio.gather(*[_scan_one(e) for e in entries_with_domains])
    print(f"  Website scan complete for {label}")


def _print_summary(label: str, results: dict[str, Any], counts: dict[str, int]) -> None:
    print(f"\n{'=' * 60}")
    print(f"RESULTS: {len(results)} {label} scanned")
    print(f"  Microsoft/Azure : {counts.get('microsoft', 0):>5}")
    print(f"  Google/GCP      : {counts.get('google', 0):>5}")
    print(f"  IONOS/1&1       : {counts.get('ionos', 0):>5}")
    print(f"  Strato          : {counts.get('strato', 0):>5}")
    print(f"  Hetzner         : {counts.get('hetzner', 0):>5}")
    print(f"  Telekom         : {counts.get('telekom', 0):>5}")
    print(f"  AWS             : {counts.get('aws', 0):>5}")
    print(f"  Kommunal        : {counts.get('kommunal', 0):>5}")
    print(f"  Hornetsecurity  : {counts.get('hornetsecurity', 0):>5}")
    print(f"  Sophos          : {counts.get('sophos', 0):>5}")
    print(f"  Barracuda       : {counts.get('barracuda', 0):>5}")
    print(f"  Proofpoint      : {counts.get('proofpoint', 0):>5}")
    print(f"  AntiSpam Europe : {counts.get('antispameurope', 0):>5}")
    print(f"  Mimecast        : {counts.get('mimecast', 0):>5}")
    print(f"  German ISP      : {counts.get('german-isp', 0):>5}")
    print(f"  Independent     : {counts.get('independent', 0):>5}")
    print(f"  Unknown/No MX   : {counts.get('unknown', 0):>5}")
    print(f"{'=' * 60}")


async def _scan_batch(
    label: str,
    items: dict[str, dict[str, Any]],
    scan_fn: Any,
    semaphore: asyncio.Semaphore,
    log_interval: int = 100,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Run scan_fn over all items and return (results, counts)."""
    total = len(items)
    print(f"\nScanning {total} {label} for MX/SPF records...")
    print("(This takes a few minutes with async lookups)\n")

    tasks = [scan_fn(item, semaphore) for item in items.values()]
    results: dict[str, Any] = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["ags"]] = result
        done += 1
        if done % log_interval == 0 or done == total:
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(
                f"  [{done:5d}/{total}]  "
                f"MS={counts.get('microsoft', 0)}  "
                f"Google={counts.get('google', 0)}  "
                f"IONOS={counts.get('ionos', 0)}  "
                f"Strato={counts.get('strato', 0)}  "
                f"Hetzner={counts.get('hetzner', 0)}  "
                f"Indep={counts.get('independent', 0)}  "
                f"?={counts.get('unknown', 0)}"
            )

    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1
    return results, counts


async def run(output_path: Path) -> None:
    municipalities = await fetch_wikidata()
    counties = await fetch_wikidata_counties()

    semaphore = asyncio.Semaphore(CONCURRENCY)

    # Scan municipalities
    muni_results, muni_counts = await _scan_batch(
        "municipalities", municipalities, scan_municipality, semaphore,
    )
    _print_summary("municipalities", muni_results, muni_counts)

    # Scan counties
    county_results, county_counts = await _scan_batch(
        "counties", counties, scan_county, semaphore, log_interval=50,
    )
    _print_summary("counties", county_results, county_counts)

    # Website scanning (hosting, CMS, trackers, consent)
    await _scan_websites_batch("municipalities", muni_results)
    await _scan_websites_batch("counties", county_results, log_interval=50)

    sorted_muni_counts = dict(sorted(muni_counts.items()))
    sorted_munis = dict(sorted(muni_results.items(), key=lambda kv: kv[0]))
    sorted_county_counts = dict(sorted(county_counts.items()))
    sorted_counties = dict(sorted(county_results.items(), key=lambda kv: kv[0]))

    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(muni_results),
        "counts": sorted_muni_counts,
        "municipalities": sorted_munis,
        "county_total": len(county_results),
        "county_counts": sorted_county_counts,
        "counties": sorted_counties,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))

    size_kb = len(json.dumps(output)) / 1024
    print(f"\nWritten {output_path} ({size_kb:.0f} KB)")
