#!/usr/bin/env python3
"""Test the pipeline with a small sample of 10 German municipalities.

Usage: uv run python scripts/test_sample.py
"""

import asyncio
import json
import time
from pathlib import Path

from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)
from mail_sovereignty.preprocess import url_to_domain, guess_domains

# 10 German municipalities of various sizes and regions
SAMPLE_MUNICIPALITIES = [
    {"ags": "11000000", "name": "Berlin", "website": "https://www.berlin.de", "state": "Berlin"},
    {"ags": "02000000", "name": "Hamburg", "website": "https://www.hamburg.de", "state": "Hamburg"},
    {"ags": "09162000", "name": "München", "website": "https://www.muenchen.de", "state": "Bayern"},
    {"ags": "05315000", "name": "Köln", "website": "https://www.stadt-koeln.de", "state": "Nordrhein-Westfalen"},
    {"ags": "06412000", "name": "Frankfurt am Main", "website": "https://www.frankfurt.de", "state": "Hessen"},
    {"ags": "08111000", "name": "Stuttgart", "website": "https://www.stuttgart.de", "state": "Baden-Württemberg"},
    {"ags": "14612000", "name": "Dresden", "website": "https://www.dresden.de", "state": "Sachsen"},
    {"ags": "03241001", "name": "Hannover", "website": "https://www.hannover.de", "state": "Niedersachsen"},
    {"ags": "01051043", "name": "Fehmarn", "website": "https://www.fehmarn.de", "state": "Schleswig-Holstein"},
    {"ags": "07111000", "name": "Koblenz", "website": "https://www.koblenz.de", "state": "Rheinland-Pfalz"},
]


async def scan_one(m: dict) -> dict:
    """Scan a single municipality."""
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
    provider = classify(
        mx,
        spf,
        mx_cnames=mx_cnames,
        mx_asns=mx_asns or None,
        resolved_spf=spf_resolved or None,
        autodiscover=autodiscover or None,
    )
    gateway = detect_gateway(mx) if mx else None

    return {
        "ags": m["ags"],
        "name": m["name"],
        "state": m["state"],
        "domain": domain or "",
        "mx": mx,
        "spf": spf,
        "provider": provider,
        "gateway": gateway,
    }


async def main():
    print("=" * 60)
    print("  MX-Map.de Test-Pipeline: 10 deutsche Gemeinden")
    print("=" * 60)

    results = {}
    for m in SAMPLE_MUNICIPALITIES:
        print(f"\n  Scanning {m['name']} ({m['ags']})...")
        result = await scan_one(m)
        results[result["ags"]] = result
        print(
            f"    Domain:   {result['domain']}"
            f"\n    MX:       {', '.join(result['mx']) or 'none'}"
            f"\n    Provider: {result['provider']}"
            + (f"\n    Gateway:  {result['gateway']}" if result['gateway'] else "")
        )

    # Summary
    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 60}")
    print("  ZUSAMMENFASSUNG")
    print(f"{'=' * 60}")
    for provider, count in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"    {provider:<20} {count}")

    # Write sample data.json
    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": dict(sorted(counts.items())),
        "municipalities": dict(sorted(results.items())),
    }

    output_path = Path("data_sample.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)

    print(f"\n  Ergebnis gespeichert in {output_path}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    asyncio.run(main())
