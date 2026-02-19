#!/usr/bin/env python3
"""
sitemap_to_csv.py

Reads a sitemap OR sitemap index, expands to all <url><loc> entries,
and outputs a single CSV sorted alphabetically by URL path.

Usage:
  pip install requests lxml
  python sitemap_to_csv.py https://example.com/sitemap.xml
  python sitemap_to_csv.py https://example.com/sitemap_index.xml --out sitemap_urls.csv
  python sitemap_to_csv.py https://example.com/sitemap.xml --include-query

CSV columns:
  url, scheme, host, path, query
"""

from __future__ import annotations

import argparse
import csv
import sys
from typing import List, Set, Tuple
from urllib.parse import urlparse

import requests
from lxml import etree


XML_PARSER = etree.XMLParser(recover=True, huge_tree=True)


def fetch_text(session: requests.Session, url: str, timeout: int) -> str:
    resp = session.get(url, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()
    return resp.text


def parse_sitemap(xml_text: str) -> Tuple[List[str], List[str]]:
    """
    Returns: (sitemap_urls, page_urls)
    Handles:
      - <sitemapindex> containing <sitemap><loc>...</loc></sitemap>
      - <urlset> containing <url><loc>...</loc></url>
    """
    root = etree.fromstring(xml_text.encode("utf-8", errors="ignore"), parser=XML_PARSER)
    tag = etree.QName(root).localname.lower()

    sitemap_urls: List[str] = []
    page_urls: List[str] = []

    if tag == "sitemapindex":
        for loc in root.xpath("//*[local-name()='sitemap']/*[local-name()='loc']/text()"):
            if isinstance(loc, str) and loc.strip():
                sitemap_urls.append(loc.strip())
    elif tag == "urlset":
        for loc in root.xpath("//*[local-name()='url']/*[local-name()='loc']/text()"):
            if isinstance(loc, str) and loc.strip():
                page_urls.append(loc.strip())
    else:
        # Fallback if root tag is non-standard
        sitemap_locs = root.xpath("//*[local-name()='sitemap']/*[local-name()='loc']/text()")
        url_locs = root.xpath("//*[local-name()='url']/*[local-name()='loc']/text()")
        if sitemap_locs:
            sitemap_urls = [s.strip() for s in sitemap_locs if isinstance(s, str) and s.strip()]
        if url_locs:
            page_urls = [u.strip() for u in url_locs if isinstance(u, str) and u.strip()]

    return sitemap_urls, page_urls


def expand_sitemaps(session: requests.Session, base_sitemap_url: str, timeout: int, max_sitemaps: int = 10000) -> List[str]:
    """
    Recursively expand sitemap indexes into a flat list of page URLs.
    De-dupes while preserving first-seen order.
    """
    seen_sitemaps: Set[str] = set()
    to_process: List[str] = [base_sitemap_url]
    all_pages: List[str] = []

    while to_process:
        sm_url = to_process.pop()
        if sm_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sm_url)

        xml_text = fetch_text(session, sm_url, timeout=timeout)
        sitemap_urls, page_urls = parse_sitemap(xml_text)

        if sitemap_urls:
            for u in sitemap_urls:
                if u not in seen_sitemaps:
                    to_process.append(u)
        if page_urls:
            all_pages.extend(page_urls)

        if len(seen_sitemaps) > max_sitemaps:
            raise RuntimeError(f"Exceeded max_sitemaps={max_sitemaps}. Aborting to prevent runaway crawl.")

    # De-dupe pages while preserving order
    deduped: List[str] = []
    seen_pages: Set[str] = set()
    for u in all_pages:
        if u not in seen_pages:
            seen_pages.add(u)
            deduped.append(u)
    return deduped


def sort_key_for_url(u: str, include_query: bool) -> Tuple[str, str, str]:
    """
    Sort by path (alphabetical), then host, then full URL as tiebreaker.
    If include_query=True, query is considered part of the "pathish" key.
    """
    p = urlparse(u)
    pathish = p.path or "/"
    if include_query and p.query:
        pathish = f"{pathish}?{p.query}"
    return (pathish.lower(), (p.netloc or "").lower(), u.lower())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sitemap_url", help="Base sitemap index URL or sitemap URL (XML).")
    ap.add_argument("--out", default="sitemap.csv", help="Output CSV path (default: sitemap.csv).")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds (default: 20).")
    ap.add_argument("--user-agent", default="SitemapToCSV/1.0 (+https://example.com)", help="User-Agent header.")
    ap.add_argument(
        "--include-query",
        action="store_true",
        help="Include the URL querystring in the path sort key (default: false).",
    )
    args = ap.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": args.user_agent})

    try:
        urls = expand_sitemaps(session, args.sitemap_url, timeout=args.timeout)
    except requests.RequestException as e:
        print(f"[FATAL] Failed to fetch sitemap(s): {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        return 2

    # Sort alphabetically by path
    urls_sorted = sorted(urls, key=lambda u: sort_key_for_url(u, args.include_query))

    # Write CSV
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "scheme", "host", "path", "query"])
        for u in urls_sorted:
            p = urlparse(u)
            w.writerow([u, p.scheme, p.netloc, p.path or "/", p.query or ""])

    print(f"[INFO] Wrote {len(urls_sorted)} URLs to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
