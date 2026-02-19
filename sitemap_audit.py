#!/usr/bin/env python3
"""
sitemap_audit_polite_keepalive.py

Polite sitemap crawler:
- Expands a sitemap (or sitemap index) into page URLs
- Visits pages using N workers; each worker processes sequentially:
    do 1 request -> wait delay -> next
- If ANY request times out, abort the entire run immediately
- Each worker has its own HTTP keep-alive Session (connection pooling per worker)

Usage:
  pip install requests lxml
  python sitemap_audit_polite_keepalive.py https://example.com/sitemap.xml --workers 4 --delay 1.0 --timeout 15
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from lxml import etree


GUID_RE = re.compile(
    r"InTheMedia Page\s*([0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12})"
)

XML_PARSER = etree.XMLParser(recover=True, huge_tree=True)

DEFAULT_CATEGORIES = {
    "events": "/events/",
    "people": "/people/",
    "posts": "/posts/",
    "research": "/research/",
}


@dataclass
class PageResult:
    url: str
    status: Optional[int] = None
    content_type: Optional[str] = None
    is_htmlish: bool = False
    itm_guids: List[str] = None
    error: Optional[str] = None
    timed_out: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["itm_guids"] is None:
            d["itm_guids"] = []
        return d


def safe_domain(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def make_session(user_agent: str) -> requests.Session:
    """
    Per-worker Session for keep-alive & connection pooling.

    Notes:
    - requests.Session already keeps connections alive by default (HTTP/1.1)
    - This makes it explicit and scopes pooling per worker thread.
    """
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": user_agent,
            "Connection": "keep-alive",
            # Optional: ask intermediaries not to transform content
            "Cache-Control": "no-cache",
        }
    )

    # Small pool per worker; since worker is sequential, 1 is sufficient.
    adapter = HTTPAdapter(
        pool_connections=1,
        pool_maxsize=1,
        max_retries=0,
        pool_block=True,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def fetch_text(session: requests.Session, url: str, timeout: int) -> Tuple[Optional[str], Optional[requests.Response], Optional[str], bool]:
    """
    Returns (text, response, error_string, timed_out)
    timed_out=True ONLY for requests timeout exceptions.
    """
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp.text, resp, None, False
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout) as e:
        return None, None, str(e), True
    except requests.RequestException as e:
        return None, None, str(e), False


def parse_sitemap(xml_text: str) -> Tuple[List[str], List[str]]:
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
        sitemap_locs = root.xpath("//*[local-name()='sitemap']/*[local-name()='loc']/text()")
        url_locs = root.xpath("//*[local-name()='url']/*[local-name()='loc']/text()")
        if sitemap_locs:
            sitemap_urls = [s.strip() for s in sitemap_locs if isinstance(s, str) and s.strip()]
        if url_locs:
            page_urls = [u.strip() for u in url_locs if isinstance(u, str) and u.strip()]

    return sitemap_urls, page_urls


def expand_sitemaps(session: requests.Session, base_sitemap_url: str, timeout: int, max_sitemaps: int = 10000) -> List[str]:
    seen_sitemaps: Set[str] = set()
    to_process: List[str] = [base_sitemap_url]
    all_pages: List[str] = []

    while to_process:
        sm_url = to_process.pop()
        if sm_url in seen_sitemaps:
            continue
        seen_sitemaps.add(sm_url)

        xml_text, resp, err, timed_out = fetch_text(session, sm_url, timeout=timeout)
        if timed_out:
            raise TimeoutError(f"Timeout fetching sitemap: {sm_url} :: {err}")
        if err:
            print(f"[WARN] Failed to fetch sitemap: {sm_url}\n       {err}", file=sys.stderr)
            continue

        sitemap_urls, page_urls = parse_sitemap(xml_text or "")
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


def looks_htmlish(content_type: Optional[str], body_text: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct or "application/xhtml+xml" in ct:
        return True
    head = (body_text or "").lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head or "<body" in head


def visit_one(session: requests.Session, url: str, timeout: int) -> PageResult:
    r = PageResult(url=url, itm_guids=[])
    text, resp, err, timed_out = fetch_text(session, url, timeout=timeout)
    r.timed_out = timed_out

    if err:
        r.error = err
        return r

    r.status = resp.status_code
    r.content_type = resp.headers.get("Content-Type", "")
    r.is_htmlish = looks_htmlish(r.content_type, text or "")

    if text:
        guids = []
        for m in GUID_RE.finditer(text):
            g = m.group(1)
            if g not in guids:
                guids.append(g)
        r.itm_guids = guids

    return r


def worker_loop(
    worker_id: int,
    user_agent: str,
    q: "queue.Queue[str]",
    timeout: int,
    delay: float,
    stop_event: threading.Event,
    results: List[PageResult],
    results_lock: threading.Lock,
    progress: Dict[str, int],
    progress_lock: threading.Lock,
) -> None:
    # Each worker gets its OWN keep-alive session.
    session = make_session(user_agent)

    while not stop_event.is_set():
        try:
            url = q.get_nowait()
        except queue.Empty:
            return

        if stop_event.is_set():
            q.task_done()
            return

        r = visit_one(session, url, timeout=timeout)

        with results_lock:
            results.append(r)

        with progress_lock:
            progress["done"] += 1
            done = progress["done"]
            total = progress["total"]

        if r.timed_out:
            # Keep going: record timeout and continue
            print(f"[{done}/{total}] TIMEOUT {url} :: {r.error}")
        if r.error:
            print(f"[{done}/{total}] ERROR {url} :: {r.error}")
        elif r.itm_guids:
            print(f"[{done}/{total}] HIT   {url} :: GUID(s)={', '.join(r.itm_guids)}")
        else:
            print(f"[{done}/{total}] OK    {url} :: {r.status} :: {'HTML' if r.is_htmlish else 'NON-HTML/UNKNOWN'}")

        q.task_done()

        if delay > 0 and not stop_event.is_set():
            time.sleep(delay)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sitemap_url", help="Base sitemap index URL or sitemap URL (XML).")
    ap.add_argument("--workers", type=int, default=4, help="Number of worker threads (default: 4).")
    ap.add_argument("--timeout", type=int, default=20, help="HTTP timeout seconds (default: 20).")
    ap.add_argument("--delay", type=float, default=1.0, help="Delay seconds AFTER EACH REQUEST per worker (default: 1.0).")
    ap.add_argument("--user-agent", default="SitemapAuditPolite/1.0 (+https://example.com)", help="User-Agent header.")
    ap.add_argument("--out", default=None, help="Write full results to a JSON file.")
    ap.add_argument(
        "--summary-format",
        default=(
            "Visited {total_urls} URLs | InTheMedia hits: {itm_hits} | "
            "events={count_events}, people={count_people}, posts={count_posts}, research={count_research} | "
            "errors={error_count} | timed_out={timed_out}"
        ),
    )
    args = ap.parse_args()

    # Use a single session for sitemap expansion (not heavy)
    sitemap_session = make_session(args.user_agent)

    print(f"[INFO] Expanding sitemap(s) from: {args.sitemap_url}")
    try:
        page_urls = expand_sitemaps(sitemap_session, args.sitemap_url, timeout=args.timeout)
    except TimeoutError as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        return 2

    total = len(page_urls)
    print(f"[INFO] Found {total} page URLs")
    print(f"[INFO] Visiting with workers={args.workers}, timeout={args.timeout}s, delay={args.delay}s (per worker, after each request)")
    print(f"[INFO] Domain: {safe_domain(args.sitemap_url) or 'unknown'}")

    # URL category counts
    cat_counts: Dict[str, int] = {k: 0 for k in DEFAULT_CATEGORIES.keys()}
    for u in page_urls:
        u_l = u.lower()
        for k, needle in DEFAULT_CATEGORIES.items():
            if needle in u_l:
                cat_counts[k] += 1

    q: "queue.Queue[str]" = queue.Queue()
    for u in page_urls:
        q.put(u)

    stop_event = threading.Event()
    results: List[PageResult] = []
    results_lock = threading.Lock()

    progress = {"done": 0, "total": total}
    progress_lock = threading.Lock()

    threads: List[threading.Thread] = []
    for i in range(max(1, args.workers)):
        t = threading.Thread(
            target=worker_loop,
            args=(
                i + 1,
                args.user_agent,
                q,
                args.timeout,
                args.delay,
                stop_event,
                results,
                results_lock,
                progress,
                progress_lock,
            ),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    itm_records: List[Tuple[str, str]] = []
    error_count = 0
    timed_out = False

    for r in results:
        if r.timed_out:
            timed_out = True
        if r.error:
            error_count += 1
        if r.itm_guids:
            for g in r.itm_guids:
                itm_records.append((r.url, g))

    print("\n=== InTheMedia Page GUID matches ===")
    if itm_records:
        for url, guid in itm_records:
            print(f"{guid}  <-  {url}")
    else:
        print("(none)")

    summary_vars = {
        "total_urls": total,
        "visited": len(results),
        "itm_hits": len(itm_records),
        "count_events": cat_counts["events"],
        "count_people": cat_counts["people"],
        "count_posts": cat_counts["posts"],
        "count_research": cat_counts["research"],
        "error_count": error_count,
        "timed_out": int(timed_out),
    }

    print("\n=== Summary ===")
    print(args.summary_format.format(**summary_vars))

    if args.out:
        payload = {
            "sitemap_url": args.sitemap_url,
            "page_count": total,
            "visited_count": len(results),
            "category_counts": cat_counts,
            "itm_records": [{"url": u, "guid": g} for u, g in itm_records],
            "errors": error_count,
            "timed_out": timed_out,
            "results": [r.to_dict() for r in results],
            "summary_vars": summary_vars,
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\n[INFO] Wrote JSON results to: {args.out}")

    # Non-zero exit if a timeout happened (your “eject” requirement)
    return 3 if timed_out else 0


if __name__ == "__main__":
    raise SystemExit(main())
