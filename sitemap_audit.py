#!/usr/bin/env python3

from __future__ import annotations
import argparse, json, queue, re, threading, time
from dataclasses import dataclass, asdict
from typing import List, Optional, Set
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from lxml import etree


GUID_RE = re.compile(r"InTheMedia Page\s*([0-9a-fA-F\-]{36})")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
PAGE_NOT_FOUND_RE = re.compile(r"page\s*not\s*found", re.IGNORECASE)
XML_PARSER = etree.XMLParser(recover=True, huge_tree=True)


@dataclass
class PageResult:
    url: str
    status: Optional[int] = None
    title: Optional[str] = None
    is_404: bool = False
    itm_guids: List[str] = None
    error: Optional[str] = None
    timed_out: bool = False

    def to_dict(self):
        d = asdict(self)
        if d["itm_guids"] is None:
            d["itm_guids"] = []
        return d


# ---------------- HTTP ----------------

def make_session():
    s = requests.Session()
    s.headers.update({"Connection": "keep-alive"})
    adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def fetch_text(session, url, timeout):
    try:
        resp = session.get(url, timeout=timeout)
        return resp.text, resp, None, False
    except requests.exceptions.Timeout as e:
        return None, None, str(e), True
    except requests.RequestException as e:
        return None, None, str(e), False


# ---------------- SITEMAP ----------------

def parse_sitemap(xml_text):
    root = etree.fromstring(xml_text.encode(), parser=XML_PARSER)
    tag = etree.QName(root).localname.lower()

    if tag == "sitemapindex":
        return root.xpath("//*[local-name()='loc']/text()"), []
    else:
        return [], root.xpath("//*[local-name()='url']/*[local-name()='loc']/text()")


def expand_sitemaps(session, base_url, timeout):
    to_process = [base_url]
    seen, pages = set(), []

    while to_process:
        url = to_process.pop()
        if url in seen:
            continue
        seen.add(url)

        xml, _, err, _ = fetch_text(session, url, timeout)
        if err:
            continue

        smaps, urls = parse_sitemap(xml)
        to_process.extend(smaps)
        pages.extend(urls)

    return list(dict.fromkeys(pages))


# ---------------- PAGE ----------------

def extract_title(html):
    m = TITLE_RE.search(html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else None


def visit_page(session, url, timeout):
    r = PageResult(url=url, itm_guids=[])

    text, resp, err, timed_out = fetch_text(session, url, timeout)
    r.timed_out = timed_out

    if err:
        r.error = err
        return r

    r.status = resp.status_code
    if resp.status_code == 404:
        r.is_404 = True

    if text:
        r.title = extract_title(text)
        if r.title and PAGE_NOT_FOUND_RE.search(r.title):
            r.is_404 = True
        r.itm_guids = list(set(GUID_RE.findall(text)))

    return r


# ---------------- PROGRESS TRACKER ----------------

class Progress:
    def __init__(self, total):
        self.total = total
        self.completed = 0
        self.start = time.time()
        self.lock = threading.Lock()
        self.timeouts = 0
        self.four04 = 0
        self.guid_hits = 0

    def update(self, result: PageResult):
        with self.lock:
            self.completed += 1
            if result.timed_out:
                self.timeouts += 1
            if result.is_404:
                self.four04 += 1
            if result.itm_guids:
                self.guid_hits += 1

    def eta_line(self):
        with self.lock:
            elapsed = time.time() - self.start
            rate = self.completed / elapsed if elapsed else 0
            remaining = self.total - self.completed
            eta = remaining / rate if rate else 0

            eta_str = time.strftime("%H:%M:%S", time.gmtime(eta))
            pct = (self.completed / self.total) * 100

            return (
                f"Progress: {self.completed}/{self.total} "
                f"({pct:.1f}%) | {rate:.1f} req/s | ETA {eta_str} "
                f"| 404s: {self.four04} | Timeouts: {self.timeouts} | GUID hits: {self.guid_hits}"
            )


# ---------------- WORKER ----------------

def worker(q, timeout, delay, results, progress: Progress):
    session = make_session()

    while True:
        try:
            url = q.get_nowait()
        except queue.Empty:
            return

        res = visit_page(session, url, timeout)
        results.append(res)
        progress.update(res)

        q.task_done()
        time.sleep(delay)


# ---------------- PROGRESS THREAD ----------------

def progress_printer(progress: Progress):
    while progress.completed < progress.total:
        print(progress.eta_line(), end="\r", flush=True)
        time.sleep(1)
    print(progress.eta_line())


# ---------------- MAIN ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sitemap_url")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--delay", type=float, default=1.0)
    args = ap.parse_args()

    print("Expanding sitemap...")
    session = make_session()
    urls = expand_sitemaps(session, args.sitemap_url, args.timeout)

    print(f"Found {len(urls)} URLs")

    q = queue.Queue()
    for u in urls:
        q.put(u)

    results = []
    progress = Progress(len(urls))

    threading.Thread(target=progress_printer, args=(progress,), daemon=True).start()

    threads = []
    for _ in range(args.workers):
        t = threading.Thread(target=worker, args=(q, args.timeout, args.delay, results, progress))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n\n=== FINAL SUMMARY ===")
    print(progress.eta_line())


if __name__ == "__main__":
    main()
