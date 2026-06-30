"""web_crawl.py — seed-list web crawl collector (SOURCE = "CRAWL").

Collects a standard No,Type,Title,Img-link list from a configured set of
external public pages. This is the seed-list approach: the operator supplies
the target sites/pages in a config file; the collector visits them politely
and extracts page title + image URLs. Automatic keyword-search discovery is a
later enhancement layered on top of this.

Safety defaults (external crawling — handle with care):
  * robots.txt is honoured per host (a disallowed URL is skipped).
  * a per-host delay (rate limit) is applied between requests.
  * an explicit, identifying User-Agent is sent.
  * a domain allowlist limits fetching to the configured hosts (link-follow
    cannot wander off-site).

Only ``requests`` (already a dependency) plus the standard library are used
(``urllib.robotparser``, ``html.parser``, ``urllib.parse``, ``hashlib``).

Config file (JSON): a list of site entries, e.g.

    [
      {
        "name": "example-board",
        "seeds": ["https://example.org/notice/list"],
        "type": "행사",
        "link_pattern": "/notice/view\\\\?id=\\\\d+",
        "max_items": 50
      }
    ]

``type`` is optional (left blank, label_assist will infer). ``link_pattern``
is optional: when given, item-page links matching the regex are followed from
each seed (one level); otherwise each seed page itself yields one row.
"""
from __future__ import annotations

import csv
import hashlib
import json
import logging
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .base import BaseListCollector
from .discovery import build_search_fn, discover_seeds

logger = logging.getLogger("list_collector")

IMAGE_EXT_RE = re.compile(r"\.(jpe?g|png|gif|bmp|tiff?|webp)(\?|#|$)", re.IGNORECASE)
# Site chrome (logo/icon/social/spacer) — excluded from collected images.
CHROME_IMG_RE = re.compile(r"(logo|favicon|ico_|/icon|sns|spacer|blank|btn_|pixel|1x1)", re.IGNORECASE)
DEFAULT_USER_AGENT = "IITP-DABT-DataCollector/1.0 (research dataset collection)"
DEFAULT_DELAY_SEC = 1.0
DEFAULT_TIMEOUT = (10, 30)
DEFAULT_RETRIES = 2
DEFAULT_BACKOFF_SEC = 1.0


class _PageParser(HTMLParser):
    """Extract title, og:title/og:image, image srcs and anchor hrefs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: List[str] = []
        self._in_title = False
        self.h1_parts: List[str] = []
        self._in_h1 = False
        self._in_script = 0
        self.og_title: Optional[str] = None
        self.og_images: List[str] = []
        self.img_srcs: List[str] = []
        self.links: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._in_script += 1
        if tag == "title":
            self._in_title = True
        elif tag == "h1":
            self._in_h1 = True
        elif tag == "meta":
            prop = (a.get("property") or a.get("name") or "").lower()
            content = a.get("content") or ""
            if prop == "og:title" and content:
                self.og_title = content.strip()
            elif prop == "og:image" and content:
                self.og_images.append(content.strip())
        elif tag == "img":
            for key in ("src", "data-src", "data-original"):
                if a.get(key):
                    self.img_srcs.append(a[key].strip())
                    break
        elif tag == "a":
            if a.get("href"):
                self.links.append(a["href"].strip())

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._in_script > 0:
            self._in_script -= 1
        if tag == "title":
            self._in_title = False
        elif tag == "h1":
            self._in_h1 = False

    def handle_data(self, data):
        if self._in_script:
            return  # ignore script/style text even inside title/h1
        if self._in_title:
            self.title_parts.append(data)
        elif self._in_h1:
            self.h1_parts.append(data)

    def best_title(self) -> str:
        # og:title (publisher-declared) is the most reliable; fall back to a
        # visible <h1>, then the document <title>.
        for candidate in (
            (self.og_title or "").strip(),
            "".join(self.h1_parts).strip(),
            "".join(self.title_parts).strip(),
        ):
            if candidate:
                return re.sub(r"\s+", " ", candidate)
        return ""


_ID_QUERY_KEYS = ("id", "uid", "idxno", "no", "seq", "idx", "bid", "wr_id",
                  "bo_id", "articleno", "ntt_id", "nttid")


def _derive_no(url: str) -> str:
    """Stable per-item id: a numeric id query param, else trailing path
    digits, else a short md5 of the URL (so every item still gets a stable id).
    """
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query))
    for key in query:
        if key.lower() in _ID_QUERY_KEYS and query[key].isdigit():
            return query[key]
    m = re.search(r"(\d+)\D*$", parts.path)
    if m:
        return m.group(1)
    return hashlib.md5(url.encode("utf-8")).hexdigest()[:10]


def extract_items_from_html(html: str, base_url: str, type_hint: str = "") -> Dict[str, object]:
    """Pure extraction (no network). Returns {title, images, links}.

    Image and link URLs are resolved to absolute against ``base_url``; images
    are filtered to image-like URLs (extension or og:image already absolute).
    """
    parser = _PageParser()
    parser.feed(html or "")
    title = parser.best_title()
    images: List[str] = []
    seen: Set[str] = set()

    def _add(src: str, keep_any: bool) -> None:
        absu = urljoin(base_url, src)
        if not absu.lower().startswith(("http://", "https://")):
            return
        # Drop obvious site chrome (logos, icons, social, spacers).
        if CHROME_IMG_RE.search(absu):
            return
        # og:image bypasses the extension check; <img> srcs must look image-like.
        if not (keep_any or IMAGE_EXT_RE.search(absu)):
            return
        if absu not in seen:
            seen.add(absu)
            images.append(absu)

    for src in parser.og_images:
        _add(src, keep_any=True)
    for src in parser.img_srcs:
        _add(src, keep_any=False)
    links = []
    lseen: Set[str] = set()
    for href in parser.links:
        absu = urljoin(base_url, href)
        if absu.lower().startswith(("http://", "https://")) and absu not in lseen:
            lseen.add(absu)
            links.append(absu)
    return {"title": title, "images": images, "links": links}


class WebCrawlCollector(BaseListCollector):
    """Seed-list crawler for external public pages.

    Options
    -------
    config:
        Path to the JSON site config (required for live runs).
    delay:
        Per-host delay in seconds between requests (default 1.0).
    user_agent:
        User-Agent string (default identifies the project).
    respect_robots:
        Honour robots.txt (default True).
    session:
        Optional pre-built ``requests.Session`` (used by tests / callers).
    """

    SOURCE = "CRAWL"

    def collect(self) -> List[Dict[str, str]]:
        sites = self._load_sites()
        delay = float(self.options.get("delay", DEFAULT_DELAY_SEC))
        self.user_agent = str(self.options.get("user_agent", DEFAULT_USER_AGENT))
        self.respect_robots = bool(self.options.get("respect_robots", True))
        self._retries = int(self.options.get("retries", DEFAULT_RETRIES))
        self._backoff = float(self.options.get("backoff", DEFAULT_BACKOFF_SEC))
        self._robots: Dict[str, Optional[RobotFileParser]] = {}
        self._last_hit: Dict[str, float] = {}
        self._delay = delay
        self._seen_urls: Set[str] = set()
        self.errors: List[Dict[str, str]] = []
        self._session = self.options.get("session") or self._new_session()

        # Resolve keyword-driven discovery into concrete seeds first, so that
        # discovered hosts are included in the allowlist below.
        self._search_fn = build_search_fn(self.options)
        self._resolve_discovery(sites)

        # Domain allowlist = all seed hosts (plus explicit allow_domains).
        allow: Set[str] = set()
        for site in sites:
            for seed in site.get("seeds", []):
                allow.add(urlparse(seed).netloc)
            for dom in site.get("allow_domains", []):
                allow.add(dom)
        self._allow = allow

        rows: List[Dict[str, str]] = []
        for site in sites:
            rows.extend(self._collect_site(site))
        if self.errors:
            logger.warning("CRAWL: %d fetch failure(s)", len(self.errors))
            error_out = self.options.get("error_out")
            if error_out:
                self.write_errors(Path(str(error_out)))
        logger.info("CRAWL: collected %d rows from %d site(s)", len(rows), len(sites))
        return rows

    def write_errors(self, path: Path) -> Path:
        """Write captured fetch failures to a CSV (url, error)."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "error"])
            writer.writeheader()
            for e in self.errors:
                writer.writerow(e)
        return path

    def _resolve_discovery(self, sites: List[dict]) -> None:
        """For sites with a ``discover`` block, find seeds via the search
        function and merge them into ``site["seeds"]``.

        ``discover``: {"keywords": [...], "max_results": N}
        """
        for site in sites:
            disc = site.get("discover")
            if not disc:
                continue
            if self._search_fn is None:
                raise SystemExit(
                    "ERROR: site uses 'discover' but no search provider is "
                    "configured (pass search_fn or discovery_list option)."
                )
            keywords = disc.get("keywords") or []
            found = discover_seeds(keywords, self._search_fn, disc.get("max_results"))
            logger.info("CRAWL: discovery found %d seed(s) for %s",
                        len(found), site.get("name", "?"))
            merged = list(site.get("seeds", [])) + [u for u in found if u not in set(site.get("seeds", []))]
            site["seeds"] = merged

    # --- config -----------------------------------------------------------

    def _load_sites(self) -> List[dict]:
        config = self.options.get("config")
        if config:
            path = Path(str(config))
            if not path.exists():
                raise SystemExit(f"ERROR: crawl config not found: {path}")
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"ERROR: invalid JSON in crawl config: {exc}")
            if not isinstance(data, list):
                raise SystemExit("ERROR: crawl config must be a JSON list of site entries")
            return data
        # Inline sites (used by tests).
        inline = self.options.get("sites")
        if inline:
            return list(inline)
        raise SystemExit("ERROR: CRAWL needs --config <sites.json> (or inline sites option)")

    # --- network ----------------------------------------------------------

    def _new_session(self):
        import requests  # local import keeps base/test import light
        s = requests.Session()
        s.headers.update({"User-Agent": self.user_agent})
        return s

    def _allowed_by_robots(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        host = urlparse(url).scheme + "://" + urlparse(url).netloc
        rp = self._robots.get(host, "missing")
        if rp == "missing":
            rp = RobotFileParser()
            rp.set_url(urljoin(host, "/robots.txt"))
            try:
                rp.read()
            except Exception as exc:  # network/parse error -> be permissive but log
                logger.debug("CRAWL: robots fetch failed for %s (%s); allowing", host, exc)
                rp = None
            self._robots[host] = rp
        if rp is None:
            return True
        return rp.can_fetch(self.user_agent, url)

    def _rate_limit(self, url: str) -> None:
        host = urlparse(url).netloc
        last = self._last_hit.get(host)
        now = time.monotonic()
        if last is not None:
            wait = self._delay - (now - last)
            if wait > 0:
                time.sleep(wait)
        self._last_hit[host] = time.monotonic()

    def _fetch(self, url: str) -> Optional[str]:
        if urlparse(url).netloc not in self._allow:
            logger.warning("CRAWL: skip off-allowlist URL: %s", url)
            return None
        if not self._allowed_by_robots(url):
            logger.warning("CRAWL: robots.txt disallows: %s", url)
            return None

        attempts = max(1, self._retries + 1)
        last_err = ""
        for attempt in range(1, attempts + 1):
            self._rate_limit(url)
            try:
                resp = self._session.get(url, timeout=DEFAULT_TIMEOUT)
                resp.raise_for_status()
                # Prefer declared encoding; fall back to detected when missing.
                if getattr(resp, "encoding", None) in (None, "ISO-8859-1"):
                    apparent = getattr(resp, "apparent_encoding", None)
                    if apparent:
                        resp.encoding = apparent
                return resp.text
            except Exception as exc:
                last_err = str(exc)
                logger.warning("CRAWL: fetch failed %s attempt=%d/%d (%s)",
                               url, attempt, attempts, last_err)
                if attempt < attempts:
                    time.sleep(self._backoff * attempt)
        self.errors.append({"url": url, "error": last_err or "unknown error"})
        return None

    # --- per-site collection ---------------------------------------------

    def _expand_seeds(self, site: dict) -> List[str]:
        """Expand seeds with optional pagination.

        ``paginate``: {"param": "page", "start": 1, "end": 3} appends
        ``?param=i`` (i in start..end) to each seed.
        """
        seeds = list(site.get("seeds", []))
        pag = site.get("paginate")
        if not pag:
            return seeds
        param = pag.get("param", "page")
        start = int(pag.get("start", 1))
        end = int(pag.get("end", start))
        expanded: List[str] = []
        for seed in seeds:
            for i in range(start, end + 1):
                parts = urlsplit(seed)
                query = dict(parse_qsl(parts.query))
                query[param] = str(i)
                expanded.append(urlunsplit(
                    (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)))
        return expanded

    def _collect_site(self, site: dict) -> List[Dict[str, str]]:
        type_hint = (site.get("type") or "").strip()
        link_pattern = site.get("link_pattern")
        max_items = site.get("max_items")
        rows: List[Dict[str, str]] = []

        def _capped() -> bool:
            return bool(max_items) and len(rows) >= int(max_items)

        for seed in self._expand_seeds(site):
            if _capped():
                break
            html = self._fetch(seed)
            if html is None:
                continue
            if link_pattern:
                data = extract_items_from_html(html, seed, type_hint)
                pat = re.compile(link_pattern)
                for item_url in data["links"]:
                    if not pat.search(item_url):
                        continue
                    if _capped():
                        break
                    if item_url in self._seen_urls:
                        continue
                    self._seen_urls.add(item_url)
                    item_html = self._fetch(item_url)
                    if item_html is None:
                        continue
                    rows.append(self._row_from(item_url, item_html, type_hint))
            else:
                if seed in self._seen_urls:
                    continue
                self._seen_urls.add(seed)
                rows.append(self._row_from(seed, html, type_hint))
        return rows

    def _row_from(self, url: str, html: str, type_hint: str) -> Dict[str, str]:
        data = extract_items_from_html(html, url, type_hint)
        return {
            "No": _derive_no(url),
            "Type": type_hint,
            "Title": data["title"],
            "Img-link": "\n".join(data["images"]),
        }
