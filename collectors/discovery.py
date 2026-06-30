"""discovery.py — keyword-driven seed discovery for the CRAWL collector.

Turns a list of keywords into candidate page URLs ("seeds") that the crawler
then visits. This is the search-driven auto-discovery layer that sits on top
of the seed-list crawler: instead of hand-listing every page, the operator
gives keywords and a provider finds candidate URLs.

The search backend is pluggable so no specific provider is hard-wired:

  * inject a callable ``search_fn(query) -> list[url]`` (used for tests and to
    plug in any search API the operator is licensed to use), or
  * use ``file_search_fn(path)`` — a manual/offline provider that reads a JSON
    map ``{"keyword": ["url", ...]}``. This lets discovery work without any
    external search service (the operator curates candidate URLs per keyword).

A live web-search provider can be added by writing a ``search_fn`` that calls
that service (API key via ``.env``) and returning the result URLs — no change
to the crawler is required. Standard library only here.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("list_collector")

SearchFn = Callable[[str], List[str]]


def discover_seeds(keywords: List[str], search_fn: SearchFn,
                   max_results: Optional[int] = None) -> List[str]:
    """Run ``search_fn`` for each keyword and return de-duplicated URLs.

    ``max_results`` caps the total number of seeds returned (across keywords).
    Only http(s) URLs are kept; order is preserved (first seen wins).
    """
    seen: set = set()
    out: List[str] = []
    for kw in keywords:
        kw = (kw or "").strip()
        if not kw:
            continue
        try:
            results = search_fn(kw) or []
        except Exception as exc:  # a provider error on one keyword is non-fatal
            logger.warning("discovery: provider failed for %r (%s)", kw, exc)
            continue
        for url in results:
            url = (url or "").strip()
            if not url or not urlparse(url).scheme.startswith("http"):
                continue
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            if max_results and len(out) >= int(max_results):
                return out
    return out


def file_search_fn(path: str) -> SearchFn:
    """Offline provider: read a JSON ``{keyword: [urls]}`` map.

    Matching is case-insensitive and substring-based, so a curated entry for
    "장애인 채용" also answers the query "장애인 채용 공고".
    """
    data_path = Path(path)
    if not data_path.exists():
        raise SystemExit(f"ERROR: discovery list not found: {data_path}")
    try:
        mapping: Dict[str, List[str]] = json.loads(data_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid JSON in discovery list: {exc}")

    norm = {str(k).strip().lower(): list(v) for k, v in mapping.items()}

    def _fn(query: str) -> List[str]:
        q = (query or "").strip().lower()
        hits: List[str] = []
        for key, urls in norm.items():
            if key and (key in q or q in key):
                hits.extend(urls)
        return hits

    return _fn


def build_search_fn(options: dict) -> Optional[SearchFn]:
    """Resolve a search function from collector options.

    Priority: an injected ``search_fn`` callable > a ``discovery_list`` JSON
    file path. Returns ``None`` when nothing is configured, so the caller can
    report a clear error only when discovery is actually requested.
    """
    fn = options.get("search_fn")
    if callable(fn):
        return fn
    list_path = options.get("discovery_list")
    if list_path:
        return file_search_fn(str(list_path))
    return None
