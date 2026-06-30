"""Source registry & routing for the list-collection layer.

Selection priority (resolved by the CLI entry point ``collect_list.py``):
``--source`` argument > ``SOURCE`` env var > ``DEFAULT_SOURCE``.

Adding a source = import its class and add one ``REGISTRY`` entry. No other
file in the collection layer changes.
"""
from __future__ import annotations

from typing import Dict, Type

from .base import BaseListCollector
from .sample_file import FileImportCollector
from .stubs import DbListCollector
from .tour_api import ApiListCollector
from .web_crawl import WebCrawlCollector

DEFAULT_SOURCE = "SAMPLE"

# Registry key -> collector class. Keys match each class ``SOURCE`` attribute.
REGISTRY: Dict[str, Type[BaseListCollector]] = {
    FileImportCollector.SOURCE: FileImportCollector,
    WebCrawlCollector.SOURCE: WebCrawlCollector,
    DbListCollector.SOURCE: DbListCollector,
    ApiListCollector.SOURCE: ApiListCollector,
}


def available_sources() -> list:
    """Return the registered source keys in a stable order."""
    return sorted(REGISTRY.keys())


def get_collector(source: str, **options: object) -> BaseListCollector:
    """Instantiate the collector registered under ``source``.

    Raises ``SystemExit`` with the list of known keys when ``source`` is
    unknown, so the CLI reports a helpful message instead of a traceback.
    """
    key = (source or "").strip().upper()
    if key not in REGISTRY:
        raise SystemExit(
            f"ERROR: unknown source {source!r}. "
            f"Available: {', '.join(available_sources())}"
        )
    return REGISTRY[key](**options)
