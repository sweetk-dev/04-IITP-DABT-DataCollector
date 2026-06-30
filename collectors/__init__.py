"""List-collection layer for 04-IITP-DABT-DataCollector.

Plugin-style architecture: each source is a ``BaseListCollector`` subclass
selected by a registry key. Working adapters: ``SAMPLE`` (file/mock import)
and ``CRAWL`` (seed-list external crawler). Partner-DB and public-API adapters
are registered placeholders (``collectors/stubs.py``).

Quick usage::

    from collectors import get_collector
    collector = get_collector("SAMPLE", input="insample/sample_t2.csv")
    rows = collector.collect()
    collector.to_csv(rows, Path("out/collected.csv"))

Adding a new source (skeleton)::

    from collectors.base import BaseListCollector
    class MySourceCollector(BaseListCollector):
        SOURCE = "MY_SOURCE"
        def collect(self):
            ...
    # then add one REGISTRY entry in collectors/registry.py
"""
from .base import BaseListCollector, STANDARD_HEADERS  # noqa: F401
from .registry import REGISTRY, available_sources, get_collector, DEFAULT_SOURCE  # noqa: F401
from .sample_file import FileImportCollector  # noqa: F401
from .web_crawl import WebCrawlCollector  # noqa: F401
from .stubs import DbListCollector  # noqa: F401
from .tour_api import ApiListCollector  # noqa: F401

__all__ = [
    "BaseListCollector",
    "STANDARD_HEADERS",
    "REGISTRY",
    "DEFAULT_SOURCE",
    "available_sources",
    "get_collector",
    "FileImportCollector",
    "WebCrawlCollector",
    "DbListCollector",
    "ApiListCollector",
]
