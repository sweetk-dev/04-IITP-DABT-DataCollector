"""Deferred list-collector adapters — registered placeholders.

These three adapters are part of the target design but are intentionally not
implemented in v1.0. Live integration requires source-specific access that is
deliberately kept out of the released package (partner DB connection, public
API keys, per-site crawling review). They are registered so the routing table
documents the full design surface; calling ``collect`` raises
``NotImplementedError`` with a short note on what each needs.

When a source is filled in later, move it into its own module
(e.g. ``collectors/tourism_api.py``) following ``FileImportCollector``.
"""
from __future__ import annotations

from typing import Dict, List

from .base import BaseListCollector


class DbListCollector(BaseListCollector):
    """Partner-operated job/education/event portal internal DB export.

    Preferred over crawling for the partner platform (stable, sanctioned).
    Needs a connection/export agreement and credentials supplied via ``.env``.
    """

    SOURCE = "DB"

    def collect(self) -> List[Dict[str, str]]:
        raise NotImplementedError(
            "DB adapter is deferred: requires partner DB connection/export "
            "configured via environment variables."
        )


class WebCrawlCollector(BaseListCollector):
    """Generic external-site crawler.

    Applied only to unrelated external sites, and only after robots.txt /
    terms-of-use / rights review, with rate limiting and an explicit
    User-Agent. Not enabled in the released package.
    """

    SOURCE = "CRAWL"

    def collect(self) -> List[Dict[str, str]]:
        raise NotImplementedError(
            "Crawl adapter is deferred: requires per-site rights review, "
            "rate-limit and User-Agent configuration."
        )


class ApiListCollector(BaseListCollector):
    """Public open-API source (e.g. accessible-tourism portals).

    Targets the phase-2 culture/tourism expansion sources. Needs an API key
    and the per-source response schema, supplied via ``.env``.
    """

    SOURCE = "API"

    def collect(self) -> List[Dict[str, str]]:
        raise NotImplementedError(
            "API adapter is deferred: requires public API key and per-source "
            "response schema configured via environment variables."
        )
