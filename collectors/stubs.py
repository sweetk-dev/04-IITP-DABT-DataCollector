"""Deferred list-collector adapters — registered placeholders.

The external-site crawler (``CRAWL``) lives in ``collectors/web_crawl.py`` and
the public open-API collector (``API``) in ``collectors/tour_api.py``; only the
partner-DB source remains deferred (needs a connection/export agreement).
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
