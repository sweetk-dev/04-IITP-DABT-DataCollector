"""BaseListCollector — list-collection layer abstract interface.

The collection layer sits in front of ``downloader.py`` and produces the
standard input CSV (``No,Type,Title,Img-link``) that the downloader consumes
unchanged. Each external source is represented by one concrete subclass
("one new source = one new adapter") so that adding a source never touches
the downloader or the base class.

Design mirrors the sibling preprocessing module (08-IITP-DABT-PreProcessing)
collectors package: an abstract base plus per-source adapters selected by a
registry key. The base owns the shared, source-agnostic behaviour
(``to_csv``); adapters own only the source-specific ``collect`` logic.
"""
from __future__ import annotations

import csv
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger("list_collector")

# Standard input-CSV header — identical to downloader.EXPECTED_HEADERS.
# Kept here as the single source of truth for the collection layer so that
# the layer has no import dependency on downloader.py.
STANDARD_HEADERS: List[str] = ["No", "Type", "Title", "Img-link"]


class BaseListCollector(ABC):
    """Common interface for list collectors.

    Concrete adapters set the ``SOURCE`` class attribute to the registry key
    used by ``--source`` / the ``SOURCE`` env var (e.g. ``"SAMPLE"``).
    """

    SOURCE: str = ""

    def __init__(self, **options: object) -> None:
        """Bind adapter-specific options (input path, limits, ...).

        Options are passed through from the CLI / env so that each adapter can
        document and validate only the keys it understands.
        """
        self.options = options

    # --- Abstract method (subclasses must implement) -----------------------

    @abstractmethod
    def collect(self) -> List[Dict[str, str]]:
        """Collect items from the source.

        Returns a list of dict rows, each holding exactly the
        ``STANDARD_HEADERS`` keys. ``Img-link`` may contain multiple URLs
        separated by newlines (the downloader splits them).
        """

    # --- Common utility (shared across adapters) ---------------------------

    def to_csv(self, rows: List[Dict[str, str]], out_path: Path) -> Path:
        """Write ``rows`` to ``out_path`` as a standard UTF-8 (BOM) CSV.

        Behaves identically across sources; adapters should not override.
        Missing keys are written as empty strings; a list value in
        ``Img-link`` is joined with newlines.
        """
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=STANDARD_HEADERS)
            writer.writeheader()
            for row in rows:
                out_row = {}
                for key in STANDARD_HEADERS:
                    value = row.get(key, "")
                    if isinstance(value, (list, tuple)):
                        value = "\n".join(str(v) for v in value)
                    out_row[key] = "" if value is None else str(value)
                writer.writerow(out_row)
        logger.info("%s wrote %d rows -> %s", self.SOURCE or "BASE", len(rows), out_path)
        return out_path

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<{self.__class__.__name__} source={self.SOURCE!r}>"
