"""FileImportCollector — reference list collector (``SOURCE = "SAMPLE"``).

This is the working reference adapter shipped with v1.0. It demonstrates the
collection contract without any external dependency or secret: it normalises
a local file (or a small built-in mock dataset) into the standard
``No,Type,Title,Img-link`` row shape.

Live adapters (partner DB export, public tourism API, external crawling) are
added later as sibling modules; see ``collectors/stubs.py`` for their
registered placeholders. The framework here — base + registry + this adapter
— is the reusable core that every future source plugs into.
"""
from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Dict, List

from .base import BaseListCollector, STANDARD_HEADERS

logger = logging.getLogger("list_collector")

# Flexible header aliases so an imported file does not have to match the
# standard header casing exactly. Keys are lower-cased source headers.
_HEADER_ALIASES = {
    "no": "No",
    "id": "No",
    "type": "Type",
    "category": "Type",
    "title": "Title",
    "name": "Title",
    "img-link": "Img-link",
    "img_link": "Img-link",
    "image": "Img-link",
    "imageurl": "Img-link",
    "image_url": "Img-link",
}

# Built-in mock rows used when no input file is provided, so the adapter runs
# out-of-the-box (placeholder URLs only — no real source data).
_MOCK_ROWS: List[Dict[str, str]] = [
    {"No": "1", "Type": "행사", "Title": "장애인 일자리 박람회 개최 안내",
     "Img-link": "https://example.com/sample/event_1.jpg"},
    {"No": "2", "Type": "교육", "Title": "직무 적응 지원 교육 과정 모집",
     "Img-link": "https://example.com/sample/edu_2.jpg"},
    {"No": "3", "Type": "채용", "Title": "사무보조 채용 공고",
     "Img-link": "https://example.com/sample/job_3a.jpg\nhttps://example.com/sample/job_3b.jpg"},
]


def _normalise_header(name: str) -> str:
    key = (name or "").strip().lower()
    return _HEADER_ALIASES.get(key, name.strip())


class FileImportCollector(BaseListCollector):
    """Normalise a local file (or mock data) into standard CSV rows.

    Options
    -------
    input:
        Optional path to a source CSV. When omitted, the built-in mock rows
        are returned so the adapter is runnable without any input.
    limit:
        Optional maximum number of rows to return (int or numeric string).
    """

    SOURCE = "SAMPLE"

    def collect(self) -> List[Dict[str, str]]:
        input_path = self.options.get("input")
        limit = self.options.get("limit")

        if input_path:
            rows = self._read_file(Path(str(input_path)))
        else:
            logger.info("SAMPLE: no input given, using built-in mock rows")
            rows = [dict(r) for r in _MOCK_ROWS]

        if limit:
            try:
                n = int(limit)
                if n >= 0:
                    rows = rows[:n]
            except (TypeError, ValueError):
                logger.warning("SAMPLE: ignoring non-integer limit=%r", limit)

        return rows

    def _read_file(self, path: Path) -> List[Dict[str, str]]:
        if not path.exists():
            raise SystemExit(f"ERROR: input file not found: {path}")
        if path.suffix.lower() != ".csv":
            raise SystemExit(f"ERROR: SAMPLE adapter supports .csv only, got: {path.suffix}")

        with path.open("r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise SystemExit("ERROR: input CSV has no header")
            mapping = {fn: _normalise_header(fn) for fn in reader.fieldnames}
            mapped_targets = set(mapping.values())
            if "Title" not in mapped_targets or "Img-link" not in mapped_targets:
                raise SystemExit(
                    "ERROR: input CSV must provide at least Title and Img-link "
                    f"columns; got headers: {reader.fieldnames}"
                )

            rows: List[Dict[str, str]] = []
            for src in reader:
                row = {h: "" for h in STANDARD_HEADERS}
                for src_key, value in src.items():
                    target = mapping.get(src_key)
                    if target in STANDARD_HEADERS:
                        row[target] = (value or "").strip()
                # Collapse internal whitespace in Title for stable filenames.
                row["Title"] = re.sub(r"\s+", " ", row["Title"]).strip()
                rows.append(row)
            logger.info("SAMPLE: read %d rows from %s", len(rows), path)
            return rows
