"""Tests for the collectors/ list-collection layer.

Standard-library ``unittest`` only (no test dependency added). Run from the
repo root with: ``python -m unittest discover -s tests`` or ``pytest``.
"""
import sys
import unittest
from pathlib import Path

# Ensure repo root is importable when tests run from any CWD.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import csv
import tempfile

from collectors import (
    FileImportCollector,
    available_sources,
    get_collector,
    STANDARD_HEADERS,
)
from collectors.stubs import ApiListCollector, DbListCollector, WebCrawlCollector


class ToCsvTest(unittest.TestCase):
    def test_to_csv_writes_standard_headers_and_joins_list(self):
        collector = FileImportCollector()
        rows = [
            {"No": "1", "Type": "행사", "Title": "t1", "Img-link": "u1"},
            {"No": "2", "Type": "교육", "Title": "t2",
             "Img-link": ["a", "b"]},
        ]
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out.csv"
            collector.to_csv(rows, out)
            with out.open("r", encoding="utf-8-sig", newline="") as f:
                reader = csv.DictReader(f)
                self.assertEqual(reader.fieldnames, STANDARD_HEADERS)
                got = list(reader)
            self.assertEqual(got[0]["Title"], "t1")
            self.assertEqual(got[1]["Img-link"], "a\nb")


class FileImportCollectorTest(unittest.TestCase):
    def test_mock_rows_when_no_input(self):
        rows = FileImportCollector().collect()
        self.assertTrue(len(rows) >= 1)
        for r in rows:
            self.assertEqual(set(STANDARD_HEADERS), set(r.keys()))

    def test_limit_option(self):
        rows = FileImportCollector(limit=2).collect()
        self.assertEqual(len(rows), 2)

    def test_reads_csv_with_alias_headers(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "in.csv"
            with src.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["id", "category", "name", "image_url"])
                w.writerow(["10", "교육", "강좌 안내", "http://x/y.jpg"])
            rows = FileImportCollector(input=str(src)).collect()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["No"], "10")
            self.assertEqual(rows[0]["Type"], "교육")
            self.assertEqual(rows[0]["Title"], "강좌 안내")
            self.assertEqual(rows[0]["Img-link"], "http://x/y.jpg")

    def test_missing_required_columns_raises(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "bad.csv"
            with src.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["foo", "bar"])
                w.writerow(["1", "2"])
            with self.assertRaises(SystemExit):
                FileImportCollector(input=str(src)).collect()


class RegistryTest(unittest.TestCase):
    def test_available_sources(self):
        self.assertEqual(available_sources(), ["API", "CRAWL", "DB", "SAMPLE"])

    def test_get_collector_case_insensitive(self):
        self.assertIsInstance(get_collector("sample"), FileImportCollector)

    def test_unknown_source_raises(self):
        with self.assertRaises(SystemExit):
            get_collector("NOPE")

    def test_deferred_adapters_raise_not_implemented(self):
        for cls in (DbListCollector, WebCrawlCollector, ApiListCollector):
            with self.assertRaises(NotImplementedError):
                cls().collect()


if __name__ == "__main__":
    unittest.main()
