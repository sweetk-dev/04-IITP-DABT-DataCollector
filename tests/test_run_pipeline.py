"""Tests for run_pipeline.py and scheduler.py — fakes only (no network/DB)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import run_pipeline
import scheduler
from collectors.base import BaseListCollector


class _FakeCollector(BaseListCollector):
    SOURCE = "FAKE"
    def __init__(self, rows, **opts):
        super().__init__(**opts)
        self._rows = rows
    def collect(self):
        return self._rows


class _FakeCursor:
    def __init__(self, store): self.store = store
    def execute(self, sql, params=None): self.store["calls"].append((sql, params))
    def fetchone(self):
        self.store["seq"] += 1
        return (self.store["seq"],)
    def close(self): pass


class _FakeConn:
    def __init__(self): self.store = {"calls": [], "seq": 0, "commits": 0}
    def cursor(self): return _FakeCursor(self.store)
    def commit(self): self.store["commits"] += 1
    def close(self): self.store["closed"] = True


class RunPipelineTest(unittest.TestCase):
    def test_collect_label_db(self):
        rows = [
            {"No": "1", "Type": "관광지", "Title": "무장애 둘레길 개방",
             "Img-link": "http://x/1.jpg\nhttp://x/2.jpg"},
            {"No": "2", "Type": "음식점", "Title": "배리어프리 식당 안내",
             "Img-link": "http://x/3.jpg"},
        ]
        conn = _FakeConn()
        with __import__("tempfile").TemporaryDirectory() as d:
            summary = run_pipeline.run_pipeline(
                "FAKE", Path(d), "TOUR_BF_API",
                collector_factory=lambda source, **o: _FakeCollector(rows, **o),
                db_conn=conn,
            )
            self.assertEqual(summary["collected"], 2)
            self.assertEqual(summary["db_items"], 2)
            self.assertEqual(summary["db_images"], 3)
            # labeled CSV produced
            self.assertTrue((Path(d) / "collected_labeled.csv").exists())
        self.assertEqual(conn.store["commits"], 1)

    def test_db_skipped_when_not_requested(self):
        rows = [{"No": "1", "Type": "", "Title": "t", "Img-link": "http://x/1.jpg"}]
        with __import__("tempfile").TemporaryDirectory() as d:
            summary = run_pipeline.run_pipeline(
                "FAKE", Path(d), "WEB_CRAWL",
                collector_factory=lambda source, **o: _FakeCollector(rows, **o),
                to_db=False,
            )
            self.assertIsNone(summary["db_items"])
            self.assertEqual(summary["collected"], 1)


class SchedulerTest(unittest.TestCase):
    def test_parse_cron_ok(self):
        self.assertEqual(
            scheduler._parse_cron("0 3 * * *"),
            {"minute": "0", "hour": "3", "day": "*", "month": "*", "day_of_week": "*"})

    def test_parse_cron_invalid(self):
        with self.assertRaises(SystemExit):
            scheduler._parse_cron("0 3 *")


if __name__ == "__main__":
    unittest.main()
