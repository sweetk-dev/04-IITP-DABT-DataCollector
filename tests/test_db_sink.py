"""Tests for db_sink.py — verified against a fake DB-API connection (no live DB)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import db_sink


class _FakeCursor:
    def __init__(self, store):
        self.store = store
        self._last_sql = ""
    def execute(self, sql, params=None):
        self.store["calls"].append((sql, params))
        self._last_sql = sql
    def fetchone(self):
        self.store["seq"] += 1
        return (self.store["seq"],)
    def close(self):
        pass


class _FakeConn:
    def __init__(self):
        self.store = {"calls": [], "seq": 0, "commits": 0}
    def cursor(self):
        return _FakeCursor(self.store)
    def commit(self):
        self.store["commits"] += 1


class MappingTest(unittest.TestCase):
    def test_item_params(self):
        row = {"No": "126273", "Type": "관광지", "Title": "가계해수욕장",
               "inferred_category": "무장애 관광지", "domain": "문화관광",
               "match_confidence": "0.60", "needs_review": "N"}
        p = db_sink.item_params(row, "TOUR_BF_API")
        self.assertEqual(p["ext_sys"], "TOUR_BF_API")
        self.assertEqual(p["src_no"], "126273")
        self.assertEqual(p["match_confidence"], 0.60)
        self.assertEqual(p["needs_review"], "N")
        self.assertEqual(p["created_by"], db_sink.DEFAULT_CREATED_BY)

    def test_blank_fields_become_none(self):
        p = db_sink.item_params({"No": "1", "Title": "t", "Type": "",
                                 "match_confidence": ""}, "WEB_CRAWL")
        self.assertIsNone(p["src_type"])
        self.assertIsNone(p["match_confidence"])
        self.assertIsNone(p["inferred_category"])

    def test_split_image_urls(self):
        cell = "http://x/1.jpg\nhttp://x/2.jpg\nhttp://x/1.jpg\nnot-a-url\n"
        self.assertEqual(db_sink.split_image_urls(cell),
                         ["http://x/1.jpg", "http://x/2.jpg"])


class SinkTest(unittest.TestCase):
    def test_upsert_item_returns_id_and_runs_upsert_sql(self):
        conn = _FakeConn()
        sink = db_sink.DbSink(conn)
        item_id = sink.upsert_item({"No": "9", "Title": "t"}, "WEB_CRAWL")
        self.assertEqual(item_id, 1)
        sql, params = conn.store["calls"][-1]
        self.assertIn("INSERT INTO public.dis_unst_collect_item", sql)
        self.assertIn("ON CONFLICT (ext_sys, src_no)", sql)
        self.assertEqual(params["src_no"], "9")

    def test_load_rows_counts_and_commits(self):
        conn = _FakeConn()
        sink = db_sink.DbSink(conn)
        rows = [
            {"No": "1", "Title": "a", "Img-link": "http://x/1.jpg\nhttp://x/2.jpg"},
            {"No": "2", "Title": "b", "Img-link": "http://x/3.jpg"},
        ]
        result = sink.load_rows(rows, "TOUR_BF_API")
        self.assertEqual(result, {"items": 2, "images": 3})
        self.assertEqual(conn.store["commits"], 1)
        # item upserts + image inserts both present
        item_calls = [c for c in conn.store["calls"] if "collect_item" in c[0]]
        img_calls = [c for c in conn.store["calls"] if "collect_img" in c[0]]
        self.assertEqual(len(item_calls), 2)
        self.assertEqual(len(img_calls), 3)
        # image order assigned 1,2 within first item
        self.assertEqual(img_calls[0][1]["img_order"], 1)
        self.assertEqual(img_calls[1][1]["img_order"], 2)


if __name__ == "__main__":
    unittest.main()
