"""Tests for collectors/tour_api.py (Korea Tourism barrier-free API) — no network/key.

A fake (operation, params)->dict getter is injected so the adapter logic
(pagination, max_items, detailImage merge, mapping) is exercised offline.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.tour_api import (
    ApiListCollector, parse_area_items, parse_detail_images, total_count,
)


def _area_payload(items, total):
    return {"response": {"header": {"resultCode": "0000"},
                         "body": {"items": {"item": items}, "totalCount": total}}}


class ParseTest(unittest.TestCase):
    def test_parse_list(self):
        payload = _area_payload([
            {"contentid": "101", "title": "무장애 둘레길", "firstimage": "http://x/1.jpg",
             "contenttypeid": "12"},
            {"contentid": "102", "title": "행사 마당", "firstimage": "http://x/2.jpg",
             "firstimage2": "http://x/2s.jpg", "contenttypeid": "15"},
        ], 2)
        rows = parse_area_items(payload)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["No"], "101")
        self.assertEqual(rows[0]["Type"], "관광지")     # contenttypeid 12
        self.assertEqual(rows[1]["Type"], "행사")        # contenttypeid 15
        self.assertIn("http://x/2s.jpg", rows[1]["Img-link"])

    def test_parse_single_item_dict(self):
        # TourAPI returns a dict (not list) when there is exactly one result
        payload = _area_payload({"contentid": "9", "title": "단일", "firstimage": "http://x/a.jpg"}, 1)
        rows = parse_area_items(payload)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["No"], "9")

    def test_item_without_image_or_title_skipped(self):
        payload = _area_payload([{"contentid": "1", "title": ""},
                                 {"contentid": "", "title": "x"}], 2)
        self.assertEqual(parse_area_items(payload), [])

    def test_parse_detail_images(self):
        payload = {"response": {"body": {"items": {"item": [
            {"originimgurl": "http://x/o1.jpg"}, {"originimgurl": "http://x/o2.jpg"}]}}}}
        self.assertEqual(parse_detail_images(payload),
                         ["http://x/o1.jpg", "http://x/o2.jpg"])

    def test_total_count(self):
        self.assertEqual(total_count(_area_payload([], 57)), 57)


class CollectTest(unittest.TestCase):
    def _getter(self, pages, images=None):
        def fn(op, params):
            if op.startswith("areaBasedList"):
                pno = int(params["pageNo"])
                return pages.get(pno, _area_payload([], pages["_total"]))
            if op.startswith("detailImage"):
                cid = params["contentId"]
                return {"response": {"body": {"items": {"item":
                        [{"originimgurl": u} for u in (images or {}).get(cid, [])]}}}}
            return {}
        return fn

    def test_pagination_until_total(self):
        pages = {"_total": 3,
                 1: _area_payload([{"contentid": "1", "title": "a", "firstimage": "http://x/1.jpg"},
                                   {"contentid": "2", "title": "b", "firstimage": "http://x/2.jpg"}], 3),
                 2: _area_payload([{"contentid": "3", "title": "c", "firstimage": "http://x/3.jpg"}], 3)}
        c = ApiListCollector(http_get_json=self._getter(pages), num_rows=2)
        rows = c.collect()
        self.assertEqual([r["No"] for r in rows], ["1", "2", "3"])
        self.assertNotIn("_contentid", rows[0])  # internal field dropped

    def test_max_items(self):
        pages = {"_total": 9,
                 1: _area_payload([{"contentid": str(i), "title": "t", "firstimage": "http://x/i.jpg"}
                                   for i in range(5)], 9)}
        c = ApiListCollector(http_get_json=self._getter(pages), num_rows=5, max_items=3)
        self.assertEqual(len(c.collect()), 3)

    def test_with_images_merges_detail(self):
        pages = {"_total": 1,
                 1: _area_payload([{"contentid": "1", "title": "a", "firstimage": "http://x/first.jpg"}], 1)}
        images = {"1": ["http://x/first.jpg", "http://x/extra.jpg"]}
        c = ApiListCollector(http_get_json=self._getter(pages, images), with_images=True)
        rows = c.collect()
        urls = rows[0]["Img-link"].split("\n")
        self.assertIn("http://x/extra.jpg", urls)
        self.assertEqual(urls.count("http://x/first.jpg"), 1)  # de-duped

    def test_missing_key_raises(self):
        import os
        old = os.environ.pop("TOUR_API_KEY", None)
        try:
            with self.assertRaises(SystemExit):
                ApiListCollector().collect()
        finally:
            if old is not None:
                os.environ["TOUR_API_KEY"] = old


class HttpRetryTest(unittest.TestCase):
    def test_transient_failure_then_success(self):
        import requests
        class _Resp:
            def __init__(s, data): s._d = data
            def raise_for_status(s): return None
            def json(s): return s._d
        payload = {"response": {"body": {"items": {"item": [
            {"contentid": "1", "title": "t", "firstimage": "http://x/1.jpg"}]}, "totalCount": 1}}}
        class _Sess:
            def __init__(s): s.n = 0
            def get(s, url, timeout=None):
                s.n += 1
                if s.n < 3:
                    raise requests.exceptions.HTTPError("401 Client Error")
                return _Resp(payload)
        sess = _Sess()
        c = ApiListCollector(service_key="k", session=sess, backoff=0, retries=3)
        rows = c.collect()
        self.assertEqual(len(rows), 1)
        self.assertEqual(sess.n, 3)  # 2 failures + 1 success

    def test_error_message_redacts_key(self):
        import requests
        class _Sess:
            def get(s, url, timeout=None):
                raise requests.exceptions.HTTPError("boom DUMMYKEY_ABC123 key")
        c = ApiListCollector(service_key="DUMMYKEY_ABC123", session=_Sess(), backoff=0, retries=0)
        with self.assertRaises(SystemExit) as ctx:
            c.collect()
        self.assertNotIn("DUMMYKEY_ABC123", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
