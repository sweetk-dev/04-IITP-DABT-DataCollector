"""Tests for collectors/web_crawl.py (seed-list crawler) — no network.

A fake requests-like session is injected so the crawler logic (allowlist,
link-follow, single-page, row shaping) is exercised offline. robots.txt is
disabled in tests to avoid network.

Run from repo root: ``python -m unittest discover -s tests`` or ``pytest``.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.web_crawl import (
    WebCrawlCollector,
    extract_items_from_html,
    _derive_no,
)


class _FakeResp:
    def __init__(self, text):
        self.text = text
    def raise_for_status(self):
        return None


class _FakeSession:
    def __init__(self, pages, fail_first=None):
        self.pages = pages
        self.headers = {}
        self.calls = {}
        # fail_first: {url: n} -> first n attempts raise, then succeed
        self.fail_first = dict(fail_first or {})
    def get(self, url, timeout=None):
        self.calls[url] = self.calls.get(url, 0) + 1
        if self.fail_first.get(url, 0) >= self.calls[url]:
            raise RuntimeError("transient " + url)
        if url not in self.pages:
            raise RuntimeError("404 " + url)
        return _FakeResp(self.pages[url])


LIST_HTML = """<html><head><title>list</title></head><body>
<a href="/notice/view?id=11">a</a>
<a href="/notice/view?id=22">b</a>
<a href="https://other.com/notice/view?id=99">off-site</a>
<a href="/about">skip</a>
</body></html>"""

ITEM_HTML = """<html><head>
<meta property="og:title" content="장애인 채용 설명회">
<meta property="og:image" content="https://cdn.example.org/cover.png">
</head><body><h1>장애인 채용 설명회</h1>
<img src="/img/p1.jpg"><img src="/img/icon.svg"></body></html>"""


class ExtractTest(unittest.TestCase):
    def test_title_priority_and_image_filter(self):
        out = extract_items_from_html(ITEM_HTML, "https://example.org/notice/view?id=11")
        self.assertEqual(out["title"], "장애인 채용 설명회")
        # og:image kept + p1.jpg kept (image ext), icon.svg dropped
        self.assertIn("https://cdn.example.org/cover.png", out["images"])
        self.assertIn("https://example.org/img/p1.jpg", out["images"])
        self.assertNotIn("https://example.org/img/icon.svg", out["images"])

    def test_og_title_preferred_and_script_ignored(self):
        html = ('<html><head><meta property="og:title" content="진짜 제목">'
                '</head><body><h1><script>var x="ban";</script></h1>'
                '<img src="/news/photo/a.jpg"></body></html>')
        out = extract_items_from_html(html, "https://x.org/news/articleView.html?idxno=1")
        self.assertEqual(out["title"], "진짜 제목")

    def test_chrome_images_excluded(self):
        html = ('<html><body><img src="/news/photo/real.jpg">'
                '<img src="/image/logo/printlogo.png">'
                '<img src="/img/favicon.ico"><img src="/img/sns.png"></body></html>')
        out = extract_items_from_html(html, "https://x.org/a")
        self.assertIn("https://x.org/news/photo/real.jpg", out["images"])
        self.assertFalse(any("logo" in u or "favicon" in u or "sns" in u for u in out["images"]))

    def test_relative_links_resolved(self):
        out = extract_items_from_html(LIST_HTML, "https://example.org/notice/list")
        self.assertIn("https://example.org/notice/view?id=11", out["links"])

    def test_derive_no(self):
        self.assertEqual(_derive_no("https://example.org/notice/view?id=22"), "22")
        self.assertEqual(len(_derive_no("https://example.org/p/no-digits")), 10)


class CrawlTest(unittest.TestCase):
    def _pages(self):
        return {
            "https://example.org/notice/list": LIST_HTML,
            "https://example.org/notice/view?id=11": ITEM_HTML,
            "https://example.org/notice/view?id=22": ITEM_HTML,
        }

    def test_link_follow_with_allowlist(self):
        site = {
            "name": "t", "seeds": ["https://example.org/notice/list"],
            "type": "행사", "link_pattern": r"/notice/view\?id=\d+",
        }
        c = WebCrawlCollector(
            sites=[site], respect_robots=False, delay=0,
            session=_FakeSession(self._pages()),
        )
        rows = c.collect()
        # only the two example.org items (other.com is off-allowlist)
        self.assertEqual(len(rows), 2)
        nos = sorted(r["No"] for r in rows)
        self.assertEqual(nos, ["t:11", "t:22"])
        for r in rows:
            self.assertEqual(r["Type"], "행사")
            self.assertTrue(r["Title"])
            self.assertIn("cover.png", r["Img-link"])

    def test_single_page_mode(self):
        site = {"name": "s", "seeds": ["https://example.org/notice/view?id=11"], "type": ""}
        c = WebCrawlCollector(
            sites=[site], respect_robots=False, delay=0,
            session=_FakeSession(self._pages()),
        )
        rows = c.collect()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["No"], "s:11")
        self.assertEqual(rows[0]["Type"], "")  # left blank for label_assist

    def test_max_items(self):
        site = {
            "name": "t", "seeds": ["https://example.org/notice/list"],
            "link_pattern": r"/notice/view\?id=\d+", "max_items": 1,
        }
        c = WebCrawlCollector(
            sites=[site], respect_robots=False, delay=0,
            session=_FakeSession(self._pages()),
        )
        self.assertEqual(len(c.collect()), 1)

    def test_missing_config_raises(self):
        with self.assertRaises(SystemExit):
            WebCrawlCollector(respect_robots=False).collect()


class RobustnessTest(unittest.TestCase):
    LIST = ('<a href="/v?id=1">a</a><a href="/v?id=2">b</a>')
    ITEM = ('<html><head><meta property="og:image" '
            'content="https://example.org/c.png"></head>'
            '<body><h1>제목</h1></body></html>')

    def _pages(self):
        return {
            "https://example.org/list": self.LIST,
            "https://example.org/v?id=1": self.ITEM,
            "https://example.org/v?id=2": self.ITEM,
        }

    def test_retry_then_succeed(self):
        sess = _FakeSession(self._pages(), fail_first={"https://example.org/v?id=1": 1})
        site = {"name": "t", "seeds": ["https://example.org/list"],
                "link_pattern": r"/v\?id=\d+"}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              backoff=0, retries=2, session=sess)
        rows = c.collect()
        self.assertEqual(len(rows), 2)          # recovered after one transient
        self.assertEqual(c.errors, [])
        self.assertEqual(sess.calls["https://example.org/v?id=1"], 2)

    def test_error_captured_after_exhausting_retries(self):
        sess = _FakeSession(self._pages(), fail_first={"https://example.org/v?id=2": 9})
        site = {"name": "t", "seeds": ["https://example.org/list"],
                "link_pattern": r"/v\?id=\d+"}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              backoff=0, retries=2, session=sess)
        rows = c.collect()
        self.assertEqual(len(rows), 1)          # id=1 ok, id=2 failed
        self.assertEqual(len(c.errors), 1)
        self.assertEqual(c.errors[0]["url"], "https://example.org/v?id=2")

    def test_pagination_expands_seeds(self):
        pages = {
            "https://example.org/list?page=1": '<a href="/v?id=1">a</a>',
            "https://example.org/list?page=2": '<a href="/v?id=2">b</a>',
            "https://example.org/v?id=1": self.ITEM,
            "https://example.org/v?id=2": self.ITEM,
        }
        site = {"name": "t", "seeds": ["https://example.org/list"],
                "link_pattern": r"/v\?id=\d+",
                "paginate": {"param": "page", "start": 1, "end": 2}}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              session=_FakeSession(pages))
        rows = c.collect()
        self.assertEqual(sorted(r["No"] for r in rows), ["t:1", "t:2"])

    def test_duplicate_item_urls_deduped(self):
        # both list pages link to the SAME item -> one row only
        pages = {
            "https://example.org/list?page=1": '<a href="/v?id=1">a</a>',
            "https://example.org/list?page=2": '<a href="/v?id=1">a</a>',
            "https://example.org/v?id=1": self.ITEM,
        }
        site = {"name": "t", "seeds": ["https://example.org/list"],
                "link_pattern": r"/v\?id=\d+",
                "paginate": {"param": "page", "start": 1, "end": 2}}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              session=_FakeSession(pages))
        self.assertEqual(len(c.collect()), 1)

    def test_write_errors_file(self):
        import tempfile
        sess = _FakeSession(self._pages(), fail_first={"https://example.org/v?id=1": 9,
                                                       "https://example.org/v?id=2": 9})
        site = {"name": "t", "seeds": ["https://example.org/list"],
                "link_pattern": r"/v\?id=\d+"}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              backoff=0, retries=0, session=sess)
        c.collect()
        with tempfile.TemporaryDirectory() as d:
            ep = Path(d) / "errs.csv"
            c.write_errors(ep)
            import csv as _csv
            with ep.open(encoding="utf-8-sig") as f:
                erows = list(_csv.DictReader(f))
            self.assertEqual(len(erows), 2)
            self.assertEqual(sorted(r["url"].rsplit("=", 1)[1] for r in erows), ["1", "2"])


if __name__ == "__main__":
    unittest.main()
