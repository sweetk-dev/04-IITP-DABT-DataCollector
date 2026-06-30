"""Tests for collectors/discovery.py — search-driven seed discovery (offline)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collectors.discovery import discover_seeds, file_search_fn, build_search_fn
from collectors.web_crawl import WebCrawlCollector


class DiscoverSeedsTest(unittest.TestCase):
    def test_dedup_and_http_filter(self):
        def fn(q):
            return ["https://a.org/1", "ftp://x/y", "https://a.org/1", "https://b.org/2"]
        seeds = discover_seeds(["k1", "k2"], fn)
        self.assertEqual(seeds, ["https://a.org/1", "https://b.org/2"])

    def test_max_results_cap(self):
        def fn(q):
            return ["https://a.org/1", "https://a.org/2", "https://a.org/3"]
        self.assertEqual(len(discover_seeds(["k"], fn, max_results=2)), 2)

    def test_provider_error_is_non_fatal(self):
        def fn(q):
            raise RuntimeError("boom")
        self.assertEqual(discover_seeds(["k"], fn), [])


class FileSearchFnTest(unittest.TestCase):
    def test_substring_match(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "disc.json"
            p.write_text(json.dumps({"장애인 채용": ["https://x/1"]}, ensure_ascii=False),
                         encoding="utf-8")
            fn = file_search_fn(str(p))
            self.assertEqual(fn("장애인 채용 공고"), ["https://x/1"])
            self.assertEqual(fn("관광"), [])


class BuildSearchFnTest(unittest.TestCase):
    def test_injected_callable_wins(self):
        f = lambda q: ["https://x/1"]
        self.assertIs(build_search_fn({"search_fn": f}), f)

    def test_none_when_unconfigured(self):
        self.assertIsNone(build_search_fn({}))


class DiscoveryIntegrationTest(unittest.TestCase):
    def test_crawl_uses_discovered_seeds(self):
        item = ('<html><head><meta property="og:image" '
                'content="https://found.org/c.png"></head><body><h1>제목</h1></body></html>')
        pages = {"https://found.org/page": item}

        class _Resp:
            def __init__(s, t): s.text = t
            def raise_for_status(s): pass
        class _Sess:
            headers = {}
            def get(s, u, timeout=None):
                if u not in pages: raise RuntimeError("404")
                return _Resp(pages[u])

        site = {"name": "auto", "discover": {"keywords": ["장애인 채용"]}, "type": "채용"}
        search_fn = lambda q: ["https://found.org/page"]
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0,
                              search_fn=search_fn, session=_Sess())
        rows = c.collect()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Type"], "채용")
        self.assertIn("found.org", rows[0]["Img-link"])

    def test_discover_without_provider_raises(self):
        site = {"name": "auto", "discover": {"keywords": ["x"]}}
        c = WebCrawlCollector(sites=[site], respect_robots=False, delay=0)
        with self.assertRaises(SystemExit):
            c.collect()


if __name__ == "__main__":
    unittest.main()
