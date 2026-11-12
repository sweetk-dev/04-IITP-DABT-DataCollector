"""Tests for image_store.py — 한 번만 받기·경로/해시 기록·중복 표시 (가짜 DB·가짜 다운로드)."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import image_store
import scripts.migrate_dated_downloads as mig  # noqa: E402


class _Cur:
    def __init__(self, rows): self.rows = rows
    def execute(self, sql, params=None): pass
    def fetchall(self): return list(self.rows)
    def close(self): pass


class _Conn:
    def __init__(self, rows): self.rows, self.commits = rows, 0
    def cursor(self): return _Cur(self.rows)
    def commit(self): self.commits += 1


class _Sink:
    def __init__(self): self.downloads, self.dedups = [], []
    def update_download(self, item_id, url, path, ext, ok, err=None): self.downloads.append((item_id, url, path, ok))
    def update_dedup(self, img_id, md5, sha, is_dup, dup_of=None): self.dedups.append((img_id, sha, is_dup, dup_of))


def _fetch_bytes(content_by_url):
    calls = []
    def fetch(session, url, dest):
        calls.append(url)
        dest = dest.with_suffix(".jpg")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(content_by_url[url])
        return True, None, ".jpg"
    fetch.calls = calls
    return fetch


class ImageStoreTest(unittest.TestCase):
    def test_stable_path_and_ext(self):
        p = image_store.stable_path(Path("r"), "TOUR_BF_API", "12/34", 2, ".png")
        self.assertEqual(p, Path("r") / "TOUR_BF_API" / "12_34_2.png")
        self.assertEqual(image_store.guess_ext("http://x/a.JPEG"), ".jpg")
        self.assertEqual(image_store.guess_ext("http://x/a.do", "image/png"), ".png")
        self.assertEqual(image_store.guess_ext("http://x/a"), ".jpg")

    def test_first_run_downloads_and_marks_same_content(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [  # img_id, item_id, img_order, url, local_path, download_yn, sha, src_no
                (1, 10, 1, "http://x/a", None, "N", None, "100"),
                (2, 10, 2, "http://x/b", None, "N", None, "100"),
                (3, 11, 1, "http://x/c", None, "N", None, "101"),
            ]
            fetch = _fetch_bytes({"http://x/a": b"A", "http://x/b": b"B", "http://x/c": b"A"})
            sink, conn = _Sink(), _Conn(rows)
            st = image_store.sync_images(conn, sink, "TOUR_BF_API", Path(d), None, fetch=fetch)
            self.assertEqual(st["downloaded"], 3)
            self.assertEqual(st["dups"], 1)
            # 3번은 1번과 내용이 같다 → 중복 표시, 사본 파일은 지워지고 1번 파일을 가리킨다
            self.assertIn((3, image_store.file_hashes(Path(d) / "TOUR_BF_API" / "100_1.jpg")[1], True, 1), sink.dedups)
            self.assertFalse((Path(d) / "TOUR_BF_API" / "101_1.jpg").exists())
            self.assertEqual(sink.downloads[-1][2], str(Path(d) / "TOUR_BF_API" / "100_1.jpg"))
            self.assertEqual(conn.commits, 1)

    def test_second_run_skips_existing(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "TOUR_BF_API" / "100_1.jpg"
            f.parent.mkdir(parents=True)
            f.write_bytes(b"A")
            sha = image_store.file_hashes(f)[1]
            rows = [(1, 10, 1, "http://x/a", str(f), "Y", sha, "100")]
            fetch = _fetch_bytes({})
            sink = _Sink()
            st = image_store.sync_images(_Conn(rows), sink, "TOUR_BF_API", Path(d), None, fetch=fetch)
            self.assertEqual(fetch.calls, [])          # 다시 받지 않는다
            self.assertEqual(st["skipped"], 1)
            self.assertEqual(sink.downloads, [])
            self.assertEqual(sink.dedups, [])          # 해시도 이미 있어 다시 계산하지 않는다

    def test_missing_file_is_refetched(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [(1, 10, 1, "http://x/a", str(Path(d) / "gone.jpg"), "Y", "abc", "100")]
            fetch = _fetch_bytes({"http://x/a": b"A"})
            st = image_store.sync_images(_Conn(rows), _Sink(), "TOUR_BF_API", Path(d), None, fetch=fetch)
            self.assertEqual(fetch.calls, ["http://x/a"])
            self.assertEqual(st["downloaded"], 1)

    def test_failed_download_recorded(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [(1, 10, 1, "http://x/a", None, "N", None, "100")]
            sink = _Sink()
            st = image_store.sync_images(_Conn(rows), sink, "TOUR_BF_API", Path(d), None,
                                         fetch=lambda s, u, p: (False, "HTTP 404", ""))
            self.assertEqual(st["failed"], 1)
            self.assertEqual(sink.downloads, [(10, "http://x/a", None, False)])

    def test_dup_dir_moves_instead_of_delete(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [(1, 10, 1, "http://x/a", None, "N", None, "100"), (2, 11, 1, "http://x/c", None, "N", None, "101")]
            fetch = _fetch_bytes({"http://x/a": b"A", "http://x/c": b"A"})
            q = Path(d) / "q"
            image_store.sync_images(_Conn(rows), _Sink(), "T", Path(d) / "r", None, fetch=fetch, dup_dir=q)
            self.assertTrue((q / "T" / "101_1.jpg").exists())

    def test_parse_legacy_name(self):
        self.assertEqual(mig.parse_legacy("1433504.쇼핑-가경 터미널시장_ 2026_06_30_16_11_1.jpg"),
                         ("1433504", 1, "2026_06_30_16_11"))
        self.assertEqual(mig.parse_legacy("12.관광지-제목_ 2026_07_05_03_00_3.png")[1], 3)
        self.assertIsNone(mig.parse_legacy("random.jpg"))


if __name__ == "__main__":
    unittest.main()
