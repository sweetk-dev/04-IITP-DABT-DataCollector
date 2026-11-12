"""Tests for inst_crawl.runner — 기관 자료실 정기 수집의 새 파일 고르기·목록 작성.

Standard-library ``unittest`` only. Run from the repo root with:
``python -m unittest discover -s tests``
"""
import csv
import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from inst_crawl import runner  # noqa: E402

SITE_DOC = {"name": "기관A", "script": "기관A.py", "구분": "기초", "분류": "분류A", "enabled": True}
SITE_IMG = {"name": "여행B", "script": "여행B.py", "구분": "이동권", "분류": "분류B", "enabled": True}


def _w(p: Path, data: bytes) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _manifest(out: Path, period: str):
    with open(out / period / "manifest.csv", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


class PeriodTest(unittest.TestCase):
    def test_quarter(self):
        self.assertEqual(runner.period_of(dt.date(2026, 11, 12)), "2026Q4")
        self.assertEqual(runner.period_of(dt.date(2027, 1, 8)), "2027Q1")
        self.assertEqual(runner.period_of(dt.date(2027, 6, 30)), "2027Q2")


class ClassifyTest(unittest.TestCase):
    def test_rules(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            self.assertIsNone(runner.classify_file(_w(d / "a.pdf", b"x" * 2000), "기초"))
            self.assertIsNone(runner.classify_file(_w(d / "b.HWP", b"x" * 2000), "기초"))
            self.assertEqual(runner.classify_file(_w(d / "c.jpg", b"x" * 50000), "기초"), "ext")
            self.assertEqual(runner.classify_file(_w(d / "d.pdf", b"x" * 10), "기초"), "small")
            self.assertEqual(runner.classify_file(_w(d / "download_log.csv", b"x" * 5000), "기초"), "log")
            self.assertEqual(runner.classify_file(_w(d / "run_2026Q4.log", b"x" * 5000), "기초"), "log")
            self.assertIsNone(runner.classify_file(_w(d / "e.jpg", b"x" * 50000), "이동권"))
            self.assertEqual(runner.classify_file(_w(d / "icon.png", b"x" * 500), "이동권"), "small")
            self.assertEqual(runner.classify_file(_w(d / "f.pdf", b"x" * 50000), "이동권"), "ext")


class CollectNewTest(unittest.TestCase):
    def test_new_files_only_across_runs_and_seed(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            work, out = d / "work", d / "out"
            wa = work / "기관A"
            _w(wa / "dl" / "one.pdf", b"ONE" * 1000)
            _w(wa / "dl" / "two.hwp", b"TWO" * 1000)
            _w(wa / "dl" / "copy_of_one.pdf", b"ONE" * 1000)       # 같은 내용 — 한 번만
            _w(wa / "dl" / "download_log.csv", b"log" * 1000)       # 기록 파일 — 거름
            seeded = _w(d / "old.pdf", b"OLD" * 1000)                 # 이전 제출분
            _w(wa / "dl" / "old_again.pdf", seeded.read_bytes())
            _w(wa / "기관A.py", b"print(1)")                          # 수집기 코드 — 대상 아님

            led = runner.Ledger(work / runner.LEDGER_NAME)
            self.assertEqual(led.add_seed([runner.sha256_of(seeded) + "\n"]), 1)
            st = runner.collect_new([SITE_DOC], work, out, "2026Q4", led, now="2026-11-12 18:00:00")["기관A"]
            self.assertEqual((st["new"], st["dup"], st["skip_log"]), (2, 2, 1))
            rows = _manifest(out, "2026Q4")
            # 같은 내용은 경로 순서상 먼저 나온 파일 하나만 남는다
            self.assertEqual(sorted(r["파일"] for r in rows), ["dl/copy_of_one.pdf", "dl/two.hwp"])
            self.assertTrue(all(r["자동수집"] == "Y" and r["분류"] == "분류A" for r in rows))
            for r in rows:
                self.assertTrue((out / "2026Q4" / "기초" / "분류A" / "기관A" / r["파일"]).is_file())

            # 다음 분기: 새 첨부 1개만 더 올라옴 → 그것만 잡힌다 (원장은 파일에서 다시 읽음)
            _w(wa / "dl" / "three.pdf", b"THREE" * 1000)
            led2 = runner.Ledger(work / runner.LEDGER_NAME)
            st2 = runner.collect_new([SITE_DOC], work, out, "2027Q1", led2)["기관A"]
            self.assertEqual(st2["new"], 1)
            self.assertEqual([r["파일"] for r in _manifest(out, "2027Q1")], ["dl/three.pdf"])

    def test_same_period_rerun_appends_without_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            work, out = d / "work", d / "out"
            _w(work / "여행B" / "img" / "a.jpg", b"A" * 20000)
            runner.collect_new([SITE_IMG], work, out, "2026Q4", runner.Ledger(work / runner.LEDGER_NAME))
            _w(work / "여행B" / "img" / "b.jpg", b"B" * 20000)
            runner.collect_new([SITE_IMG], work, out, "2026Q4", runner.Ledger(work / runner.LEDGER_NAME))
            self.assertEqual(sorted(r["파일"] for r in _manifest(out, "2026Q4")), ["img/a.jpg", "img/b.jpg"])


class RunSiteTest(unittest.TestCase):
    def test_runs_script_in_its_work_folder(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            sites_dir = d / "sites"
            _w(sites_dir / "기관A.py", b"import pathlib\npathlib.Path('dl').mkdir(exist_ok=True)\n"
                                       b"pathlib.Path('dl/new.pdf').write_bytes(b'N'*4000)\n")
            with mock.patch.object(runner, "SITES_DIR", sites_dir):
                r = runner.run_site(SITE_DOC, d / "work", sys.executable, 60, "2026Q4")
            self.assertEqual(r["rc"], 0)
            self.assertTrue((d / "work" / "기관A" / "dl" / "new.pdf").is_file())
            self.assertTrue((d / "work" / "기관A" / "run_2026Q4.log").is_file())

    def test_timeout_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _w(d / "sites" / "기관A.py", b"import time\ntime.sleep(5)\n")
            with mock.patch.object(runner, "SITES_DIR", d / "sites"):
                r = runner.run_site(SITE_DOC, d / "work", sys.executable, 1, "2026Q4")
            self.assertEqual(r["rc"], "timeout")


class SitesConfigTest(unittest.TestCase):
    def test_every_site_has_script(self):
        sites = runner.load_sites()
        self.assertGreater(len(sites), 0)
        for s in sites:
            self.assertTrue((runner.SITES_DIR / s["script"]).is_file(), s["script"])
            self.assertIn(s["구분"], runner.KEEP_EXT)

    def test_main_no_run_writes_summary(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            _w(d / "work" / "기관A" / "dl" / "x.pdf", b"X" * 3000)
            with mock.patch.object(runner, "load_sites", return_value=[SITE_DOC]):
                rc = runner.main(["--work", str(d / "work"), "--out", str(d / "out"), "--no-run", "--period", "2026Q4"])
            self.assertEqual(rc, 0)
            s = json.loads((d / "out" / "2026Q4" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(s["new_total"], 1)


class PlaceTypesTest(unittest.TestCase):
    def test_place_of(self):
        self.assertEqual(runner.place_of("과천 렛츠런파크_3.jpg"), "과천 렛츠런파크")
        self.assertEqual(runner.place_of("가나아트파크_무장애관광 시설 편의시설 2.jpg"), "가나아트파크")
        self.assertEqual(runner.place_of("이름만.jpg"), "이름만")

    def test_classified_per_place_and_unknown_reported(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            types_dir = d / "pkg"
            _w(types_dir / "place_types" / "t.csv",
               "장소,분류,비고\n과천 렛츠런파크,체험,\n가평 자라섬,관람_자연,\n".encode("utf-8-sig"))
            site = dict(SITE_IMG, 분류="미분류", place_types="place_types/t.csv")
            wd = d / "work" / site["name"]
            _w(wd / "img" / "과천 렛츠런파크_1.jpg", b"A" * 20000)
            _w(wd / "img" / "가평  자라섬_1.jpg", b"B" * 20000)       # 공백 차이는 같은 장소
            _w(wd / "img" / "새로운 장소_1.jpg", b"C" * 20000)
            with mock.patch.object(runner, "HERE", types_dir):
                st = runner.collect_new([site], d / "work", d / "out", "2027Q1",
                                        runner.Ledger(d / "work" / runner.LEDGER_NAME))[site["name"]]
            got = {r["파일"]: r["분류"] for r in _manifest(d / "out", "2027Q1")}
            self.assertEqual(got, {"img/과천 렛츠런파크_1.jpg": "체험", "img/가평  자라섬_1.jpg": "관람_자연",
                                   "img/새로운 장소_1.jpg": "미분류"})
            self.assertEqual(st["unknown_places"], {"새로운 장소": 1})
            self.assertTrue((d / "out" / "2027Q1" / "이동권" / "체험" / site["name"] / "img" / "과천 렛츠런파크_1.jpg").is_file())

    def test_shipped_place_types_cover_2025_places(self):
        for s in runner.load_sites():
            types = runner.load_place_types(s)
            if types is not None:
                self.assertGreater(len(types), 0)
                self.assertTrue(set(types.values()) <= {"관람_시설", "관람_자연", "체험", "활동", "카페", "식당", "쇼핑"})


if __name__ == "__main__":
    unittest.main()
