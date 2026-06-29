"""Tests for label_assist.py category normalisation.

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

import label_assist as la


class ClassifyTest(unittest.TestCase):
    def test_employment_categories(self):
        self.assertEqual(la.classify("사무보조 채용 공고")[0], "일자리/채용")
        self.assertEqual(la.classify("직무 적응 교육 과정")[0], "교육")
        self.assertEqual(la.classify("장애인식개선 캠페인 행사")[0], "행사")

    def test_tourism_categories(self):
        self.assertEqual(la.classify("무장애 열린관광 안내")[1], la.DOMAIN_TOURISM)
        self.assertEqual(la.classify("경사로 점자 화장실 설치")[0], "편의시설")

    def test_unclassified_when_no_keyword(self):
        cat, domain, conf, hits = la.classify("zzz 내용 없음 xxxx")
        self.assertEqual(cat, la.UNCLASSIFIED)
        self.assertEqual(conf, 0.0)
        self.assertEqual(hits, 0)

    def test_confidence_increases_with_hits(self):
        one = la.classify("채용")[2]
        many = la.classify("채용 구직 일자리 모집")[2]
        self.assertGreater(many, one)


class LabelRowTest(unittest.TestCase):
    def test_needs_review_when_unclassified(self):
        row = {"No": "1", "Type": "", "Title": "내용 없는 제목 xxx", "Img-link": ""}
        out = la.label_row(row)
        self.assertEqual(out["needs_review"], "Y")

    def test_needs_review_when_type_conflicts(self):
        # Type says 교육 but the title is clearly a 채용 posting.
        row = {"No": "1", "Type": "교육", "Title": "사무보조 채용 구직 공고",
               "Img-link": ""}
        out = la.label_row(row)
        self.assertEqual(out["inferred_category"], "일자리/채용")
        self.assertEqual(out["needs_review"], "Y")

    def test_no_review_when_consistent(self):
        row = {"No": "1", "Type": "교육", "Title": "직무 교육 강좌 연수",
               "Img-link": ""}
        out = la.label_row(row)
        self.assertEqual(out["needs_review"], "N")


class StatsTest(unittest.TestCase):
    def test_build_stats_ratio_sums_to_one(self):
        rows = [la.label_row({"No": str(i), "Type": "교육",
                              "Title": "교육 강좌", "Img-link": ""})
                for i in range(4)]
        stats = la.build_stats(rows)
        self.assertAlmostEqual(sum(s["ratio"] for s in stats), 1.0, places=4)


if __name__ == "__main__":
    unittest.main()
