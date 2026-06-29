"""Tests for split_manifest.py stratified splitting.

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

import split_manifest as sm


class ParseRatioTest(unittest.TestCase):
    def test_normalises_to_fractions(self):
        r = sm.parse_ratio("8:1:1")
        self.assertAlmostEqual(sum(r), 1.0, places=6)
        self.assertAlmostEqual(r[0], 0.8, places=6)

    def test_invalid_raises(self):
        with self.assertRaises(SystemExit):
            sm.parse_ratio("8:1")


class SplitTest(unittest.TestCase):
    def _items(self, n_per_cat=10, cats=("A", "B")):
        items = []
        for c in cats:
            for i in range(n_per_cat):
                items.append({"path": f"{c}/{i}.jpg", "category": c})
        return items

    def test_counts_preserved(self):
        items = self._items()
        rows = sm.stratified_split(items, sm.parse_ratio("8:1:1"), seed=42)
        self.assertEqual(len(rows), len(items))
        for r in rows:
            self.assertIn(r["split"], sm.SPLIT_NAMES)

    def test_deterministic_with_same_seed(self):
        items = self._items()
        a = sm.stratified_split(items, sm.parse_ratio("8:1:1"), seed=7)
        b = sm.stratified_split(items, sm.parse_ratio("8:1:1"), seed=7)
        self.assertEqual([r["split"] for r in a], [r["split"] for r in b])

    def test_stratified_ratio_per_category(self):
        items = self._items(n_per_cat=10, cats=("A",))
        rows = sm.stratified_split(items, sm.parse_ratio("8:1:1"), seed=1)
        counts = {s: sum(1 for r in rows if r["split"] == s) for s in sm.SPLIT_NAMES}
        self.assertEqual(counts["train"], 8)
        self.assertEqual(counts["val"], 1)
        self.assertEqual(counts["test"], 1)


if __name__ == "__main__":
    unittest.main()
