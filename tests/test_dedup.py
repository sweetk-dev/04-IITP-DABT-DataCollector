"""Tests for dedup.py content-based duplicate detection.

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

import tempfile

import dedup


class DedupTest(unittest.TestCase):
    def _make(self, d, name, content):
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return p

    def test_detects_content_duplicate_across_names(self):
        with tempfile.TemporaryDirectory() as d:
            self._make(d, "a/one.jpg", b"SAME-BYTES")
            self._make(d, "b/copy.png", b"SAME-BYTES")
            self._make(d, "a/diff.jpg", b"OTHER")
            files = dedup.iter_images(Path(d))
            sets, _ = dedup.find_duplicates(files)
            self.assertEqual(len(sets), 1)
            members = sets[0]["members"]
            self.assertEqual(len(members), 2)
            keeps = [m for m in members if m == sets[0]["keep"]]
            self.assertEqual(len(keeps), 1)

    def test_no_false_positive(self):
        with tempfile.TemporaryDirectory() as d:
            self._make(d, "x.jpg", b"A")
            self._make(d, "y.jpg", b"B")
            sets, _ = dedup.find_duplicates(dedup.iter_images(Path(d)))
            self.assertEqual(sets, [])

    def test_apply_deletes_only_non_kept(self):
        with tempfile.TemporaryDirectory() as d:
            self._make(d, "a/one.jpg", b"DUP")
            self._make(d, "b/two.jpg", b"DUP")
            sets, _ = dedup.find_duplicates(dedup.iter_images(Path(d)))
            removed = dedup.apply_deletions(sets)
            self.assertEqual(removed, 1)
            remaining = dedup.iter_images(Path(d))
            self.assertEqual(len(remaining), 1)
            self.assertEqual(remaining[0], sets[0]["keep"])


if __name__ == "__main__":
    unittest.main()
