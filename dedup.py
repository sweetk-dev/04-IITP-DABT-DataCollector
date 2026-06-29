"""dedup.py — content-based duplicate image check (MD5 -> SHA256).

Finds true duplicates by file content, not by name: two files with different
names but identical bytes are duplicates. Improves dataset quality and size.

Strategy (two passes, standard ``hashlib`` only — no added dependency):
  1. Group candidates by a fast MD5 of the file content.
  2. For each MD5 group with more than one file, re-confirm with SHA256 to
     rule out the (vanishingly rare) MD5 collision.
  3. Within each confirmed duplicate set, keep one file (the shortest path,
     then lexicographically first) and mark the rest as delete candidates.

By default this only writes a report. Actual deletion happens only with
``--apply``. Independent CLI utility — does not touch ``downloader.py``.

Usage
-----
    python dedup.py <directory> [--out report.csv] [--apply]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".img"}
CHUNK = 1 << 20  # 1 MiB


def file_hash(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_images(root: Path) -> List[Path]:
    if root.is_file():
        return [root] if root.suffix.lower() in IMAGE_EXTS else []
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in IMAGE_EXTS
    )


def _keep_choice(paths: List[Path]) -> Path:
    """Pick the file to keep: shortest path string, then lexicographic."""
    return sorted(paths, key=lambda p: (len(str(p)), str(p)))[0]


def find_duplicates(files: List[Path]):
    """Return (sets, md5_map). ``sets`` is a list of dicts describing each
    confirmed duplicate set; ``md5_map`` is the first-pass grouping."""
    md5_map: Dict[str, List[Path]] = defaultdict(list)
    for path in files:
        try:
            md5_map[file_hash(path, "md5")].append(path)
        except OSError as exc:
            print(f"[skip] unreadable: {path} ({exc})", file=sys.stderr)

    sets = []
    set_id = 0
    for md5, group in md5_map.items():
        if len(group) < 2:
            continue
        # Re-confirm with SHA256; identical MD5 may (rarely) need splitting.
        sha_map: Dict[str, List[Path]] = defaultdict(list)
        for path in group:
            sha_map[file_hash(path, "sha256")].append(path)
        for sha, confirmed in sha_map.items():
            if len(confirmed) < 2:
                continue
            set_id += 1
            keep = _keep_choice(confirmed)
            sets.append({
                "set_id": set_id,
                "md5": md5,
                "sha256": sha,
                "keep": keep,
                "members": confirmed,
            })
    return sets, md5_map


def write_report(sets, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["set_id", "path", "md5", "sha256", "keep"])
        for s in sets:
            for path in s["members"]:
                writer.writerow([
                    s["set_id"], str(path), s["md5"], s["sha256"],
                    "Y" if path == s["keep"] else "N",
                ])


def apply_deletions(sets) -> int:
    removed = 0
    for s in sets:
        for path in s["members"]:
            if path == s["keep"]:
                continue
            try:
                path.unlink()
                removed += 1
            except OSError as exc:
                print(f"[error] could not delete {path}: {exc}", file=sys.stderr)
    return removed


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Content-based duplicate image check (MD5 -> SHA256).")
    p.add_argument("directory", help="directory (or single file) to scan")
    p.add_argument("--out", default="dedup_report.csv", help="report CSV path")
    p.add_argument("--apply", action="store_true",
                   help="actually delete duplicates (default: report only)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.directory).expanduser().resolve()
    if not root.exists():
        raise SystemExit(f"ERROR: path not found: {root}")

    files = iter_images(root)
    sets, _ = find_duplicates(files)
    dup_candidates = sum(len(s["members"]) - 1 for s in sets)

    out_path = Path(args.out)
    write_report(sets, out_path)

    print(f"Scanned images : {len(files)}")
    print(f"Duplicate sets : {len(sets)}")
    print(f"Removable dups : {dup_candidates}")
    print(f"Report         : {out_path}")

    if args.apply:
        removed = apply_deletions(sets)
        print(f"Deleted        : {removed} file(s)")
    else:
        print("(report only — re-run with --apply to delete)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
