"""split_manifest.py — dataset split manifest (stratified, reproducible).

Splits a labelled image list into train/val/test with category stratification
and a fixed, recorded seed, so the split is reproducible. Directly supports
the "dataset generation" purpose of this module.

Input
-----
  * a labelled CSV (e.g. ``*_labeled.csv`` from ``label_assist.py``); the item
    key is ``Img-link`` (or ``No`` when present) and the stratification
    category is ``inferred_category`` (falls back to ``Type``), or
  * a directory of images; the item key is the file path and the category is
    the immediate parent folder name (flat directories become "기타/미분류").

Output (next to input or under --out-dir)
  dataset_manifest.csv / .json   path, category, split
  plus a per-split x per-category summary printed and embedded in the JSON.

Ratios and seed come from CLI (``--ratio 8:1:1`` / ``--seed 42``) or env
(``SPLIT_RATIO`` / ``SPLIT_SEED``). Standard library only.

Usage
-----
    python split_manifest.py <labeled.csv | directory> [--ratio 8:1:1] \
        [--seed 42] [--out-dir DIR]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

SPLIT_NAMES = ["train", "val", "test"]
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".img"}
UNCLASSIFIED = "기타/미분류"


def parse_ratio(text: str) -> Tuple[float, float, float]:
    parts = [p for p in str(text).replace(",", ":").split(":") if p != ""]
    if len(parts) != 3:
        raise SystemExit(f"ERROR: --ratio must be three parts like 8:1:1, got: {text!r}")
    try:
        nums = [float(p) for p in parts]
    except ValueError:
        raise SystemExit(f"ERROR: --ratio parts must be numbers, got: {text!r}")
    total = sum(nums)
    if total <= 0:
        raise SystemExit("ERROR: --ratio sum must be positive")
    return tuple(n / total for n in nums)  # normalised fractions


def read_items(path: Path) -> List[Dict[str, str]]:
    """Return items as dicts with keys: path, category."""
    if path.is_dir():
        return _read_directory(path)
    if path.suffix.lower() == ".csv":
        return _read_csv(path)
    raise SystemExit(f"ERROR: input must be a .csv or a directory, got: {path}")


def _read_directory(root: Path) -> List[Dict[str, str]]:
    items = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in IMAGE_EXTS:
            category = p.parent.name if p.parent != root else UNCLASSIFIED
            items.append({"path": str(p), "category": category or UNCLASSIFIED})
    return items


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise SystemExit("ERROR: input CSV has no header")
        fields = reader.fieldnames
        key_field = "Img-link" if "Img-link" in fields else ("No" if "No" in fields else None)
        if key_field is None:
            raise SystemExit(f"ERROR: CSV needs Img-link or No column; got: {fields}")
        cat_field = "inferred_category" if "inferred_category" in fields else (
            "Type" if "Type" in fields else None)
        items = []
        for src in reader:
            key = (src.get(key_field, "") or "").strip()
            if not key:
                continue
            category = (src.get(cat_field, "") or "").strip() if cat_field else ""
            items.append({"path": key, "category": category or UNCLASSIFIED})
        return items


def stratified_split(items: List[Dict[str, str]], ratios: Tuple[float, float, float],
                     seed: int) -> List[Dict[str, str]]:
    """Assign each item a split, stratified per category with a fixed seed."""
    rng = random.Random(seed)
    by_cat: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for it in items:
        by_cat[it["category"]].append(it)

    out: List[Dict[str, str]] = []
    for category in sorted(by_cat.keys()):
        members = by_cat[category][:]
        rng.shuffle(members)
        n = len(members)
        n_train = int(n * ratios[0])
        n_val = int(n * ratios[1])
        # Remainder goes to test so the counts always sum to n.
        for idx, it in enumerate(members):
            if idx < n_train:
                split = "train"
            elif idx < n_train + n_val:
                split = "val"
            else:
                split = "test"
            row = dict(it)
            row["split"] = split
            out.append(row)
    return out


def summarise(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, int]]:
    summary: Dict[str, Dict[str, int]] = defaultdict(lambda: {s: 0 for s in SPLIT_NAMES})
    for r in rows:
        summary[r["category"]][r["split"]] += 1
    return {k: dict(v) for k, v in summary.items()}


def write_outputs(rows, summary, ratios, seed, out_dir: Path, stem: str) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_csv = out_dir / "dataset_manifest.csv"
    manifest_json = out_dir / "dataset_manifest.json"

    with manifest_csv.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "category", "split"])
        for r in rows:
            writer.writerow([r["path"], r["category"], r["split"]])

    split_totals = {s: sum(1 for r in rows if r["split"] == s) for s in SPLIT_NAMES}
    payload = {
        "source": stem,
        "seed": seed,
        "ratio": {SPLIT_NAMES[i]: round(ratios[i], 4) for i in range(3)},
        "total": len(rows),
        "split_totals": split_totals,
        "by_category": summary,
    }
    with manifest_json.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return manifest_csv, manifest_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Build a stratified, reproducible train/val/test split manifest.")
    p.add_argument("input", help="labelled CSV or image directory")
    p.add_argument("--ratio", default=os.getenv("SPLIT_RATIO", "8:1:1"),
                   help="train:val:test ratio (default 8:1:1 or SPLIT_RATIO env)")
    p.add_argument("--seed", type=int, default=int(os.getenv("SPLIT_SEED", "42")),
                   help="random seed (default 42 or SPLIT_SEED env)")
    p.add_argument("--out-dir", help="output directory (default: next to input)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    in_path = Path(args.input).expanduser().resolve()
    if not in_path.exists():
        raise SystemExit(f"ERROR: input not found: {in_path}")

    ratios = parse_ratio(args.ratio)
    items = read_items(in_path)
    if not items:
        raise SystemExit("ERROR: no items found to split")

    rows = stratified_split(items, ratios, args.seed)
    summary = summarise(rows)

    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else (
        in_path.parent if in_path.is_file() else in_path)
    stem = in_path.stem if in_path.is_file() else in_path.name
    manifest_csv, manifest_json = write_outputs(rows, summary, ratios, args.seed, out_dir, stem)

    split_totals = {s: sum(1 for r in rows if r["split"] == s) for s in SPLIT_NAMES}
    print(f"Items: {len(rows)} | seed: {args.seed} | ratio: "
          + ":".join(f"{r:.2f}" for r in ratios))
    print(f"Splits: " + ", ".join(f"{s}={split_totals[s]}" for s in SPLIT_NAMES))
    print(f"Manifest: {manifest_csv} / {manifest_json}")
    for category in sorted(summary.keys()):
        counts = summary[category]
        print(f"  - {category}: " + ", ".join(f"{s}={counts[s]}" for s in SPLIT_NAMES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
