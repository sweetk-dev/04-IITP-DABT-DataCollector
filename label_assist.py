"""label_assist.py — labelling helper (domain category normalisation).

Normalises the free-text ``Type`` of collected/downloaded rows into a fixed
category taxonomy and flags rows whose inferred category disagrees with the
recorded ``Type`` for human review. Produces per-category distribution
statistics so the dataset can be checked for label consistency.

Standard-library only. Independent CLI utility — does not import or modify
``downloader.py``.

Taxonomy (two domains, ready for the phase-2 culture/tourism expansion):
  Employment domain : 일자리/채용, 교육, 행사, 직무/생산품
  Culture/Tourism   : 무장애 관광지, 편의시설, 이동시설/이동경로, 숙박/음식 접근성
  Fallback          : 기타/미분류 (rule miss -> needs_review)

Usage
-----
    python label_assist.py <input.csv> [--out-dir DIR]
Outputs (next to input, or under --out-dir):
    <stem>_labeled.csv         original rows + inferred_category, domain,
                               match_confidence, needs_review
    <stem>_label_stats.csv     category, domain, count, ratio
    <stem>_label_stats.json    same, structured
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Domain labels
DOMAIN_EMPLOYMENT = "고용"
DOMAIN_TOURISM = "문화관광"
DOMAIN_NONE = "기타"

UNCLASSIFIED = "기타/미분류"

# Ordered rules: (canonical_category, domain, [keywords]). Earlier entries are
# preferred only as a tie-break; the winner is the category with the most hits.
CATEGORY_RULES: List[Tuple[str, str, List[str]]] = [
    ("일자리/채용", DOMAIN_EMPLOYMENT,
     ["일자리", "채용", "구직", "취업", "고용", "모집", "공고", "인력", "구인"]),
    ("교육", DOMAIN_EMPLOYMENT,
     ["교육", "강의", "연수", "강좌", "과정", "양성", "교실", "워크숍", "훈련"]),
    ("행사", DOMAIN_EMPLOYMENT,
     ["행사", "캠페인", "공모", "세미나", "박람회", "대회", "축제", "기념", "페스티벌", "공연"]),
    ("직무/생산품", DOMAIN_EMPLOYMENT,
     ["생산품", "직무", "제품", "판매", "직업재활", "작업", "납품"]),
    ("무장애 관광지", DOMAIN_TOURISM,
     ["관광", "여행", "무장애", "열린관광", "관광지", "명소", "다누림", "투어"]),
    ("편의시설", DOMAIN_TOURISM,
     ["경사로", "엘리베이터", "점자", "화장실", "주차", "편의시설", "리프트", "안내판"]),
    ("이동시설/이동경로", DOMAIN_TOURISM,
     ["이동경로", "이동시설", "저상버스", "휠체어", "동선", "교통약자", "보행"]),
    ("숙박/음식 접근성", DOMAIN_TOURISM,
     ["숙박", "호텔", "객실", "음식", "식당", "카페", "맛집", "조식"]),
]

LABELED_FIELDS = ["No", "Type", "Title", "Img-link",
                  "inferred_category", "domain", "match_confidence", "needs_review"]


def classify(text: str) -> Tuple[str, str, float, int]:
    """Classify ``text`` into (category, domain, confidence, hit_count).

    Confidence is a 0.0-1.0 score derived from the number of distinct keyword
    hits for the winning category (1 hit -> 0.6, 2 -> 0.8, 3+ -> 1.0). No hit
    returns the unclassified fallback at confidence 0.0.
    """
    text = text or ""
    best_cat = UNCLASSIFIED
    best_domain = DOMAIN_NONE
    best_hits = 0
    for category, domain, keywords in CATEGORY_RULES:
        hits = sum(1 for kw in keywords if kw in text)
        if hits > best_hits:
            best_hits = hits
            best_cat = category
            best_domain = domain
    if best_hits == 0:
        return UNCLASSIFIED, DOMAIN_NONE, 0.0, 0
    confidence = {1: 0.6, 2: 0.8}.get(best_hits, 1.0)
    return best_cat, best_domain, confidence, best_hits


def label_row(row: Dict[str, str]) -> Dict[str, str]:
    title = row.get("Title", "") or ""
    type_val = row.get("Type", "") or ""
    # Primary inference uses Title + Type together.
    inferred, domain, confidence, _ = classify(f"{title} {type_val}")
    # Secondary classification of the recorded Type alone, to detect conflict.
    type_cat, _, _, type_hits = classify(type_val)

    needs_review = "N"
    if inferred == UNCLASSIFIED:
        needs_review = "Y"
    elif type_hits > 0 and type_cat != inferred:
        needs_review = "Y"

    out = dict(row)
    out["inferred_category"] = inferred
    out["domain"] = domain
    out["match_confidence"] = f"{confidence:.2f}"
    out["needs_review"] = needs_review
    return out


def read_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise SystemExit("ERROR: input CSV has no header")
        if "Title" not in reader.fieldnames:
            raise SystemExit(f"ERROR: input CSV must contain a Title column; got: {reader.fieldnames}")
        rows = []
        for src in reader:
            row = {
                "No": (src.get("No", "") or "").strip(),
                "Type": (src.get("Type", "") or "").strip(),
                "Title": re.sub(r"\s+", " ", (src.get("Title", "") or "")).strip(),
                "Img-link": (src.get("Img-link", "") or "").strip(),
            }
            rows.append(row)
        return rows


def write_labeled(rows: List[Dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LABELED_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in LABELED_FIELDS})


def build_stats(rows: List[Dict[str, str]]) -> List[Dict[str, object]]:
    total = len(rows) or 1
    counter = Counter((r["inferred_category"], r["domain"]) for r in rows)
    stats = []
    for (category, domain), count in counter.most_common():
        stats.append({
            "category": category,
            "domain": domain,
            "count": count,
            "ratio": round(count / total, 4),
        })
    return stats


def write_stats(stats: List[Dict[str, object]], csv_path: Path, json_path: Path,
                total: int, needs_review: int) -> None:
    with csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "domain", "count", "ratio"])
        for s in stats:
            writer.writerow([s["category"], s["domain"], s["count"], s["ratio"]])
    payload = {
        "total": total,
        "needs_review": needs_review,
        "categories": stats,
    }
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Normalise Type into a fixed category taxonomy and flag review rows.")
    p.add_argument("input", help="input CSV (No,Type,Title,Img-link)")
    p.add_argument("--out-dir", help="output directory (default: next to input)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    in_path = Path(args.input).expanduser().resolve()
    if not in_path.exists():
        raise SystemExit(f"ERROR: file not found: {in_path}")

    rows = read_rows(in_path)
    labeled = [label_row(r) for r in rows]
    needs_review = sum(1 for r in labeled if r["needs_review"] == "Y")

    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else in_path.parent
    stem = in_path.stem
    labeled_path = out_dir / f"{stem}_labeled.csv"
    stats_csv = out_dir / f"{stem}_label_stats.csv"
    stats_json = out_dir / f"{stem}_label_stats.json"

    write_labeled(labeled, labeled_path)
    stats = build_stats(labeled)
    write_stats(stats, stats_csv, stats_json, len(labeled), needs_review)

    print(f"Rows: {len(labeled)} | needs_review: {needs_review}")
    print(f"Labeled : {labeled_path}")
    print(f"Stats   : {stats_csv} / {stats_json}")
    for s in stats:
        print(f"  - {s['category']} [{s['domain']}]: {s['count']} ({s['ratio']:.1%})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
