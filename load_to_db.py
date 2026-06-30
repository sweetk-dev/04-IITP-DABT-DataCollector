"""load_to_db.py — load a collected/labeled CSV into iitp_db.

Reads DB connection from the environment (.env) and loads the rows into
``dis_unst_collect_item`` / ``dis_unst_collect_img`` via db_sink.DbSink.

Usage:
    python load_to_db.py out/collected_labeled.csv --ext-sys TOUR_BF_API
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import db_sink

VALID_EXT_SYS = ("TOUR_BF_API", "ABLEJOB", "WEB_CRAWL")


def read_rows(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Load a collected/labeled CSV into iitp_db.")
    p.add_argument("csv", help="collected or labeled CSV (No,Type,Title,Img-link[,inferred_category,...])")
    p.add_argument("--ext-sys", required=True, help="source code: " + ", ".join(VALID_EXT_SYS))
    args = p.parse_args(argv)

    path = Path(args.csv).expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"ERROR: file not found: {path}")

    rows = read_rows(path)
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
        load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)
    except Exception:
        pass

    conn = db_sink.connect_from_env()
    try:
        result = db_sink.DbSink(conn).load_rows(rows, args.ext_sys)
    finally:
        conn.close()
    print(f"Loaded {result['items']} items, {result['images']} images -> iitp_db (ext_sys={args.ext_sys})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
