"""run_pipeline.py — one-shot dataset pipeline runner (for scheduled runs).

Orchestrates the full chain as a single job so a scheduler can invoke it:

    collect (source adapter) -> label -> [download images] -> [load to iitp_db]

Each stage reuses the standalone modules; this runner only wires them and
reports a summary. Configuration comes from CLI args / environment (.env), so
no source-specific or infra-specific values are hard-coded.

Usage:
    python run_pipeline.py --source API --ext-sys TOUR_BF_API \
        --out-dir out --limit 200 --download --to-db
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

from collectors import get_collector
import label_assist
import db_sink

logger = logging.getLogger("run_pipeline")


def _read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def run_pipeline(
    source: str,
    out_dir: Path,
    ext_sys: str,
    *,
    collector_options: Optional[dict] = None,
    rules_path: Optional[str] = None,
    download: bool = False,
    to_db: bool = False,
    collector_factory: Callable = get_collector,
    db_conn=None,
) -> Dict[str, object]:
    """Run collect -> label -> [download] -> [db load]. Returns a summary.

    ``collector_factory`` and ``db_conn`` are injectable for testing.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    collector_options = collector_options or {}

    # 1) collect
    collector = collector_factory(source, **collector_options)
    rows = collector.collect()
    collected = out_dir / "collected.csv"
    collector.to_csv(rows, collected)
    logger.info("collected %d rows -> %s", len(rows), collected)

    # 2) label (in-process)
    rules = label_assist.get_rules(rules_path)
    csv_rows = _read_csv(collected)
    labeled = [label_assist.label_row(r, rules) for r in csv_rows]
    labeled_path = out_dir / "collected_labeled.csv"
    label_assist.write_labeled(labeled, labeled_path)
    needs_review = sum(1 for r in labeled if r["needs_review"] == "Y")

    summary: Dict[str, object] = {
        "source": source, "ext_sys": ext_sys,
        "collected": len(rows), "needs_review": needs_review,
        "downloaded": None, "db_items": None, "db_images": None,
    }

    # 3) download images (optional) — delegate to the standalone downloader CLI
    if download:
        env = dict(os.environ, URL_CSV_PATH=str(collected))
        root = env.get("ROOT_DIR") or str(out_dir / "downloads")
        env["ROOT_DIR"] = root
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent / "downloader.py")],
            env=env, capture_output=True, text=True)
        summary["downloaded"] = (proc.returncode == 0)
        logger.info("download step rc=%s", proc.returncode)

    # 4) load to iitp_db (optional)
    if to_db or db_conn is not None:
        conn = db_conn or db_sink.connect_from_env()
        close = db_conn is None
        try:
            res = db_sink.DbSink(conn).load_rows(labeled, ext_sys)
            summary["db_items"] = res["items"]
            summary["db_images"] = res["images"]
        finally:
            if close:
                conn.close()

    logger.info("pipeline summary: %s", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run the collect->label->download->db pipeline once.")
    p.add_argument("--source", default=os.getenv("SOURCE", "API"))
    p.add_argument("--ext-sys", default=os.getenv("EXT_SYS", "TOUR_BF_API"))
    p.add_argument("--out-dir", default=os.getenv("OUT_DIR", "out"))
    p.add_argument("--rules", default=os.getenv("LABEL_RULES"))
    p.add_argument("--limit", type=int, default=(int(os.getenv("COLLECT_LIMIT")) if os.getenv("COLLECT_LIMIT") else None))
    p.add_argument("--area", default=os.getenv("TOUR_AREA"))
    p.add_argument("--content-type", dest="content_type", default=os.getenv("TOUR_CONTENT_TYPE"))
    p.add_argument("--with-images", dest="with_images", action="store_true")
    p.add_argument("--download", action="store_true")
    p.add_argument("--to-db", dest="to_db", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
        load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)
    except Exception:
        pass

    opts: Dict[str, object] = {}
    if args.limit is not None:
        opts["max_items"] = args.limit
    if args.area:
        opts["area_code"] = args.area
    if args.content_type:
        opts["content_type"] = args.content_type
    if args.with_images:
        opts["with_images"] = True

    summary = run_pipeline(
        args.source, Path(args.out_dir), args.ext_sys,
        collector_options=opts, rules_path=args.rules,
        download=args.download, to_db=args.to_db,
    )
    print("Pipeline done:", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
