"""collect_list.py — CLI entry point for the list-collection layer.

First stage of the pipeline:
    collect_list -> downloader.py -> label_assist -> dedup -> split_manifest

Selects a source adapter (priority: --source > SOURCE env > default), runs
``collect()``, and writes the standard ``No,Type,Title,Img-link`` CSV that
``downloader.py`` consumes unchanged.

Examples
--------
    python collect_list.py --source SAMPLE --out out/collected.csv
    python collect_list.py --source SAMPLE --input insample/sample_t2.csv \
        --out out/collected.csv
    python collect_list.py --list-sources
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from collectors import DEFAULT_SOURCE, available_sources, get_collector

logger = logging.getLogger("list_collector")


def _configure_logging(level_name: str) -> None:
    level = getattr(logging, (level_name or "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stdout,
    )


def resolve_source(cli_source) -> str:
    """Resolve the active source key: CLI > SOURCE env > default."""
    if cli_source:
        return cli_source
    env_source = (os.getenv("SOURCE", "") or "").strip()
    if env_source:
        return env_source
    return DEFAULT_SOURCE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect a standard No,Type,Title,Img-link CSV from a source adapter."
    )
    parser.add_argument("--source", help="source adapter key (overrides SOURCE env)")
    parser.add_argument("--input", help="input file for file-based adapters (e.g. SAMPLE)")
    parser.add_argument("--limit", type=int, help="maximum number of rows to collect")
    parser.add_argument("--out", default="out/collected.csv", help="output CSV path")
    parser.add_argument("--list-sources", action="store_true", help="print registered sources and exit")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.log_level)

    if args.list_sources:
        print("Available sources: " + ", ".join(available_sources()))
        return 0

    source = resolve_source(args.source)
    options = {}
    if args.input:
        options["input"] = args.input
    if args.limit is not None:
        options["limit"] = args.limit

    collector = get_collector(source, **options)
    logger.info("Collecting via source=%s", source)
    rows = collector.collect()

    out_path = Path(args.out)
    collector.to_csv(rows, out_path)

    msg = f"Collected {len(rows)} rows -> {out_path}"
    logger.info(msg)
    print(msg)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)
