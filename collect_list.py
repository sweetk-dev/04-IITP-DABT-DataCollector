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
    parser.add_argument("--config", help="site config JSON for the CRAWL adapter")
    parser.add_argument("--delay", type=float, help="per-host delay seconds for CRAWL (default 1.0)")
    parser.add_argument("--area", help="areaCode filter for API source")
    parser.add_argument("--content-type", dest="content_type", help="contentTypeId filter for API source")
    parser.add_argument("--num-rows", dest="num_rows", type=int, help="API page size (default 100)")
    parser.add_argument("--with-images", dest="with_images", action="store_true", help="API: also fetch detailImage per item")
    parser.add_argument("--limit", type=int, help="maximum number of rows to collect")
    parser.add_argument("--out", default="out/collected.csv", help="output CSV path")
    parser.add_argument("--list-sources", action="store_true", help="print registered sources and exit")
    parser.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.log_level)

    # Load .env (cwd + script dir) so secrets like TOUR_API_KEY are available
    # without exporting them manually. .env is gitignored.
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
        load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)
    except Exception:
        pass

    if args.list_sources:
        print("Available sources: " + ", ".join(available_sources()))
        return 0

    source = resolve_source(args.source)
    out_path = Path(args.out)
    options = {}
    if args.input:
        options["input"] = args.input
    if args.config or os.getenv("CRAWL_CONFIG"):
        options["config"] = args.config or os.getenv("CRAWL_CONFIG")
    if args.delay is not None:
        options["delay"] = args.delay
    elif os.getenv("CRAWL_DELAY"):
        options["delay"] = float(os.getenv("CRAWL_DELAY"))
    ua = os.getenv("CRAWL_USER_AGENT")
    if ua:
        options["user_agent"] = ua
    if os.getenv("CRAWL_RETRIES"):
        options["retries"] = int(os.getenv("CRAWL_RETRIES"))
    if source.strip().upper() == "API":
        if args.area:
            options["area_code"] = args.area
        if args.content_type:
            options["content_type"] = args.content_type
        if args.num_rows is not None:
            options["num_rows"] = args.num_rows
        if args.with_images:
            options["with_images"] = True
        if args.limit is not None:
            options["max_items"] = args.limit
    if source.strip().upper() == "CRAWL":
        options["error_out"] = str(out_path.with_name(out_path.stem + "_crawl_errors.csv"))
        if os.getenv("DISCOVERY_LIST"):
            options["discovery_list"] = os.getenv("DISCOVERY_LIST")
    if args.limit is not None:
        options["limit"] = args.limit

    collector = get_collector(source, **options)
    logger.info("Collecting via source=%s", source)
    rows = collector.collect()

    collector.to_csv(rows, out_path)

    msg = f"Collected {len(rows)} rows -> {out_path}"
    logger.info(msg)
    print(msg)
    errors = getattr(collector, "errors", None)
    if errors:
        print(f"Fetch failures: {len(errors)} -> {options.get('error_out')}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:
        logger.exception("Fatal error")
        sys.exit(1)
