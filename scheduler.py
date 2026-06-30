"""scheduler.py — periodic pipeline scheduler (server automation).

Runs ``run_pipeline`` on a cron schedule using APScheduler, mirroring the
scheduled-update pattern used by the policy service. Intended to run as a
long-lived process (e.g. inside the deployment container). All settings come
from the environment so nothing source/infra-specific is baked in here:

    SCHED_CRON     cron expression fields, default "0 3 * * *" (daily 03:00)
    SOURCE         collector source (default API)
    EXT_SYS        source code for DB load (default TOUR_BF_API)
    OUT_DIR        working output dir
    COLLECT_LIMIT  max items per run
    RUN_DOWNLOAD   "1" to download images
    RUN_TO_DB      "1" to load into iitp_db

Run:  python scheduler.py        (blocks, runs on schedule)
      python scheduler.py --now  (run once immediately, then exit)
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("scheduler")


def _job() -> None:
    from run_pipeline import run_pipeline
    opts = {}
    if os.getenv("COLLECT_LIMIT"):
        opts["max_items"] = int(os.getenv("COLLECT_LIMIT"))
    if os.getenv("TOUR_AREA"):
        opts["area_code"] = os.getenv("TOUR_AREA")
    if os.getenv("TOUR_CONTENT_TYPE"):
        opts["content_type"] = os.getenv("TOUR_CONTENT_TYPE")
    run_pipeline(
        os.getenv("SOURCE", "API"),
        Path(os.getenv("OUT_DIR", "out")),
        os.getenv("EXT_SYS", "TOUR_BF_API"),
        collector_options=opts,
        rules_path=os.getenv("LABEL_RULES"),
        download=os.getenv("RUN_DOWNLOAD") == "1",
        to_db=os.getenv("RUN_TO_DB") == "1",
    )


def _parse_cron(expr: str) -> dict:
    fields = (expr or "0 3 * * *").split()
    if len(fields) != 5:
        raise SystemExit(f"ERROR: SCHED_CRON must have 5 fields, got: {expr!r}")
    keys = ("minute", "hour", "day", "month", "day_of_week")
    return dict(zip(keys, fields))


def main(argv=None) -> int:
    args = argparse.ArgumentParser(description="Periodic dataset pipeline scheduler.")
    args.add_argument("--now", action="store_true", help="run once immediately and exit")
    ns = args.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", stream=sys.stdout)
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
        load_dotenv(dotenv_path=Path(__file__).resolve().parent / ".env", override=False)
    except Exception:
        pass

    if ns.now:
        _job()
        return 0

    try:
        from apscheduler.schedulers.blocking import BlockingScheduler
    except ImportError:
        raise SystemExit("ERROR: APScheduler required (pip install apscheduler) — or use --now")

    cron = _parse_cron(os.getenv("SCHED_CRON", "0 3 * * *"))
    sched = BlockingScheduler(timezone=os.getenv("TZ", "Asia/Seoul"))
    sched.add_job(_job, "cron", **cron, id="dataset_pipeline")
    logger.info("scheduler started (cron=%s)", cron)
    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
