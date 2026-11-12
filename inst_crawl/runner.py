"""기관 자료실 정기 수집 — 수집기 실행 → 새 파일 골라내기 → 수집 목록 작성.

장애인 복지관·가족지원센터·체육회·권익옹호기관·공공기관 자료실의 첨부 문서와
무장애 여행 이미지를 기관별 수집기(`sites/*.py`)로 받는다. 수집기는 기관마다
작업 폴더에서 돌며, 이미 받은 파일은 건너뛰므로 작업 폴더를 지우지 않으면
다음 실행 때는 새로 올라온 첨부만 받는다.

실행이 끝나면 작업 폴더 전체를 훑어
  1. 잡파일(수집 로그·아이콘·썸네일·대상 밖 확장자)을 거르고
  2. 내용 해시(SHA-256)가 이전 실행 또는 기준 해시 목록에 있으면 건너뛰고
  3. 처음 보는 파일만 `<out>/<기간>/<구분>/<분류>/<수집기>/` 로 복사한 뒤
  4. `<out>/<기간>/manifest.csv`(파일별 목록)와 `summary.json`(수집기별 건수)을 남긴다.
본 해시는 `<work>/_ledger.tsv` 에 쌓여 다음 실행의 중복 판정에 쓰인다.

    python -m inst_crawl.runner --work out/inst_work --out out/inst            # 전체 실행
    python -m inst_crawl.runner --work out/inst_work --out out/inst --only 한국장애인개발원
    python -m inst_crawl.runner --work out/inst_work --out out/inst --no-run   # 받아 둔 파일만 정리
    python -m inst_crawl.runner ... --seed-hashes base_sha256.txt              # 기준 해시(이전 제출분) 더하기
"""
from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

logger = logging.getLogger("inst_crawl")

HERE = Path(__file__).resolve().parent
SITES_JSON = HERE / "sites.json"
SITES_DIR = HERE / "sites"
LEDGER_NAME = "_ledger.tsv"

# 구분별로 남길 확장자. 기초(기관 자료실)는 문서만, 이동권(무장애 여행)은 사진만 남긴다.
KEEP_EXT = {
    "기초": {"pdf", "hwp", "hwpx", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
             "zip", "alz", "egg", "7z", "txt", "csv"},
    "이동권": {"jpg", "jpeg", "png", "gif", "webp", "bmp"},
}
# 수집기가 스스로 남기는 기록 파일 — 수집 대상이 아니다.
LOG_NAMES = {"download_log.csv", "run.log"}
MIN_BYTES = {"기초": 1024, "이동권": 10 * 1024}   # 이보다 작으면 빈 파일·아이콘·썸네일로 본다

MANIFEST_COLS = ["기간", "구분", "분류", "수집기", "파일", "크기", "sha256", "수집일시", "자동수집"]


def period_of(day: _dt.date) -> str:
    return f"{day.year}Q{(day.month - 1) // 3 + 1}"


def load_sites(path: Path = SITES_JSON) -> List[dict]:
    with open(path, encoding="utf-8") as f:
        sites = json.load(f)
    for s in sites:
        for k in ("name", "script", "구분", "분류"):
            if not s.get(k):
                raise ValueError(f"sites.json 항목에 {k} 가 없습니다: {s}")
        if s["구분"] not in KEEP_EXT:
            raise ValueError(f"알 수 없는 구분: {s['구분']}")
    return sites


def sha256_of(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_file(p: Path, gubun: str) -> Optional[str]:
    """남길 파일이면 None, 거르면 그 이유."""
    name = p.name
    if name in LOG_NAMES or name.startswith("run_") and name.endswith(".log"):
        return "log"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext == "py" or ext not in KEEP_EXT[gubun]:
        return "ext"
    try:
        size = p.stat().st_size
    except OSError:
        return "missing"
    if size < MIN_BYTES[gubun]:
        return "small"
    return None


class Ledger:
    """이미 본 내용 해시 목록 — 작업 폴더의 `_ledger.tsv`(sha256, 기간, 수집기, 상대경로)."""

    def __init__(self, path: Path):
        self.path = path
        self.seen: Set[str] = set()
        if path.exists():
            with open(path, encoding="utf-8") as f:
                for line in f:
                    h = line.split("\t", 1)[0].strip().lower()
                    if h:
                        self.seen.add(h)

    def add_seed(self, hashes: Iterable[str]) -> int:
        n = 0
        with open(self.path, "a", encoding="utf-8") as f:
            for h in hashes:
                h = h.strip().lower()
                if len(h) == 64 and h not in self.seen:
                    self.seen.add(h)
                    f.write(f"{h}\tseed\t\t\n")
                    n += 1
        return n

    def record(self, rows: List[dict]) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            for r in rows:
                f.write(f"{r['sha256']}\t{r['기간']}\t{r['수집기']}\t{r['파일']}\n")


def run_site(site: dict, work: Path, python: str, timeout: int, period: str) -> dict:
    wd = work / site["name"]
    wd.mkdir(parents=True, exist_ok=True)
    src = SITES_DIR / site["script"]
    dst = wd / site["script"]
    shutil.copy2(src, dst)  # 수집기 코드는 매번 레포 것으로 맞춘다
    log_path = wd / f"run_{period}.log"
    t0 = time.time()
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n=== {_dt.datetime.now():%Y-%m-%d %H:%M:%S} 시작 ===\n")
        log.flush()
        try:
            rc = subprocess.run([python, "-u", dst.name], cwd=wd, stdout=log, stderr=subprocess.STDOUT,
                                timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
        log.write(f"=== 끝 rc={rc} ===\n")
    return {"rc": rc, "seconds": round(time.time() - t0)}


def collect_new(sites: List[dict], work: Path, out: Path, period: str, ledger: Ledger,
                now: Optional[str] = None) -> Dict[str, dict]:
    """작업 폴더에서 처음 보는 파일만 기간 폴더로 복사하고 목록을 남긴다."""
    now = now or _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdir = out / period
    stats: Dict[str, dict] = {}
    new_rows: List[dict] = []
    for site in sites:
        wd = work / site["name"]
        st = {"seen": 0, "new": 0, "dup": 0, "skip_log": 0, "skip_ext": 0, "skip_small": 0, "bytes": 0}
        stats[site["name"]] = st
        if not wd.is_dir():
            continue
        for p in sorted(wd.rglob("*")):
            if not p.is_file() or p.name == site["script"]:
                continue
            why = classify_file(p, site["구분"])
            if why in ("log", "ext", "small"):
                st["skip_" + why] += 1
                continue
            if why:
                continue
            st["seen"] += 1
            h = sha256_of(p)
            if h in ledger.seen:
                st["dup"] += 1
                continue
            ledger.seen.add(h)
            rel = p.relative_to(wd).as_posix()
            dst = pdir / site["구분"] / site["분류"] / site["name"] / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
            size = p.stat().st_size
            st["new"] += 1
            st["bytes"] += size
            new_rows.append({"기간": period, "구분": site["구분"], "분류": site["분류"], "수집기": site["name"],
                             "파일": rel, "크기": size, "sha256": h, "수집일시": now, "자동수집": "Y"})
    if new_rows or not (pdir / "manifest.csv").exists():
        pdir.mkdir(parents=True, exist_ok=True)
        mpath = pdir / "manifest.csv"
        exists = mpath.exists()
        with open(mpath, "a", encoding="utf-8-sig" if not exists else "utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=MANIFEST_COLS)
            if not exists:
                w.writeheader()
            w.writerows(new_rows)
    ledger.record(new_rows)
    return stats


def write_summary(out: Path, period: str, sites: List[dict], runs: Dict[str, dict], stats: Dict[str, dict]) -> Path:
    pdir = out / period
    pdir.mkdir(parents=True, exist_ok=True)
    path = pdir / "summary.json"
    prev = {}
    if path.exists():
        try:
            prev = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            prev = {}
    runs_hist = prev.get("runs", [])
    runs_hist.append({
        "at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sites": {s["name"]: {**runs.get(s["name"], {}), **stats.get(s["name"], {})} for s in sites},
    })
    total_new = sum(st.get("new", 0) for st in stats.values())
    data = {"period": period, "runs": runs_hist,
            "new_total": prev.get("new_total", 0) + total_new}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="기관 자료실 정기 수집")
    ap.add_argument("--work", default=os.getenv("INST_WORK_DIR", "out/inst_work"))
    ap.add_argument("--out", default=os.getenv("INST_OUT_DIR", "out/inst"))
    ap.add_argument("--period", default=None, help="기본: 실행일의 분기 (예: 2026Q4)")
    ap.add_argument("--only", nargs="*", default=None, help="이 수집기만")
    ap.add_argument("--parallel", type=int, default=int(os.getenv("INST_PARALLEL", "4")))
    ap.add_argument("--timeout", type=int, default=int(os.getenv("INST_TIMEOUT", "14400")),
                    help="수집기 1개당 최대 실행 초")
    ap.add_argument("--python", default=os.getenv("INST_PYTHON", sys.executable))
    ap.add_argument("--no-run", action="store_true", help="수집기는 돌리지 않고 작업 폴더만 정리")
    ap.add_argument("--seed-hashes", default=None, help="이미 제출·보관한 파일의 SHA-256 목록(줄마다 1개)")
    ap.add_argument("--include-disabled", action="store_true")
    a = ap.parse_args(argv)
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")

    work, out = Path(a.work), Path(a.out)
    work.mkdir(parents=True, exist_ok=True)
    period = a.period or period_of(_dt.date.today())
    sites = [s for s in load_sites() if a.include_disabled or s.get("enabled", True)]
    if a.only:
        sites = [s for s in sites if s["name"] in set(a.only)]
    ledger = Ledger(work / LEDGER_NAME)
    if a.seed_hashes:
        with open(a.seed_hashes, encoding="utf-8-sig") as f:
            logger.info("기준 해시 %d건 추가", ledger.add_seed(f))

    runs: Dict[str, dict] = {}
    if not a.no_run:
        logger.info("%s 수집 시작 — 수집기 %d개, 동시 %d", period, len(sites), a.parallel)
        with ThreadPoolExecutor(max_workers=max(1, a.parallel)) as ex:
            futs = {s["name"]: ex.submit(run_site, s, work, a.python, a.timeout, period) for s in sites}
            for name, fut in futs.items():
                try:
                    runs[name] = fut.result()
                except Exception as e:  # 한 수집기 실패가 나머지를 막지 않는다
                    runs[name] = {"rc": f"error:{type(e).__name__}"}
                logger.info("  %s rc=%s %ss", name, runs[name].get("rc"), runs[name].get("seconds", "-"))

    stats = collect_new(sites, work, out, period, ledger)
    path = write_summary(out, period, sites, runs, stats)
    for s in sites:
        st = stats[s["name"]]
        logger.info("  %-28s 새 파일 %4d · 이미 있음 %4d · 거름 %d", s["name"], st["new"], st["dup"],
                    st["skip_log"] + st["skip_ext"] + st["skip_small"])
    logger.info("%s 새 파일 합계 %d → %s", period, sum(st["new"] for st in stats.values()), path)
    bad = [n for n, r in runs.items() if r.get("rc") not in (0,)]
    return 1 if bad and len(bad) == len(runs) else 0


if __name__ == "__main__":
    sys.exit(main())
