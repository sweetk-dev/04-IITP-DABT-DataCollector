"""migrate_dated_downloads.py — 날짜 폴더에 쌓인 예전 다운로드를 고정 경로로 옮기고 사본을 따로 모은다 (1회용).

예전 파이프라인은 실행할 때마다 ``ROOT_DIR/<YYYY-MM-DD>/`` 에 모든 사진을 다시 받았다.
이 스크립트는 그 결과를 image_store 의 고정 경로 체계로 바꾼다.

    1. 날짜 폴더의 파일 이름 ``{No}.{Type}-{Title}_ {YYYY_MM_DD_HH_MM}_{순번}{확장자}`` 에서
       원본번호(No)와 순번(= dis_unst_collect_img.img_order)을 읽는다.
    2. 같은 (원본번호, 순번)의 파일이 여러 날짜에 있으면 가장 나중에 받은 1개(원천의 최신 사진)를 고르고,
       DB 에 그 사진 행이 있으면 고정 경로 ``ROOT_DIR/<ext_sys>/<No>_<순번><확장자>`` 로 옮겨 경로를 기록한다.
    3. 나머지 사본, DB 행이 없는 파일은 지우지 않고 --quarantine 폴더로 옮긴다(날짜 폴더 구조 유지).
    4. 같은 (항목, 순번)에 URL 이 다른 행이 여러 개면(원천이 사진을 바꾼 경우) 가장 최근 행만 두고
       옛 행은 삭제 표시(del_yn='Y')한다 — 옛 URL 을 다시 받으러 가지 않게.
    5. 이어서 image_store.sync_images 를 돌려 해시를 채우고, 내용이 같은 사진은 중복으로 표시한다
       (그 사본도 --quarantine 으로 옮긴다). 고정 경로에 파일이 없는 행만 새로 받는다.

기본은 미리 보기(--apply 없음): 무엇을 옮길지 건수만 출력하고 파일·DB 를 건드리지 않는다.

    python scripts/migrate_dated_downloads.py --root downloads --ext-sys TOUR_BF_API --quarantine _dup_quarantine
    python scripts/migrate_dated_downloads.py --root downloads --ext-sys TOUR_BF_API --quarantine _dup_quarantine --apply
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import db_sink  # noqa: E402
import image_store  # noqa: E402

# 같은 (항목, 순번)에서 가장 최근 행(img_id 최대)이 아닌 행 — 원천이 바꾼 옛 사진 URL
SQL_SUPERSEDED = """
SELECT i.img_id FROM public.dis_unst_collect_img i
  JOIN public.dis_unst_collect_item it ON it.item_id = i.item_id
 WHERE it.ext_sys = %(ext_sys)s AND COALESCE(i.del_yn, 'N') = 'N'
   AND i.img_id < (SELECT max(j.img_id) FROM public.dis_unst_collect_img j
                    WHERE j.item_id = i.item_id AND j.img_order = i.img_order AND COALESCE(j.del_yn, 'N') = 'N')
"""
SQL_RETIRE_BY_ID = """
UPDATE public.dis_unst_collect_img SET del_yn = 'Y', deleted_at = CURRENT_TIMESTAMP, deleted_by = 'SYS-BACH'
 WHERE img_id = ANY(%(ids)s)
"""

DATE_DIR = re.compile(r"^\d{4}-\d{2}-\d{2}$")
LEGACY = re.compile(r"^(?P<no>[^.]+)\.(?P<rest>.*)_ (?P<ts>\d{4}_\d{2}_\d{2}_\d{2}_\d{2})(?:_(?P<idx>\d+))?$")


def parse_legacy(name: str):
    """예전 파일 이름에서 (원본번호, 순번, 받은 시각 문자열)을 읽는다. 형식이 다르면 None."""
    stem, _ext = os.path.splitext(name)
    m = LEGACY.match(stem)
    if not m:
        return None
    return m.group("no"), int(m.group("idx") or 1), m.group("ts")


def plan(root: Path):
    """날짜 폴더를 훑어 (원본번호, 순번) → [(정렬키, 경로)] 를 만든다. 형식이 다른 파일은 따로 돌려준다."""
    groups, odd = {}, []
    for d in sorted(p for p in root.iterdir() if p.is_dir() and DATE_DIR.match(p.name)):
        for f in sorted(d.iterdir()):
            if not f.is_file() or f.suffix == ".part":
                continue
            key = parse_legacy(f.name)
            if key is None:
                odd.append(f)
                continue
            no, idx, ts = key
            groups.setdefault((no, idx), []).append(((d.name, ts, f.name), f))
    return groups, odd


def move(src: Path, dst: Path, apply: bool) -> None:
    if apply:
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.replace(src, dst)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", required=True, help="예전 다운로드 루트(날짜 폴더가 있는 곳)")
    ap.add_argument("--ext-sys", default="TOUR_BF_API")
    ap.add_argument("--quarantine", required=True, help="사본·미대응 파일을 옮겨 둘 폴더(지우지 않는다)")
    ap.add_argument("--apply", action="store_true", help="실제로 옮기고 DB 를 갱신한다")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    from dotenv import load_dotenv  # 실행할 때만 필요(테스트는 이름 해석만 본다)
    load_dotenv(ROOT / ".env")

    root, quarantine = Path(args.root).resolve(), Path(args.quarantine).resolve()
    groups, odd = plan(root)
    conn = db_sink.connect_from_env()
    cur = conn.cursor()
    cur.execute(SQL_SUPERSEDED, {"ext_sys": args.ext_sys})
    superseded = [r[0] for r in cur.fetchall()]
    cur.execute(image_store.SQL_SELECT_IMAGES, {"ext_sys": args.ext_sys})
    rows = {(str(r[7]), int(r[2])): r for r in cur.fetchall()}  # (src_no, img_order) -> row
    cur.close()

    sink = db_sink.DbSink(conn)
    kept = extra = unmatched = 0
    for (no, idx), files in sorted(groups.items()):
        files.sort()
        first = files[-1][1]   # 가장 최근에 받은 것 — 원천에서 사진이 바뀐 경우 최신본을 남긴다
        row = rows.get((no, idx))
        if row is None:
            for _k, f in files:
                move(f, quarantine / "unmatched" / f.parent.name / f.name, args.apply)
                unmatched += 1
            continue
        img_id, item_id, _order, url, *_ = row
        dst = image_store.stable_path(root, args.ext_sys, no, idx, first.suffix.lower())
        move(first, dst, args.apply)
        if args.apply:
            sink.update_download(item_id, url, str(dst), dst.suffix, True, None)
        kept += 1
        for _k, f in files[:-1]:
            move(f, quarantine / f.parent.name / f.name, args.apply)
            extra += 1
    for f in odd:
        move(f, quarantine / "unparsed" / f.parent.name / f.name, args.apply)
    print(f"keep(고정 경로로 이동) {kept} · 사본(보관 폴더로) {extra} · DB 행 없음(보관 폴더로) {unmatched} · "
          f"이름 형식 다름(보관 폴더로) {len(odd)} · DB 사진 (항목,순번) {len(rows)} · 옛 URL 행(삭제 표시) {len(superseded)}")
    if not args.apply:
        print("미리 보기 — 아무것도 옮기지 않았다. --apply 로 실행한다.")
        conn.close()
        return 0
    if superseded:
        cur = conn.cursor()
        cur.execute(SQL_RETIRE_BY_ID, {"ids": superseded})
        cur.close()
    conn.commit()
    # 빈 날짜 폴더 정리(파일이 남아 있으면 그대로 둔다)
    for d in root.iterdir():
        if d.is_dir() and DATE_DIR.match(d.name) and not any(d.iterdir()):
            d.rmdir()
    import requests
    stats = image_store.sync_images(conn, sink, args.ext_sys, root, requests.Session(), dup_dir=quarantine / "same_content")
    print("sync:", stats)
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
