"""image_store.py — DB 기준 이미지 저장소 (한 번만 받기 · 경로/해시 기록 · 중복 표시).

배경
    예전 파이프라인은 실행할 때마다 downloader.py 를 불러 ``ROOT_DIR/<오늘 날짜>/`` 폴더를 새로 만들고
    목록의 모든 사진을 처음부터 다시 받았다. 파일 이름에 받은 시각이 붙어 이름도 겹치지 않으므로
    같은 사진의 사본이 실행 횟수만큼 쌓였고(5회 실행 뒤 3,920개 중 고유 927개), DB 의
    dis_unst_collect_img 에는 파일 경로·받음 여부·해시가 한 번도 기록되지 않았다.

이 모듈이 하는 일 (파이프라인이 DB 적재 다음 단계로 부른다)
    1. dis_unst_collect_img 에서 대상 수집원(ext_sys)의 사진 행을 읽는다.
    2. 이미 받은 사진(download_yn='Y' 이고 local_path 파일이 실제로 있음)은 건너뛴다.
    3. 새 사진만 고정 경로 ``ROOT_DIR/<ext_sys>/<src_no>_<img_order><확장자>`` 에 받는다.
       같은 사진은 언제 받아도 같은 경로라 다시 받아도 사본이 생기지 않는다.
       받는 도중 끊기면 .part 임시 파일만 지워지고 최종 파일은 생기지 않는다(원자적 저장).
    4. 받은 결과(경로·확장자·성공 여부·오류)를 update_download 로 기록한다.
    5. 해시(MD5·SHA-256)가 비어 있거나 파일이 새로 받아진 행은 해시를 계산해 update_dedup 으로 기록한다.
       내용이 같은 사진이 이미 있으면(SHA-256 일치) 뒤의 행을 dup_yn='Y', dup_of_img_id=앞 행으로 표시한다.
       이때 뒤 행의 파일은 지우고 local_path 를 앞 행 파일로 가리켜 같은 내용이 두 번 저장되지 않게 한다.

DB 연결은 DB-API 2.0(psycopg2) — 테스트는 가짜 연결로 한다. 네트워크 호출은 session 을 주입받는다.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("image_store")

# 확장자 추정용 (downloader.py 와 같은 규칙)
CONTENT_TYPE_EXT = {
    "image/jpeg": ".jpg", "image/jpg": ".jpg", "image/png": ".png", "image/gif": ".gif",
    "image/webp": ".webp", "image/bmp": ".bmp", "image/tiff": ".tif",
}
SAFE = re.compile(r"[^0-9A-Za-z._-]+")

SQL_SELECT_IMAGES = """
SELECT i.img_id, i.item_id, i.img_order, i.img_url, i.local_path, i.download_yn,
       i.sha256_hash, it.src_no
  FROM public.dis_unst_collect_img i
  JOIN public.dis_unst_collect_item it ON it.item_id = i.item_id
 WHERE it.ext_sys = %(ext_sys)s AND COALESCE(i.del_yn, 'N') = 'N' AND COALESCE(it.del_yn, 'N') = 'N'
 ORDER BY i.img_id
"""


def stable_path(root: Path, ext_sys: str, src_no: str, img_order: int, ext: str) -> Path:
    """사진 한 장의 고정 저장 경로. 이름에 쓸 수 없는 글자는 '_' 로 바꾼다."""
    sub = SAFE.sub("_", ext_sys or "NA")
    stem = f"{SAFE.sub('_', str(src_no) or 'NA')}_{int(img_order)}"
    return root / sub / f"{stem}{ext or '.jpg'}"


def guess_ext(url: str, content_type: str = "") -> str:
    """URL 경로의 확장자를 우선 쓰고, 없으면 Content-Type 으로, 그것도 없으면 .jpg."""
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    if ext in (".do", ""):
        ext = CONTENT_TYPE_EXT.get((content_type or "").split(";")[0].strip().lower(), "")
    if ext == ".jpeg":
        ext = ".jpg"
    return ext or ".jpg"


def file_hashes(path: Path) -> Tuple[str, str]:
    """(md5, sha256) — 1MiB 씩 읽는다."""
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            md5.update(chunk)
            sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()


def fetch_to(session, url: str, dest: Path, timeout=(10, 60)) -> Tuple[bool, Optional[str], str]:
    """url 을 dest 로 받는다. 반환 (성공, 오류, 확장자). dest 의 확장자는 응답을 보고 다시 정한다."""
    try:
        resp = session.get(url, stream=True, timeout=timeout)
        resp.raise_for_status()
        ext = guess_ext(url, resp.headers.get("Content-Type", ""))
        dest = dest.with_suffix(ext)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        try:
            with open(tmp, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            expected = resp.headers.get("Content-Length", "")
            if expected.isdigit() and tmp.stat().st_size != int(expected):
                raise IOError(f"incomplete download: {tmp.stat().st_size}/{expected} bytes")
            os.replace(tmp, dest)
        except Exception:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise
        return True, None, ext
    except Exception as e:  # noqa: BLE001 — 사진 한 장 실패가 전체를 멈추지 않게 기록만 한다
        return False, str(e)[:500], ""


def _retire(path: Path, root: Path, dup_dir: Optional[Path]) -> None:
    """중복 사본 파일을 치운다. dup_dir 가 있으면 root 기준 상대 경로를 유지해 옮기고, 없으면 지운다."""
    try:
        if dup_dir is None:
            path.unlink()
            return
        try:
            rel = path.relative_to(root)
        except ValueError:
            rel = Path(path.name)
        target = Path(dup_dir) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(path, target)
    except OSError as e:
        logger.warning("중복 사본 정리 실패 %s: %s", path, e)


def sync_images(conn, sink, ext_sys: str, root: Path, session,
                fetch: Optional[Callable] = None, dup_dir: Optional[Path] = None) -> Dict[str, int]:
    """대상 수집원의 사진을 DB 기준으로 맞춘다. 반환: 건수 요약.

    conn  : DB-API 연결(읽기용 커서). sink : db_sink.DbSink (update_download·update_dedup 사용).
    fetch : 테스트용 주입(session, url, dest) -> (ok, err, ext). 기본은 fetch_to.
    dup_dir : 주면 내용이 겹치는 사본 파일을 지우지 않고 이 폴더로 옮긴다(기존 파일 정리 때 쓴다).
    """
    fetch = fetch or fetch_to
    root = Path(root).resolve()   # DB 에는 절대 경로를 남긴다(실행 위치가 달라도 찾을 수 있게)
    cur = conn.cursor()
    cur.execute(SQL_SELECT_IMAGES, {"ext_sys": ext_sys})
    rows = cur.fetchall()
    cur.close()

    stats = {"images": len(rows), "skipped": 0, "downloaded": 0, "failed": 0, "hashed": 0, "dups": 0}
    first_by_hash: Dict[str, Tuple[int, str]] = {}   # sha256 -> (img_id, local_path)
    for img_id, item_id, img_order, url, local_path, download_yn, sha, src_no in rows:
        path = Path(local_path) if local_path else None
        have = download_yn == "Y" and path is not None and path.exists()
        fresh = False
        if have:
            stats["skipped"] += 1
        else:
            dest = stable_path(root, ext_sys, src_no, img_order, guess_ext(url))
            ok, err, ext = fetch(session, url, dest)
            if ok:
                path = dest.with_suffix(ext)
                stats["downloaded"] += 1
                fresh = True
            else:
                stats["failed"] += 1
                path = None
            sink.update_download(item_id, url, str(path) if path else None,
                                 (ext or None) if ok else None, ok, err)
        if path is None:
            continue
        if fresh or not sha:
            md5, sha = file_hashes(path)
            stats["hashed"] += 1
            prev = first_by_hash.get(sha)
            if prev and prev[1] != str(path):
                # 같은 내용이 이미 있음 — 뒤 행은 중복 표시, 사본 파일은 지우고 앞 파일을 가리킨다
                _retire(path, root, dup_dir)
                sink.update_download(item_id, url, prev[1], path.suffix, True, None)
                sink.update_dedup(img_id, md5, sha, True, prev[0])
                stats["dups"] += 1
                continue
            sink.update_dedup(img_id, md5, sha, False, None)
        first_by_hash.setdefault(sha, (img_id, str(path)))
    conn.commit()
    logger.info("image sync %s: %s", ext_sys, stats)
    return stats
