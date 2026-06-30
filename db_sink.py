"""db_sink.py — load the collected dataset into iitp_db.

Pushes collected/labeled rows into the unstructured-image tables defined in
01-IITP-DABT-Database (``dis_unst_collect_item`` / ``dis_unst_collect_img``).
Each pipeline stage updates its own columns:

    collect/label -> dis_unst_collect_item (+ img rows, download_yn='N')
    downloader    -> dis_unst_collect_img.local_path / file_ext / download_yn
    dedup         -> dis_unst_collect_img.md5_hash / sha256_hash / dup_yn
    split         -> dis_unst_collect_img.dataset_split / split_seed

Design notes
  - Works against any DB-API 2.0 connection (psycopg2 in production; a fake
    connection in tests) so the SQL/logic is verifiable without a live DB.
  - psycopg2 is imported lazily inside ``connect_from_env`` only, so this
    module imports and unit-tests without psycopg2 installed.
  - Idempotent: upserts use the table UNIQUE constraints (ON CONFLICT).
  - Connection settings come from the environment (.env), never hard-coded.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, Iterable, List, Optional

logger = logging.getLogger("db_sink")

DEFAULT_CREATED_BY = "SYS-BACH"   # "sys_work_type" comm code

SQL_UPSERT_ITEM = """
INSERT INTO public.dis_unst_collect_item
    (ext_sys, src_no, src_type, title, src_url, inferred_category, domain,
     match_confidence, needs_review, collected_at, created_by)
VALUES
    (%(ext_sys)s, %(src_no)s, %(src_type)s, %(title)s, %(src_url)s,
     %(inferred_category)s, %(domain)s, %(match_confidence)s, %(needs_review)s,
     %(collected_at)s, %(created_by)s)
ON CONFLICT (ext_sys, src_no) DO UPDATE SET
    src_type          = EXCLUDED.src_type,
    title             = EXCLUDED.title,
    inferred_category = EXCLUDED.inferred_category,
    domain            = EXCLUDED.domain,
    match_confidence  = EXCLUDED.match_confidence,
    needs_review      = EXCLUDED.needs_review,
    updated_at        = CURRENT_TIMESTAMP,
    updated_by        = EXCLUDED.created_by
RETURNING item_id;
"""

SQL_UPSERT_IMG = """
INSERT INTO public.dis_unst_collect_img
    (item_id, img_order, img_url, created_by)
VALUES (%(item_id)s, %(img_order)s, %(img_url)s, %(created_by)s)
ON CONFLICT (item_id, img_url) DO NOTHING
RETURNING img_id;
"""

SQL_UPDATE_DOWNLOAD = """
UPDATE public.dis_unst_collect_img
   SET local_path = %(local_path)s, file_ext = %(file_ext)s,
       download_yn = %(download_yn)s, download_err = %(download_err)s,
       updated_at = CURRENT_TIMESTAMP, updated_by = %(updated_by)s
 WHERE item_id = %(item_id)s AND img_url = %(img_url)s;
"""

SQL_UPDATE_DEDUP = """
UPDATE public.dis_unst_collect_img
   SET md5_hash = %(md5_hash)s, sha256_hash = %(sha256_hash)s,
       dup_yn = %(dup_yn)s, dup_of_img_id = %(dup_of_img_id)s,
       updated_at = CURRENT_TIMESTAMP, updated_by = %(updated_by)s
 WHERE img_id = %(img_id)s;
"""


def _none_if_blank(v):
    v = (v or "").strip() if isinstance(v, str) else v
    return v if v not in ("", None) else None


def item_params(row: Dict[str, str], ext_sys: str,
                created_by: str = DEFAULT_CREATED_BY,
                collected_at=None) -> Dict[str, object]:
    """Map a labeled CSV row to dis_unst_collect_item parameters."""
    conf = _none_if_blank(row.get("match_confidence"))
    return {
        "ext_sys": ext_sys,
        "src_no": (row.get("No") or "").strip() or "NA",
        "src_type": _none_if_blank(row.get("Type")),
        "title": (row.get("Title") or "").strip(),
        "src_url": _none_if_blank(row.get("src_url") or row.get("Src-url")),
        "inferred_category": _none_if_blank(row.get("inferred_category")),
        "domain": _none_if_blank(row.get("domain")),
        "match_confidence": float(conf) if conf is not None else None,
        "needs_review": (row.get("needs_review") or "N").strip()[:1] or "N",
        "collected_at": collected_at,
        "created_by": created_by,
    }


def split_image_urls(img_link: str) -> List[str]:
    """Split a Img-link cell (newline-joined) into ordered unique URLs."""
    seen, out = set(), []
    for u in (img_link or "").replace("\r", "\n").split("\n"):
        u = u.strip()
        if u and u.lower().startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


class DbSink:
    """Loader bound to an open DB-API 2.0 connection."""

    def __init__(self, conn, created_by: str = DEFAULT_CREATED_BY):
        self.conn = conn
        self.created_by = created_by

    def upsert_item(self, row: Dict[str, str], ext_sys: str, collected_at=None) -> int:
        params = item_params(row, ext_sys, self.created_by, collected_at)
        cur = self.conn.cursor()
        cur.execute(SQL_UPSERT_ITEM, params)
        item_id = cur.fetchone()[0]
        cur.close()
        return item_id

    def upsert_images(self, item_id: int, urls: Iterable[str]) -> int:
        cur = self.conn.cursor()
        n = 0
        for order, url in enumerate(urls, start=1):
            cur.execute(SQL_UPSERT_IMG, {
                "item_id": item_id, "img_order": order,
                "img_url": url, "created_by": self.created_by,
            })
            n += 1
        cur.close()
        return n

    def update_download(self, item_id: int, img_url: str, local_path: str,
                        file_ext: str, ok: bool, err: Optional[str] = None) -> None:
        cur = self.conn.cursor()
        cur.execute(SQL_UPDATE_DOWNLOAD, {
            "item_id": item_id, "img_url": img_url, "local_path": local_path,
            "file_ext": file_ext, "download_yn": "Y" if ok else "N",
            "download_err": err, "updated_by": self.created_by,
        })
        cur.close()

    def update_dedup(self, img_id: int, md5_hash: str, sha256_hash: str,
                     is_dup: bool, dup_of_img_id: Optional[int] = None) -> None:
        cur = self.conn.cursor()
        cur.execute(SQL_UPDATE_DEDUP, {
            "img_id": img_id, "md5_hash": md5_hash, "sha256_hash": sha256_hash,
            "dup_yn": "Y" if is_dup else "N", "dup_of_img_id": dup_of_img_id,
            "updated_by": self.created_by,
        })
        cur.close()

    def load_rows(self, rows: List[Dict[str, str]], ext_sys: str, collected_at=None) -> Dict[str, int]:
        """Load labeled rows: upsert each item then its images. Commits once."""
        items = imgs = 0
        for row in rows:
            item_id = self.upsert_item(row, ext_sys, collected_at)
            items += 1
            imgs += self.upsert_images(item_id, split_image_urls(row.get("Img-link", "")))
        self.conn.commit()
        logger.info("DB load: %d items, %d images (ext_sys=%s)", items, imgs, ext_sys)
        return {"items": items, "images": imgs}


def connect_from_env():
    """Open a psycopg2 connection from environment variables (.env).

    Required: DB_HOST, DB_NAME, DB_USER, DB_PASSWORD. Optional: DB_PORT(5432).
    psycopg2 is imported here so the rest of the module needs no driver.
    """
    try:
        import psycopg2  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("ERROR: psycopg2 is required for DB load (pip install psycopg2-binary)") from exc
    import psycopg2
    missing = [k for k in ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD") if not os.getenv(k)]
    if missing:
        raise SystemExit(f"ERROR: missing DB env vars: {', '.join(missing)}")
    return psycopg2.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )
