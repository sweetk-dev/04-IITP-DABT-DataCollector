"""tour_api.py — public open-API list collector (``SOURCE = "API"``).

Collects a standard No,Type,Title,Img-link list from the Korea Tourism
Organization "barrier-free travel" open API (data.go.kr service 15101897,
TourAPI ``KorWithService``). This is the sanctioned, licensed channel for the
phase-2 accessible-tourism image dataset (no crawling / copyright ambiguity).

Auth: the service key is read from the ``TOUR_API_KEY`` environment variable
(or a ``service_key`` option). It is never hard-coded or committed.

Endpoint version is configurable (``TOUR_API_BASE`` / options) because the
gateway exposes both v1 (``KorWithService1``/``areaBasedList1``) and v2
(``KorWithService2``/``areaBasedList2``); switch without code changes.

Mapping to the standard row:
    No       <- contentid
    Type     <- contenttypeid label (관광지/문화시설/행사/숙박/음식점/...) — a hint
    Title    <- title
    Img-link <- firstimage (+ firstimage2, + detailImage originimgurl when enabled)

Standard library + ``requests`` only. Network is injectable for tests.
"""
from __future__ import annotations

import logging
import os
from typing import Callable, Dict, List, Optional
from urllib.parse import urlencode

from .base import BaseListCollector

logger = logging.getLogger("list_collector")

DEFAULT_BASE = "http://apis.data.go.kr/B551011/KorWithService2"
DEFAULT_LIST_OP = "areaBasedList2"
DEFAULT_IMAGE_OP = "detailImage2"
DEFAULT_TIMEOUT = (10, 30)
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF_SEC = 2.0  # data.go.kr gateway can return transient 401/5xx right after key activation

# TourAPI contenttypeid -> Korean label (used as the Type hint for label_assist)
CONTENT_TYPE_LABEL = {
    "12": "관광지",
    "14": "문화시설",
    "15": "행사",
    "25": "여행코스",
    "28": "레포츠",
    "32": "숙박",
    "38": "쇼핑",
    "39": "음식점",
}

JsonGetter = Callable[[str, Dict[str, str]], dict]


def _as_item_list(body: dict) -> List[dict]:
    """TourAPI returns items.item as a dict (1 result) or list (N). Normalise."""
    items = (((body or {}).get("items") or {}) or {}).get("item")
    if items is None:
        return []
    if isinstance(items, dict):
        return [items]
    return list(items)


def parse_area_items(payload: dict) -> List[Dict[str, str]]:
    """Map an areaBasedList JSON payload to standard rows (firstimage only)."""
    body = (((payload or {}).get("response") or {}).get("body") or {})
    rows: List[Dict[str, str]] = []
    for it in _as_item_list(body):
        content_id = str(it.get("contentid", "")).strip()
        title = str(it.get("title", "")).strip()
        if not content_id or not title:
            continue
        imgs = [str(it.get("firstimage", "")).strip(),
                str(it.get("firstimage2", "")).strip()]
        imgs = [u for u in imgs if u.startswith("http")]
        type_hint = CONTENT_TYPE_LABEL.get(str(it.get("contenttypeid", "")).strip(), "")
        rows.append({
            "No": content_id,
            "Type": type_hint,
            "Title": title,
            "Img-link": "\n".join(dict.fromkeys(imgs)),  # de-dup, keep order
            "_contentid": content_id,  # internal, dropped before to_csv
        })
    return rows


def parse_detail_images(payload: dict) -> List[str]:
    """Map a detailImage JSON payload to a list of original image URLs."""
    body = (((payload or {}).get("response") or {}).get("body") or {})
    urls: List[str] = []
    for it in _as_item_list(body):
        u = str(it.get("originimgurl", "")).strip()
        if u.startswith("http"):
            urls.append(u)
    return urls


def total_count(payload: dict) -> int:
    body = (((payload or {}).get("response") or {}).get("body") or {})
    try:
        return int(body.get("totalCount", 0))
    except (TypeError, ValueError):
        return 0


class ApiListCollector(BaseListCollector):
    """Korea Tourism barrier-free travel open-API collector.

    Options
    -------
    service_key: API key (else env ``TOUR_API_KEY``).
    base_url:    service base (else env ``TOUR_API_BASE`` else v2 default).
    list_op / image_op: operation names (version-specific).
    area_code:   optional areaCode filter.
    content_type: optional contentTypeId filter.
    num_rows:    page size (default 100).
    max_items:   stop after N rows.
    with_images: also call detailImage per item (default False — firstimage is
                 usually enough and avoids N extra calls).
    http_get_json: inject a ``(operation, params) -> dict`` callable (tests).
    """

    SOURCE = "API"

    def collect(self) -> List[Dict[str, str]]:
        self._key = self.options.get("service_key") or os.getenv("TOUR_API_KEY", "")
        getter = self.options.get("http_get_json")
        if getter is None and not self._key:
            raise SystemExit(
                "ERROR: API source needs TOUR_API_KEY (env) or service_key option."
            )
        self._base = (self.options.get("base_url")
                      or os.getenv("TOUR_API_BASE") or DEFAULT_BASE).rstrip("/")
        self._list_op = self.options.get("list_op", DEFAULT_LIST_OP)
        self._image_op = self.options.get("image_op", DEFAULT_IMAGE_OP)
        self._get_json: JsonGetter = getter or self._http_get_json
        self._session = self.options.get("session")

        num_rows = int(self.options.get("num_rows", 100))
        max_items = self.options.get("max_items")
        with_images = bool(self.options.get("with_images", False))

        base_params = {
            "MobileOS": "ETC", "MobileApp": "iitp-dabt",
            "_type": "json", "arrange": "A", "numOfRows": str(num_rows),
        }
        if self.options.get("area_code"):
            base_params["areaCode"] = str(self.options["area_code"])
        if self.options.get("content_type"):
            base_params["contentTypeId"] = str(self.options["content_type"])

        rows: List[Dict[str, str]] = []
        page = 1
        while True:
            params = dict(base_params, pageNo=str(page))
            payload = self._get_json(self._list_op, params)
            page_rows = parse_area_items(payload)
            if not page_rows:
                break
            rows.extend(page_rows)
            logger.info("API: page %d -> %d rows (total %d)", page, len(page_rows), len(rows))
            if max_items and len(rows) >= int(max_items):
                rows = rows[: int(max_items)]
                break
            if len(rows) >= total_count(payload):
                break
            page += 1

        if with_images:
            for row in rows:
                extra = parse_detail_images(
                    self._get_json(self._image_op,
                                   {"contentId": row["_contentid"], "imageYN": "Y",
                                    "MobileOS": "ETC", "MobileApp": "iitp-dabt", "_type": "json"}))
                if extra:
                    have = [u for u in row["Img-link"].split("\n") if u]
                    merged = list(dict.fromkeys(have + extra))
                    row["Img-link"] = "\n".join(merged)

        for row in rows:
            row.pop("_contentid", None)  # drop internal field before output
        logger.info("API: collected %d rows", len(rows))
        return rows

    # --- network ----------------------------------------------------------

    def _redact(self, text: str) -> str:
        """Remove the service key from any message before it is shown/raised."""
        return (text or "").replace(self._key, "***") if self._key else (text or "")

    def _http_get_json(self, operation: str, params: Dict[str, str]) -> dict:
        import time
        import requests
        sess = self._session or requests
        # serviceKey appended raw (data.go.kr hex keys need no URL-encoding).
        url = f"{self._base}/{operation}?serviceKey={self._key}&{urlencode(params)}"
        retries = int(self.options.get("retries", DEFAULT_RETRIES))
        backoff = float(self.options.get("backoff", DEFAULT_BACKOFF_SEC))
        attempts = max(1, retries + 1)
        last = ""
        for attempt in range(1, attempts + 1):
            try:
                resp = sess.get(url, timeout=DEFAULT_TIMEOUT)
                resp.raise_for_status()
                return resp.json()
            except ValueError:
                # 200 but non-JSON (XML error body) — surface a redacted snippet.
                snippet = self._redact((getattr(resp, "text", "") or "")[:200])
                raise SystemExit(f"ERROR: API did not return JSON (key/endpoint?). Body: {snippet}")
            except Exception as exc:  # transient gateway 401/429/5xx etc.
                last = self._redact(str(exc))
                logger.warning("API: %s attempt %d/%d failed (%s)", operation, attempt, attempts, last)
                if attempt < attempts:
                    time.sleep(backoff * attempt)
        raise SystemExit(f"ERROR: API request failed after {attempts} attempts: {last}")
