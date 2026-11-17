# -*- coding: utf-8 -*-
"""
VisitKorea 열린관광(무장애) 이미지 다운로더 (페이지 2~30 수집)
- 리스트: https://access.visitkorea.or.kr/ms/ajax/list.do (POST, 경기도 areaCode=41, 최신순)
  2026-11 지역코드가 바뀌어 예전 31(경기도)이 울산을 가리킨다 — 화면 목록도 같은 ajax 로 그린다
- 상세: swiper background-image URL 추출, a 텍스트(예: "서해수호관 1")로 저장
"""
import os, re, csv, time, html, unicodedata
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm


# ====== 설정 ======
PAGE_START = 1
PAGE_END = int(os.getenv("INST_MAX_PAGES", "0")) or None   # 0·미지정 = 목록 끝까지(시험 실행 때 작게 준다)
AREA_CODE = "41"                                             # 경기도 (2026-11 개편 뒤 코드)
LIST_PAGE = "https://access.visitkorea.or.kr/ms/list.do"
LIST_AJAX = "https://access.visitkorea.or.kr/ms/ajax/list.do"
BASE = "https://access.visitkorea.or.kr"
LIST_SELECTOR = "ul#listResult li a"  # 상세 링크
SAVE_DIR = Path("vk_access_images")
CSV_PATH = SAVE_DIR / "download_log.csv"

SEL_WAIT = 20
SCROLL_PAUSE = 0.5
MAX_SCROLL_TRIES = 30

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

def sanitize_filename(text: str, max_len: int = 140) -> str:
    if not text:
        text = "image"
    text = unicodedata.normalize("NFKC", text)
    text = html.unescape(text).strip()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r'[\\/:*?"<>|]', "_", text)
    return (text or "image")[:max_len]

def ensure_ext_from_url(url: str, default=".jpg") -> str:
    _, ext = os.path.splitext(urlparse(url).path)
    return ext if ext.lower() in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"] else default

def parse_bg_url(style_value: str):
    if not style_value:
        return None
    m = re.search(r"background-image\s*:\s*url\((['\"]?)(.+?)\1\)", style_value, re.IGNORECASE)
    return html.unescape(m.group(2)) if m else None

def download(url: str, save_dir: Path, filename_base: str, referer: str | None = None) -> str | None:
    ext = ensure_ext_from_url(url)
    base = sanitize_filename(filename_base)
    save_dir.mkdir(parents=True, exist_ok=True)

    out = save_dir / f"{base}{ext}"
    n = 2
    while out.exists():
        out = save_dir / f"{base} ({n}){ext}"
        n += 1

    headers = dict(HEADERS)
    if referer:
        headers["Referer"] = referer

    try:
        with requests.get(url, headers=headers, stream=True, timeout=30) as r:
            r.raise_for_status()
            with open(out, "wb") as f:
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)
        return str(out)
    except Exception as e:
        print(f"  ! 다운로드 실패: {e} :: {url}")
        return None

# ---------- 리스트: ajax 로 쪽마다 ----------
def collect_detail_links_multi_pages(page_start: int, page_end) -> list[str]:
    """목록 화면이 부르는 ajax(POST ajax/list.do)를 직접 불러 상세 주소(detail.do?cotId=)를 모은다.

    응답 JSON: list[{cotId, title, ...}], totalCnt, rowCnt(쪽당 건수). page_end 가 None 이면 마지막 쪽까지.
    """
    s = requests.Session()
    headers = dict(HEADERS); headers.update({"Referer": LIST_PAGE, "X-Requested-With": "XMLHttpRequest"})
    s.get(LIST_PAGE, headers=headers, timeout=30)
    urls, seen, page, last = [], set(), page_start, None
    while True:
        r = s.post(LIST_AJAX, data={"bigCategory": "", "smallCategory": "", "areaCode": AREA_CODE, "sigugunCode": "",
                                     "orderType": "modifiedDate", "page": page}, headers=headers, timeout=30)
        r.raise_for_status()
        j = r.json()
        if last is None:
            total, per = int(j.get("totalCnt") or 0), int(j.get("rowCnt") or 9)
            last = max(1, -(-total // per))
            if page_end:
                last = min(last, page_end)
            print(f" - 경기도 {total}건, {last}쪽까지")
        items = j.get("list") or []
        for it in items:
            u = f"{BASE}/ms/detail.do?cotId={it.get('cotId')}"
            if it.get("cotId") and u not in seen:
                seen.add(u); urls.append(u)
        if not items or page >= last:
            break
        page += 1
        time.sleep(0.2)
    return urls


# ---------- 상세 파싱 ----------
def parse_detail_images(detail_url: str) -> list[tuple[str, str]]:
    headers = dict(HEADERS)
    headers["Referer"] = detail_url
    r = requests.get(detail_url, headers=headers, timeout=30)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    pairs = []
    for a in soup.select("div.swiper-wrapper div.swiper-slide a[style*='background-image']"):
        style = a.get("style", "")
        img = parse_bg_url(style)
        if not img:
            continue
        if img.startswith("//"):
            img = "https:" + img
        elif img.startswith("/"):
            img = urljoin(BASE, img)
        title = a.get_text(strip=True) or "image"
        pairs.append((img, title))

    # 중복 제거
    uniq, seen = [], set()
    for u, t in pairs:
        key = (u, t)
        if key not in seen:
            seen.add(key)
            uniq.append((u, t))
    return uniq

# ---------- 메인 ----------
def main():
    SAVE_DIR.mkdir(parents=True, exist_ok=True)
    is_new_csv = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        if is_new_csv:
            writer.writerow(["detail_url", "image_url", "saved_filename", "title_text"])

        # 지난 실행에서 받은 사진 주소 — 분기마다 다시 돌리므로 새 사진만 받는다
        done_urls = set()
        if not is_new_csv:
            with open(CSV_PATH, newline="", encoding="utf-8-sig") as f:
                done_urls = {row[1] for row in csv.reader(f) if len(row) > 1}
        print(f"[1/3] 페이지 {PAGE_START}~{PAGE_END or '끝'} 리스트 수집…")
        detail_urls = collect_detail_links_multi_pages(PAGE_START, PAGE_END)
        print(f" - 총 수집 상세 링크: {len(detail_urls)}")

        print("[2/3] 상세 페이지 순회 & 이미지 추출/다운로드…")
        saved_cnt = 0
        for du in tqdm(detail_urls):
            try:
                pairs = parse_detail_images(du)
                if not pairs:
                    continue
                for img_url, title in pairs:
                    if img_url in done_urls:
                        continue
                    p = download(img_url, SAVE_DIR, title, referer=du)
                    if p:
                        done_urls.add(img_url)
                        saved_cnt += 1
                        writer.writerow([du, img_url, os.path.basename(p), title])
                time.sleep(0.1)
            except Exception as e:
                print(f"  ! 상세 처리 실패: {du} ({e})")

        print("[3/3] 완료")
        print(" - 저장 폴더:", SAVE_DIR.resolve())
        print(" - CSV 로그 :", CSV_PATH.resolve())
        print(" - 저장 수  :", saved_cnt)

if __name__ == "__main__":
    main()
