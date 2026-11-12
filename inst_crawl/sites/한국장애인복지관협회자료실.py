# -*- coding: utf-8 -*-
"""
한국장애인복지관협회 자료실 파일 다운로더
- 목록: http://www.hinet.or.kr/bbs/board.php?bo_table=5020&page=1..34
- 상세: section#bo_v_file ul li a.view_file_download
- 파일명: <a> 내부 <strong> 텍스트
"""

import os
import re
import csv
import time
import html
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# -------------------- 설정 --------------------
BASE = "http://www.hinet.or.kr"
LIST_FMT = BASE + "/bbs/board.php?bo_table=5020&page={page}"
PAGE_START, PAGE_END = 1, 34

SAVE_DIR = Path("hinet_downloads")
CSV_PATH = SAVE_DIR / "download_log.csv"
SAVE_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# -------------------- 세션/네트워크 --------------------
def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(HEADERS)
    s.trust_env = False  # 프록시/보안솔루션 개입 최소화
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

def fetch_html(url: str, referer: str | None = None, timeout: int = 25) -> BeautifulSoup:
    headers = dict(HEADERS)
    if referer:
        headers["Referer"] = referer
    r = SESSION.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

# -------------------- 유틸 --------------------
def sanitize_filename(name: str, max_len: int = 160) -> str:
    name = html.unescape(name or "").strip()
    name = re.sub(r"\s+", " ", name)
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    return (name or "file")[:max_len]

def safe_join(base_url: str, href: str) -> str:
    href = href or ""
    if href.startswith("//"):
        return "http:" + href
    return urljoin(base_url, href)

def get_content_disposition_filename(resp: requests.Response) -> str | None:
    cd = resp.headers.get("Content-Disposition") or resp.headers.get("content-disposition")
    if not cd:
        return None
    # filename*=UTF-8''... > filename="..." > filename=...
    m = re.search(r'filename\*=\s*UTF-8\'\'([^;]+)', cd, flags=re.I)
    if m:
        return sanitize_filename(unquote(m.group(1)))
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd, flags=re.I)
    if m:
        return sanitize_filename(m.group(1))
    m = re.search(r'filename\s*=\s*([^;]+)', cd, flags=re.I)
    if m:
        return sanitize_filename(m.group(1))
    return None

def ensure_ext_by_url_or_name(name: str, url: str) -> str:
    # 이름에 확장자가 없으면 URL 경로에서 확장자 추정
    if "." in os.path.basename(name):
        return name
    path = urlparse(url).path
    _, ext = os.path.splitext(path)
    return f"{name}{ext}" if ext else name

# -------------------- 파싱 --------------------
def collect_post_links(page: int) -> list[str]:
    """
    목록 페이지에서 상세 링크 수집
    - table > tr > td.td_subject > a[href]
    """
    url = LIST_FMT.format(page=page)
    soup = fetch_html(url)
    links = []
    for a in soup.select("table td.td_subject a[href]"):
        href = a.get("href")
        if not href:
            continue
        abs_url = safe_join(url, href)
        links.append(abs_url)

    # 중복 제거(순서 유지)
    seen, out = set(), []
    for u in links:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out

def parse_files_from_detail(detail_url: str) -> list[tuple[str, str]]:
    """
    상세 페이지에서 첨부 파일 목록 파싱
    - section#bo_v_file ul li a.view_file_download
    - 파일명: <strong> 텍스트
    """
    soup = fetch_html(detail_url, referer=detail_url)
    files = []
    for a in soup.select("section#bo_v_file ul li a.view_file_download"):
        href = a.get("href")
        if not href:
            continue
        file_url = safe_join(detail_url, href)
        name_tag = a.find("strong")
        name = name_tag.get_text(strip=True) if name_tag else a.get_text(strip=True)
        name = sanitize_filename(name or "file")
        files.append((file_url, name))

    # 중복 제거
    seen, out = set(), []
    for item in files:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out

# -------------------- 다운로드 --------------------
def download_file(file_url: str, filename_hint: str, referer: str) -> str | None:
    headers = dict(HEADERS)
    headers["Referer"] = referer

    try:
        with SESSION.get(file_url, headers=headers, stream=True, timeout=40, allow_redirects=True) as r:
            r.raise_for_status()

            # ✅ 서버 제공 파일명(Content-Disposition) 무시하고, 항상 name 기준 사용
            final_name = sanitize_filename(filename_hint)
            final_name = ensure_ext_by_url_or_name(final_name, r.url or file_url)

            out_path = SAVE_DIR / final_name
            n = 2
            while out_path.exists():
                stem, ext = os.path.splitext(final_name)
                out_path = SAVE_DIR / f"{stem} ({n}){ext}"
                n += 1

            with open(out_path, "wb") as f:
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)

        return str(out_path)

    except Exception as e:
        print(f"  ! 다운로드 실패: {e} :: {file_url}")
        return None

# -------------------- 메인 --------------------
def main():
    is_new = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as fp:
        writer = csv.writer(fp)
        if is_new:
            writer.writerow(["page", "detail_url", "file_url", "saved_path", "name"])

        # 1) 목록 순회
        all_posts: list[tuple[int, str]] = []
        print("[1/3] 목록 수집…")
        for p in range(PAGE_START, PAGE_END + 1):
            try:
                posts = collect_post_links(p)
                all_posts.extend((p, u) for u in posts)
                print(f" - page {p}: posts {len(posts)}")
            except Exception as e:
                print(f"  ! 목록 실패(page {p}): {e}")
            time.sleep(0.15)

        # 2) 상세에서 파일 추출/다운로드
        print(f"[2/3] 상세 {len(all_posts)}건 처리…")
        saved_cnt = 0
        for page_no, detail in tqdm(all_posts):
            try:
                files = parse_files_from_detail(detail)
                if not files:
                    continue
                for file_url, name in files:
                    saved = download_file(file_url, name, referer=detail)
                    writer.writerow([page_no, detail, file_url, saved or "", name])
                    if saved:
                        saved_cnt += 1
                time.sleep(0.05)
            except Exception as e:
                print(f"  ! 상세 실패: {detail} ({e})")

        # 3) 요약
        print("[3/3] 완료")
        print(" - 저장 폴더:", SAVE_DIR.resolve())
        print(" - CSV 로그 :", CSV_PATH.resolve())
        print(" - 저장 수  :", saved_cnt)

if __name__ == "__main__":
    # 인증서 경고 등 노이즈 억제(HTTP 사이트지만 혹시 중간 HTTPS 리다이렉트가 있을 경우 대비)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        main()
