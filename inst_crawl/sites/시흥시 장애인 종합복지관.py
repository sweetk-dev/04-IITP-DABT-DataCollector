# -*- coding: utf-8 -*-
"""
시흥시 장애인 종합복지관 자료실 파일 다운로더 (견고 모드: SSL 우회/HTTP 폴백)
- 목록: https://www.shwcd.org/bbs/board.php?bo_table=datafile&page=1..6
- 상세: section#bo_v_file ul li a.view_file_download
- 파일명: a 내부 <strong>텍스트>
"""

import os
import re
import csv
import time
import html
import warnings
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import certifi
from bs4 import BeautifulSoup
from tqdm import tqdm
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE = "https://www.shwcd.org"
LIST_FMT = BASE + "/bbs/board.php?bo_table=datafile&page={page}"
PAGE_START, PAGE_END = 1, 6

SAVE_DIR = Path("shwcd_downloads")
CSV_PATH = SAVE_DIR / "download_log.csv"
SAVE_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

# ---------- TLS 어댑터 (TLS1.2 강제 + 레거시 호환) ----------
class TLS12LegacyAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except Exception:
            pass
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(connections, maxsize, block, **kwargs)

def make_session():
    s = requests.Session()
    s.headers.update(HEADERS)
    s.trust_env = False
    retry = Retry(
        total=3, connect=3, read=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    s.mount("https://", TLS12LegacyAdapter(max_retries=retry))
    s.mount("http://", HTTPAdapter(max_retries=retry))
    return s

SESSION = make_session()

# ---------- 유틸 ----------
def sanitize_filename(name: str, max_len: int = 150) -> str:
    name = html.unescape(name or "").strip()
    name = re.sub(r"\s+", " ", name)
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    return (name or "file")[:max_len]

def safe_join(base_url: str, href: str) -> str:
    href = href or ""
    if href.startswith("//"):
        return "https:" + href
    return urljoin(base_url, href)

def get_content_disposition_filename(resp: requests.Response) -> str | None:
    cd = resp.headers.get("Content-Disposition") or resp.headers.get("content-disposition")
    if not cd:
        return None
    m = re.search(r'filename\*=\s*UTF-8\'\'([^;]+)', cd, flags=re.I)
    if m:
        from urllib.parse import unquote
        return sanitize_filename(unquote(m.group(1)))
    m = re.search(r'filename\s*=\s*"([^"]+)"', cd, flags=re.I)
    if m:
        return sanitize_filename(m.group(1))
    m = re.search(r'filename\s*=\s*([^;]+)', cd, flags=re.I)
    if m:
        return sanitize_filename(m.group(1))
    return None

def ensure_ext_by_url_or_path(name: str, url: str) -> str:
    if "." in os.path.basename(name):
        return name
    _, ext = os.path.splitext(urlparse(url).path)
    return f"{name}{ext}" if ext else name

def to_http(url: str) -> str:
    pu = urlparse(url)
    if pu.scheme == "https":
        return urlunparse(("http", pu.netloc, pu.path, pu.params, pu.query, pu.fragment))
    return url

# ---------- 네트워크(견고 모드) ----------
# 기존 robust_get 을 아래로 교체

def robust_get(url: str, *, headers=None, timeout=25, stream=False):
    """HTTPS(certifi) → (SSL 에러시) HTTP → (최후) 어댑터 우회 + verify=False"""
    headers = headers or HEADERS

    # 1) HTTPS with certifi (세션 사용: 커스텀 TLS 어댑터 적용)
    try:
        return SESSION.get(url, headers=headers, timeout=timeout,
                           verify=certifi.where(), stream=stream, allow_redirects=True)
    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.RequestException:
        pass

    # 2) HTTP fallback (세션 사용)
    url_http = to_http(url)
    if url_http != url:
        try:
            return SESSION.get(url_http, headers=headers, timeout=timeout,
                               stream=stream, allow_redirects=True)
        except requests.exceptions.RequestException:
            pass

    # 3) 최후수단: 어댑터(ssl_context) 우회 + verify=False
    #    => 모듈 레벨 requests.get 사용 (세션 미사용)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return requests.get(url, headers=headers, timeout=timeout,
                            verify=False, stream=stream, allow_redirects=True)


def fetch_html(url: str, referer: str | None = None, timeout: int = 25) -> BeautifulSoup:
    headers = dict(HEADERS)
    if referer:
        headers["Referer"] = referer
    r = robust_get(url, headers=headers, timeout=timeout, stream=False)
    r.raise_for_status()
    return BeautifulSoup(r.text, "lxml")

def download_file(file_url: str, filename: str, referer: str) -> str | None:
    headers = dict(HEADERS)
    headers["Referer"] = referer
    try:
        r = robust_get(file_url, headers=headers, timeout=40, stream=True)
        r.raise_for_status()

        cd_name = get_content_disposition_filename(r)
        final_name = sanitize_filename(cd_name or filename)
        final_name = ensure_ext_by_url_or_path(final_name, file_url)

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

# ---------- 파싱 ----------
def collect_post_links(page: int) -> list[str]:
    url = LIST_FMT.format(page=page)
    soup = fetch_html(url)
    links = []
    for a in soup.select("table .bo_tit a"):
        href = a.get("href")
        if not href:
            continue
        abs_url = safe_join(url, href)
        links.append(abs_url)
    # 중복 제거(순서 유지)
    seen, uniq = set(), []
    for u in links:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq

def parse_files_from_detail(detail_url: str) -> list[tuple[str, str]]:
    soup = fetch_html(detail_url, referer=detail_url)
    out = []
    for a in soup.select("section#bo_v_file ul li a.view_file_download"):
        file_href = a.get("href")
        if not file_href:
            continue
        file_url = safe_join(detail_url, file_href)
        strong = a.find("strong")
        name = strong.get_text(strip=True) if strong else a.get_text(strip=True)
        name = sanitize_filename(name or "file")
        out.append((file_url, name))
    # 중복 제거
    seen, uniq = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            uniq.append(item)
    return uniq

# ---------- 메인 ----------
def main():
    is_new = not CSV_PATH.exists()
    with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as fp:
        writer = csv.writer(fp)
        if is_new:
            writer.writerow(["page", "detail_url", "file_url", "saved_path", "name"])

        all_posts = []
        print("[1/3] 목록 순회 중…")
        for p in range(PAGE_START, PAGE_END + 1):
            try:
                posts = collect_post_links(p)
                all_posts.extend([(p, u) for u in posts])
                print(f" - page {p}: posts {len(posts)}")
            except Exception as e:
                print(f"  ! 목록 실패(page {p}): {e}")
            time.sleep(0.2)

        print(f"[2/3] 상세({len(all_posts)}건)에서 파일 링크 추출 및 다운로드…")
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

        print("[3/3] 완료")
        print(" - 저장 폴더:", SAVE_DIR.resolve())
        print(" - CSV 로그 :", CSV_PATH.resolve())
        print(" - 저장 수  :", saved_cnt)

if __name__ == "__main__":
    main()
