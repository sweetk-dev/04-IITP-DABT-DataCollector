# -*- coding: utf-8 -*-
# pip install requests beautifulsoup4 certifi
import os, re, csv, time, html, random
import requests, certifi
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup

# ================== 설정 ==================
BASE      = "https://www.rehab21.or.kr"
LIST_BASE = f"{BASE}/bbs/board.php?bo_table=B11"  # 공지 목록
SAVE_DIR  = "seongnam_rehab21_dl"
LOG_CSV   = os.path.join(SAVE_DIR, "download_log.csv")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; Rehab21Crawler/1.0)"}
TIMEOUT, RETRY = 15, 3
SLEEP = 0.25

ALLOWED_EXTS = {".pdf", ".hwp", ".hwpx", ".doc", ".docx", ".jpg", ".jpeg", ".png"}

# ================== 유틸 ==================
def ensure_dir(p): os.makedirs(p, exist_ok=True); return p

def _clean_name(s: str) -> str:
    s = html.unescape(s or "").strip()
    s = re.sub(r'[\\/:*?"<>|\r\n\t]+', " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:180] or "file"

def _try_unquote(v: str) -> str:
    try:
        return unquote(unquote(v))
    except Exception:
        return v

def _apply_encoding(resp):
    """EUC-KR/UTF-8 자동 감지"""
    ct = (resp.headers.get("Content-Type") or "").lower()
    if "euc-kr" in ct or "ks_c_5601" in ct:
        resp.encoding = "euc-kr"; return
    snippet = resp.content[:2048].decode("latin-1", errors="ignore").lower()
    if "charset=euc-kr" in snippet or "charset=ks_c_5601" in snippet:
        resp.encoding = "euc-kr"
    else:
        resp.encoding = resp.encoding or "utf-8"

def http_get(sess, url, **kw):
    verify = kw.pop("verify", certifi.where())
    last = None
    for i in range(RETRY):
        try:
            r = sess.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, verify=verify, **kw)
            if r.status_code == 200:
                _apply_encoding(r); return r
            last = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last = e
        time.sleep(SLEEP + 0.3*i + random.uniform(0, 0.15))
    raise last

# ================== 목록 파싱 ==================
def build_list_url(page: int) -> str:
    if "page=" in LIST_BASE:
        return re.sub(r"(page=)\d+", rf"\g<1>{page}", LIST_BASE)
    sep = "&" if "?" in LIST_BASE else "?"
    return f"{LIST_BASE}{sep}page={page}"

def extract_post_links_with_icon(list_html: str, list_url: str):
    """
    목록 테이블 내에서:
      - td 안의 a[href]를 후보로 보고
      - 같은 td 내부에 <i class="fa fa-download"> 아이콘이 있으면 첨부 있는 글로 간주
    반환: [절대URL, ...]
    """
    soup = BeautifulSoup(list_html, "html.parser")
    posts = []
    # 테이블 제약을 너무 빡세게 두지 않고 td 내 a를 포괄
    for td in soup.select("table td"):
        a = td.find("a", href=True)
        if not a:
            continue
        # 첨부 아이콘 존재?
        has_icon = bool(td.select_one("i.fa.fa-download"))
        if not has_icon:
            continue
        href = a.get("href")
        posts.append(urljoin(list_url, href))
    # 중복 제거
    return list(dict.fromkeys(posts))

# ================== 상세 파싱/저장 ==================
def parse_attachments_from_detail(detail_html: str, detail_url: str):
    """
    상세에서 class='view_file_download' 영역의 첨부 a 수집
    """
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    for a in soup.select(".view_file_download a[href]"):
        href = a.get("href")
        text = a.get_text(" ", strip=True)
        if not href:
            continue
        links.append((urljoin(detail_url, href), text))
    # 여유롭게 파일 확장자 힌트도 추가로 줌(혹시 클래스 명이 다를 때 대비)
    if not links:
        for a in soup.select("a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], a[href$='.docx'], a[href$='.jpg'], a[href$='.jpeg'], a[href$='.png']"):
            href = a.get("href"); 
            if href:
                links.append((urljoin(detail_url, href), a.get_text(" ", strip=True)))
    # 중복 제거
    uniq, seen = [], set()
    for u, t in links:
        if u not in seen:
            seen.add(u); uniq.append((u, t))
    # 제목 보조(기본 파일명용)
    title = soup.title.get_text(strip=True) if soup.title else "상세"
    return title, uniq

def extract_pretty_from_link_text(t: str) -> str | None:
    if not t: return None
    t = _clean_name(t)
    # '(...byte)' 꼬리 제거
    t = re.sub(r"\s*\(\s*\d[\d,]*\s*byte\s*\)\s*$", "", t, flags=re.I)
    # 확장자 포함 파일명만 캡처
    m = re.search(r"(.+?\.(pdf|hwp|hwpx|docx|doc|jpg|jpeg|png))\b", t, flags=re.I)
    return _clean_name(m.group(1)) if m else None

def pick_filename(link_text: str | None, url: str, title_fallback: str) -> str:
    pretty = extract_pretty_from_link_text(link_text or "")
    if pretty:
        ext = os.path.splitext(pretty.lower())[1]
        if not ALLOWED_EXTS or ext in ALLOWED_EXTS:
            return pretty
    from_url = _clean_name(_try_unquote(os.path.basename(urlparse(url).path)))
    if from_url:
        base, ext = os.path.splitext(from_url)
        if ext and (not ALLOWED_EXTS or ext.lower() in ALLOWED_EXTS):
            return from_url
    return _clean_name(title_fallback) + ".pdf"

def save_file(sess, file_url: str, link_text: str, title_for_default: str) -> str | None:
    # 파일명 결정
    fname = pick_filename(link_text, file_url, title_for_default)
    ext = os.path.splitext(fname.lower())[1]
    if ALLOWED_EXTS and ext and ext not in ALLOWED_EXTS:
        return None
    r = http_get(sess, file_url, stream=True)
    ensure_dir(SAVE_DIR)
    path = os.path.join(SAVE_DIR, fname)
    base, ext = os.path.splitext(path); i = 1
    while os.path.exists(path):
        path = f"{base}_{i}{ext}"; i += 1
    with open(path, "wb") as f:
        for chunk in r.iter_content(8192):
            if chunk: f.write(chunk)
    return path

# ================== 메인 ==================
def crawl(max_pages: int | None = None):
    ensure_dir(SAVE_DIR)
    if not os.path.exists(LOG_CSV):
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["page","post_url","detail_title","file_url","link_text","saved_path"])

    sess = requests.Session()
    total_saved = 0
    empty_pages = 0

    page = 1
    while True:
        list_url = build_list_url(page)
        print(f"\n[List] page={page} → {list_url}")
        try:
            lr = http_get(sess, list_url)
        except Exception as e:
            print(" - 목록 요청 실패:", e)
            break

        # 첨부 아이콘이 있는 게시글만 수집
        posts = extract_post_links_with_icon(lr.text, list_url)
        print(f" - 첨부아이콘 게시글: {len(posts)}건")

        if not posts:
            empty_pages += 1
            # 2페이지 연속으로 비면 종료 (마지막 도달)
            if empty_pages >= 2:
                print(" - 더 이상 게시글이 없어 종료합니다.")
                break
        else:
            empty_pages = 0

        for idx, purl in enumerate(posts, 1):
            try:
                dr = http_get(sess, purl)
                detail_title, attaches = parse_attachments_from_detail(dr.text, purl)
                print(f"   [{idx}/{len(posts)}] 첨부 {len(attaches)}건 / {purl}")

                for file_url, link_text in attaches:
                    try:
                        saved_path = save_file(sess, file_url, link_text, detail_title)
                        if saved_path:
                            total_saved += 1
                            print("     · 저장:", os.path.basename(saved_path))
                            with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                                csv.writer(f).writerow([page, purl, detail_title, file_url, link_text, saved_path])
                        else:
                            print("     · 스킵(확장자 비허용/판단불가):", file_url)
                    except Exception as e:
                        print("     · 실패:", file_url, "→", e)
                time.sleep(SLEEP)
            except Exception as e:
                print("   ! 상세 실패:", purl, "→", e)
                time.sleep(SLEEP)

        # 종료/다음 페이지
        if max_pages is not None and page >= max_pages:
            break
        page += 1

    print(f"\n완료: 총 {total_saved}개 파일 저장 → {os.path.abspath(SAVE_DIR)}")

if __name__ == "__main__":
    # max_pages=None 이면 '게시글 없는 페이지 2회 연속' 만날 때까지 순회
    crawl(max_pages=None)
