# -*- coding: utf-8 -*-
# pip install requests beautifulsoup4 certifi
import os, re, csv, time, html, random
import requests, certifi
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup

# ================== 설정 ==================
BASE      = "https://suwonrehab.or.kr"
LIST_BASE = f"{BASE}/bbs/board.php?bo_table=welfaredata"  # 공지 목록 (notice)
SAVE_DIR  = "suwon_rehab_welfare"
LOG_CSV   = os.path.join(SAVE_DIR, "download_log.csv")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SuwonRehabCrawler/1.0)"}
TIMEOUT, RETRY = 15, 3
SLEEP = 0.5  # 서버 부하 방지를 위해 증가

# 다운로드 허용 확장자
ALLOWED_EXTS = {".pdf", ".hwp", ".hwpx", ".doc", ".docx"}

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
    """페이지 URL 생성 - 수원시장애인종합복지관 페이지네이션 형식에 맞춤"""
    if page == 1:
        return LIST_BASE
    sep = "&" if "?" in LIST_BASE else "?"
    return f"{LIST_BASE}{sep}page={page}"

def extract_post_links(list_html: str, list_url: str):
    """
    목록 테이블에서 게시글 링크 추출:
      - td 안 a[href] 중 wr_id= 포함 링크만 수집
    반환: [절대URL, ...]
    """
    soup = BeautifulSoup(list_html, "html.parser")
    posts = []
    
    # 테이블에서 링크 추출 (더 정확한 선택자)
    for a in soup.select("table a[href*='wr_id=']"):
        href = a.get("href")
        if not href:
            continue
        posts.append(urljoin(list_url, href))
    
    # 백업: 일반적인 링크 패턴도 확인
    if not posts:
        for a in soup.select("a[href*='wr_id=']"):
            href = a.get("href")
            if href and "wr_id=" in href:
                posts.append(urljoin(list_url, href))
    
    # 중복 제거 & 공지 상단 고정/중복 방지
    return list(dict.fromkeys(posts))

def check_has_next_page(list_html: str) -> bool:
    """다음 페이지 존재 여부 확인"""
    soup = BeautifulSoup(list_html, "html.parser")
    # 페이지네이션에서 다음 페이지 링크 확인
    next_links = soup.select("a[href*='page='], .pagination a, .pg a")
    for link in next_links:
        href = link.get("href", "")
        if "page=" in href and any(keyword in link.get_text().lower() for keyword in ["다음", "next", ">"]):
            return True
    return False

# ================== 상세 파싱/저장 ==================
def parse_attachments_from_detail(detail_html: str, detail_url: str):
    """
    상세에서 class='view_file_download' 영역의 첨부 a 수집
    """
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    
    # 주요 방법: view_file_download 클래스의 첨부파일 링크
    for a in soup.select(".view_file_download[href]"):
        href = a.get("href")
        text = a.get_text(" ", strip=True)
        if href:
            links.append((urljoin(detail_url, href), text))
    
    # 백업: 첨부파일 관련 클래스들
    if not links:
        for selector in [".file_download a[href]", ".attach_file a[href]", ".attachment a[href]"]:
            for a in soup.select(selector):
                href = a.get("href")
                text = a.get_text(" ", strip=True)
                if href:
                    links.append((urljoin(detail_url, href), text))
    
    # 최종 백업: 확장자 기반
    if not links:
        for a in soup.select(
            "a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], "
            "a[href$='.docx'], a[href$='.jpg'], a[href$='.jpeg'], a[href$='.png']"
        ):
            href = a.get("href")
            text = a.get_text(" ", strip=True)
            if href:
                links.append((urljoin(detail_url, href), text))

    # 중복 제거
    uniq, seen = [], set()
    for u, t in links:
        if u not in seen:
            seen.add(u); uniq.append((u, t))

    # 제목(파일명 기본값용)
    title = soup.title.get_text(strip=True) if soup.title else "상세"
    return title, uniq

def extract_pretty_from_link_text(t: str) -> str | None:
    if not t: return None
    t = _clean_name(t)
    # '(...byte)' 꼬리 제거
    t = re.sub(r"\s*\(\s*\d[\d,]*\s*byte\s*\)\s*$", "", t, flags=re.I)
    # 확장자 포함 파일명만 추출
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
    fname = pick_filename(link_text, file_url, title_for_default)
    ext = os.path.splitext(fname.lower())[1]
    if ALLOWED_EXTS and ext and ext not in ALLOWED_EXTS:
        return None
    
    try:
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
    except Exception as e:
        print(f"     · 파일 다운로드 실패: {file_url} → {e}")
        return None

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

        posts = extract_post_links(lr.text, list_url)
        print(f" - 게시글: {len(posts)}건")

        if not posts:
            empty_pages += 1
            if empty_pages >= 2:
                print(" - 더 이상 게시글이 없어 종료합니다.")
                break
        else:
            empty_pages = 0

        # 다음 페이지 존재 여부 확인
        has_next = check_has_next_page(lr.text)
        if not has_next and page > 1:
            print(" - 다음 페이지가 없어 종료합니다.")
            break

        for idx, purl in enumerate(posts, 1):
            try:
                print(f"   [{idx}/{len(posts)}] 상세 페이지 접근: {purl}")
                dr = http_get(sess, purl)
                detail_title, attaches = parse_attachments_from_detail(dr.text, purl)
                print(f"     제목: {detail_title}")
                print(f"     첨부파일: {len(attaches)}건")

                if not attaches:
                    print("     · 첨부파일 없음")
                    continue

                for file_idx, (file_url, link_text) in enumerate(attaches, 1):
                    try:
                        print(f"       [{file_idx}/{len(attaches)}] 다운로드 시도: {file_url}")
                        saved_path = save_file(sess, file_url, link_text, detail_title)
                        if saved_path:
                            total_saved += 1
                            print("         ✓ 저장 완료:", os.path.basename(saved_path))
                            with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                                csv.writer(f).writerow([page, purl, detail_title, file_url, link_text, saved_path])
                        else:
                            print("         ✗ 스킵(확장자 비허용/판단불가):", file_url)
                    except Exception as e:
                        print("         ✗ 실패:", file_url, "→", e)
                    
                    # 파일 간 간격
                    time.sleep(SLEEP * 0.5)
                
                time.sleep(SLEEP)
            except Exception as e:
                print("   ! 상세 실패:", purl, "→", e)
                time.sleep(SLEEP)

        if max_pages is not None and page >= max_pages:
            print(f" - 최대 페이지({max_pages})에 도달하여 종료합니다.")
            break
        page += 1

    print(f"\n완료: 총 {total_saved}개 파일 저장 → {os.path.abspath(SAVE_DIR)}")

if __name__ == "__main__":
    # max_pages=None → 비는 페이지 2회 만나면 종료
    # max_pages=5 → 최대 5페이지까지만 크롤링
    crawl(max_pages=None)
