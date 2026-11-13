# -*- coding: utf-8 -*-
# pip install requests beautifulsoup4 certifi
import os, re, csv, time, html, random
import requests, certifi
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup

# ================== 설정 ==================
BASE      = "https://www.swsad.co.kr"
LIST_BASE = f"{BASE}/base/board/list?boardManagementNo=1&menuLevel=2&menuNo=2"  # 공지 목록
SAVE_DIR  = "suwon_sports_dl"
LOG_CSV   = os.path.join(SAVE_DIR, "download_log.csv")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SuwonSportsCrawler/1.0)"}
TIMEOUT, RETRY = 15, 3
SLEEP = 0.5  # 서버 부하 방지를 위해 증가

# 다운로드 허용 확장자
ALLOWED_EXTS = {".pdf", ".hwp", ".hwpx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".rar"}

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
    """UTF-8 인코딩 설정"""
    resp.encoding = "utf-8"

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
    """페이지 URL 생성 - 수원시장애인체육회 페이지네이션 형식에 맞춤"""
    if page == 1:
        return LIST_BASE
    sep = "&" if "?" in LIST_BASE else "?"
    return f"{LIST_BASE}{sep}page={page}"

def extract_post_links(list_html: str, list_url: str):
    """
    목록 테이블에서 게시글 링크 추출:
      - 첨부파일 아이콘이 있는 게시물의 링크만 수집
    반환: [절대URL, ...]
    """
    soup = BeautifulSoup(list_html, "html.parser")
    posts = []
    
    # 테이블에서 첨부파일이 있는 게시글 링크 추출
    table = soup.select_one("table")
    if table:
        rows = table.select("tr")
        for row in rows:
            # 첨부파일 아이콘 확인
            file_icon = row.select_one("img[src*='file-icon.png']")
            if file_icon:
                # 같은 행에서 제목 링크 찾기
                title_link = row.select_one("a[href*='board/read']")
                if title_link:
                    href = title_link.get("href")
                    if href:
                        posts.append(urljoin(list_url, href))
    
    # 중복 제거
    return list(dict.fromkeys(posts))

def check_has_next_page(list_html: str, current_page: int) -> bool:
    """다음 페이지 존재 여부 확인"""
    soup = BeautifulSoup(list_html, "html.parser")
    
    # 방법 1: 페이지 번호가 현재 페이지보다 큰 링크가 있는지 확인
    page_links = soup.select("a[href*='page=']")
    max_page_found = current_page
    
    for link in page_links:
        href = link.get("href", "")
        if "page=" in href:
            try:
                # URL에서 page 파라미터 값 추출
                page_match = re.search(r'page=(\d+)', href)
                if page_match:
                    page_num = int(page_match.group(1))
                    max_page_found = max(max_page_found, page_num)
            except:
                continue
    
    # 방법 2: "다음" 또는 ">" 텍스트가 있는 링크 확인
    has_next_text = False
    for link in page_links:
        text = link.get_text(strip=True).lower()
        if any(keyword in text for keyword in ["다음", "next", ">", "다음목록"]):
            has_next_text = True
            break
    
    # 방법 3: 현재 페이지가 31 미만이면 계속 진행 (수동 설정)
    manual_check = current_page < 31
    
    print(f"  페이지네이션 체크: 현재={current_page}, 최대발견={max_page_found}, 다음텍스트={has_next_text}, 수동체크={manual_check}")
    
    return max_page_found > current_page or has_next_text or manual_check

# ================== 상세 파싱/저장 ==================
def parse_attachments_from_detail(detail_html: str, detail_url: str):
    """
    상세에서 첨부파일 링크 수집
    - div="board_view_file" 아래 p class="file_each" 안의 a href 링크 수집
    """
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    
    print("=== 디버그: 첨부파일 검색 ===")
    
    # HTML 구조 디버그 - 처음 1000자만 출력
    html_preview = detail_html[:1000]
    #print(f"HTML 미리보기: {html_preview}")
    
    # 주요 방법: board_view_file div 아래 file_each 클래스의 링크
    board_view_file = soup.select_one('div[class="board_view_file"]')
    if board_view_file:
        print(f"✓ board_view_file div 발견")
        file_each_elements = board_view_file.select('p[class="file_each"]')
        print(f"file_each 요소: {len(file_each_elements)}개")
        
        for i, file_elem in enumerate(file_each_elements):
            # file_each 안의 a 태그 찾기
            file_links = file_elem.select('a[href]')
            for a in file_links:
                href = a.get("href")
                text = a.get_text(" ", strip=True)
                print(f"  {i+1}번째 file_each: {href} - {text}")
                if href:
                    links.append((urljoin(detail_url, href), text))
    else:
        print("✗ board_view_file div를 찾을 수 없음")
        
        # 대안: 다른 선택자들 시도
        print("  대안 선택자 시도...")
        
        # 1. id에 "file"이 포함된 div
        file_divs = soup.select('div[id*="file"]')
        print(f"  id에 'file' 포함된 div: {len(file_divs)}개")
        for div in file_divs:
            print(f"    div id='{div.get('id')}'")
            file_links = div.select('a[href]')
            for a in file_links:
                href = a.get("href")
                text = a.get_text(" ", strip=True)
                if href:
                    links.append((urljoin(detail_url, href), text))
        
        # 2. class에 "file"이 포함된 요소
        file_elements = soup.select('[class*="file"]')
        print(f"  class에 'file' 포함된 요소: {len(file_elements)}개")
        for elem in file_elements:
            file_links = elem.select('a[href]')
            for a in file_links:
                href = a.get("href")
                text = a.get_text(" ", strip=True)
                if href:
                    links.append((urljoin(detail_url, href), text))
    
    # 백업: 첨부파일 관련 클래스들로 검색
    if not links:
        print("  백업 방법 시도...")
        for selector in [
            ".file_download a[href]", 
            ".attach_file a[href]", 
            ".attachment a[href]",
            ".file a[href]",
            ".download a[href]"
        ]:
            for a in soup.select(selector):
                href = a.get("href")
                text = a.get_text(" ", strip=True)
                if href:
                    links.append((urljoin(detail_url, href), text))
    
    # 최종 백업: 확장자 기반 검색
    if not links:
        print("  확장자 기반 검색 시도...")
        for a in soup.select(
            "a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], "
            "a[href$='.docx'], a[href$='.xls'], a[href$='.xlsx'], a[href$='.zip'], a[href$='.rar']"
        ):
            href = a.get("href")
            text = a.get_text(" ", strip=True)
            if href:
                links.append((urljoin(detail_url, href), text))

    print(f"  총 {len(links)}개 첨부파일 링크 수집됨")

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
    m = re.search(r"(.+?\.(pdf|hwp|hwpx|docx|doc|xls|xlsx|zip|rar))\b", t, flags=re.I)
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
        print(f" - 첨부파일 있는 게시글: {len(posts)}건")

        if not posts:
            empty_pages += 1
            if empty_pages >= 2:
                print(" - 더 이상 첨부파일이 있는 게시글이 없어 종료합니다.")
                break
        else:
            empty_pages = 0

        # 다음 페이지 존재 여부 확인
        has_next = check_has_next_page(lr.text, page)
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
    crawl(max_pages=None)  # 전체 페이지 크롤링 (31페이지까지)
