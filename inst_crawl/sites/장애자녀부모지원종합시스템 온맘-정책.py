# -*- coding: utf-8 -*-
# pip install requests beautifulsoup4 certifi
import os, re, csv, time, html, random
import requests, certifi
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup

# ================== 설정 ==================
BASE      = "http://www.nise.go.kr"  # HTTPS에서 HTTP로 변경
LIST_BASE = f"{BASE}/onmam/front/M0000029/board/list.do"  # 자료실 목록 (M0000031) 관계법령(M0000029)
SAVE_DIR  = "nise_onmam_press"
LOG_CSV   = os.path.join(SAVE_DIR, "download_log.csv")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; NiseOnmamCrawler/1.0)"}
TIMEOUT, RETRY = 15, 3
SLEEP = 0.5  # 서버 부하 방지를 위해 증가

# 다운로드 허용 확장자
ALLOWED_EXTS = {".pdf", ".hwp", ".hwpx", ".doc", ".docx", ".xls", ".xlsx"}

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
    # SSL 검증 비활성화 및 더 안전한 연결 설정
    verify = kw.pop("verify", False)  # SSL 검증 비활성화
    last = None
    for i in range(RETRY):
        try:
            # SSL 경고 무시 및 더 안전한 연결 설정
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # 더 강력한 SSL 우회를 위한 추가 설정
            import ssl
            ssl._create_default_https_context = ssl._create_unverified_context
            
            r = sess.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, verify=verify, **kw)
            if r.status_code == 200:
                _apply_encoding(r); return r
            last = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last = e
            print(f"    시도 {i+1}/{RETRY} 실패: {e}")
        time.sleep(SLEEP + 0.3*i + random.uniform(0, 0.15))
    raise last

def http_post(sess, url, data, **kw):
    """POST 요청 전송 - 폼 제출 방식 페이지네이션용"""
    verify = kw.pop("verify", False)
    last = None
    for i in range(RETRY):
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            import ssl
            ssl._create_default_https_context = ssl._create_unverified_context
            
            r = sess.post(url, data=data, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True, verify=verify, **kw)
            if r.status_code == 200:
                _apply_encoding(r); return r
            last = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last = e
            print(f"    시도 {i+1}/{RETRY} 실패: {e}")
        time.sleep(SLEEP + 0.3*i + random.uniform(0, 0.15))
    raise last

# ================== 목록 파싱 ==================
def build_list_url(page: int) -> str:
    """페이지 URL 생성 - 온맘 사이트는 폼 제출 방식 사용"""
    if page == 1:
        return LIST_BASE
    # 온맘 사이트는 fn_linkPage(pageIndex) 함수를 사용하여 폼 제출
    # POST 방식으로 pageIndex 파라미터 전송
    return LIST_BASE

def extract_post_links(list_html: str, list_url: str):
    """
    목록에서 게시글 링크 추출:
      - table 내의 tr에서 td class="subject" 안의 링크
    반환: [절대URL, ...]
    """
    soup = BeautifulSoup(list_html, "html.parser")
    posts = []
    
    # 테이블에서 게시글 링크 찾기
    tables = soup.select("table")
    print(f"  테이블 발견: {len(tables)}개")
    
    # 페이지네이션 정보도 함께 확인
    pagination_info = soup.select("div, span, a")
    for elem in pagination_info:
        text = elem.get_text(strip=True)
        if "페이지" in text or "page" in text.lower() or "1 / 41" in text:
            print(f"  페이지네이션 요소 발견: {text}")
    
    for table_idx, table in enumerate(tables):
        rows = table.select("tr")
        for row_idx, row in enumerate(rows):
            # td class="subject" 안의 링크 찾기
            subject_td = row.select_one('td[class="subject"]')
            if subject_td:
                title_link = subject_td.select_one('a[href*="view.do?pstSn="]')
                if title_link:
                    href = title_link.get("href")
                    title_text = title_link.get_text(strip=True)
                    if href:
                        full_url = urljoin(list_url, href)
                        posts.append(full_url)
                        print(f"    게시글: {title_text[:50]}...")
    
    # 중복 제거
    return list(dict.fromkeys(posts))

def check_has_next_page(list_html: str, current_page: int) -> bool:
    """다음 페이지 존재 여부 확인"""
    soup = BeautifulSoup(list_html, "html.parser")
    
    print(f"=== 페이지네이션 디버그 ===")
    
    # 방법 1: 페이지 번호가 현재 페이지보다 큰 링크가 있는지 확인
    page_links = soup.select("a[href*='page=']")
    print(f"  page= 파라미터가 있는 링크: {len(page_links)}개")
    
    max_page_found = current_page
    for link in page_links:
        href = link.get("href", "")
        text = link.get_text(strip=True)
        print(f"    링크: {href} - {text}")
        if "page=" in href:
            try:
                # URL에서 page 파라미터 값 추출
                page_match = re.search(r'page=(\d+)', href)
                if page_match:
                    page_num = int(page_match.group(1))
                    max_page_found = max(max_page_found, page_num)
                    print(f"      페이지 번호 발견: {page_num}")
            except:
                continue
    
    # 방법 2: "다음" 또는 ">" 텍스트가 있는 링크 확인
    has_next_text = False
    next_links = soup.select("a")
    for link in next_links:
        text = link.get_text(strip=True).lower()
        href = link.get("href", "")
        if any(keyword in text for keyword in ["다음", "next", ">", "다음목록", "다음페이지"]):
            has_next_text = True
            print(f"    다음 페이지 링크 발견: {text} - {href}")
            break
    
    # 방법 3: 현재 페이지가 41 미만이면 계속 진행 (온맘 사이트는 41페이지까지 있음)
    manual_check = current_page < 41
    
    print(f"  페이지네이션 체크: 현재={current_page}, 최대발견={max_page_found}, 다음텍스트={has_next_text}, 수동체크={manual_check}")
    
    return max_page_found > current_page or has_next_text or manual_check

# ================== 상세 파싱/저장 ==================
def parse_attachments_from_detail(detail_html: str, detail_url: str):
    """
    상세에서 첨부파일 링크 수집
    - div class="boardFile" 내의 li 요소에서 다운로드 링크 수집
    """
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    
    print("=== 디버그: 첨부파일 검색 ===")
    
    # 주요 방법: div class="boardFile" 내의 첨부파일 찾기
    board_file = soup.select_one('div[class="boardFile"]')
    if board_file:
        print(f"✓ boardFile div 발견")
        
        # li 요소 안의 다운로드 링크 찾기
        file_items = board_file.select("li")
        print(f"첨부파일 항목: {len(file_items)}개")
        
        for i, item in enumerate(file_items, 1):
            # a 태그에서 다운로드 링크와 파일명 추출
            download_link = item.select_one('a[href*="fileDown.do"]')
            if download_link:
                href = download_link.get("href")
                # 파일명은 span class="fileName"에서 추출
                file_name_span = download_link.select_one('span[class="fileName"]')
                file_name = file_name_span.get_text(strip=True) if file_name_span else ""
                
                if href:
                    full_url = urljoin(detail_url, href)
                    links.append((full_url, file_name))
                    print(f"  {i}번째 첨부파일: {href} - {file_name}")
    
    # 대안: fileDown.do 링크가 있는 모든 a 태그 검색
    if not links:
        print("  대안: fileDown.do 링크 검색...")
        download_links = soup.select('a[href*="fileDown.do"]')
        for a in download_links:
            href = a.get("href")
            # 파일명 추출 시도
            file_name_span = a.select_one('span[class="fileName"]')
            file_name = file_name_span.get_text(strip=True) if file_name_span else ""
            
            if href:
                full_url = urljoin(detail_url, href)
                links.append((full_url, file_name))
                print(f"  fileDown.do에서 발견: {href} - {file_name}")
    
    # 백업: 확장자 기반 검색
    if not links:
        print("  확장자 기반 검색 시도...")
        for a in soup.select(
            "a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], "
            "a[href$='.docx'], a[href$='.xls'], a[href$='.xlsx'] "
        ):
            href = a.get("href")
            text = a.get_text(strip=True)
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
    m = re.search(r"(.+?\.(pdf|hwp|hwpx|docx|doc|xls|xlsx|zip|rar|jpg|jpeg|png|gif))\b", t, flags=re.I)
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

    # SSL 문제 해결을 위한 세션 설정
    sess = requests.Session()
    
    # SSL 관련 설정 추가
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # 더 안전한 연결을 위한 설정
    sess.verify = False
    
    total_saved = 0
    empty_pages = 0
    page = 1

    while True:
        list_url = build_list_url(page)
        print(f"\n[List] page={page} → {list_url}")
        try:
            if page == 1:
                # 첫 페이지는 GET 요청
                lr = http_get(sess, list_url)
            else:
                # 2페이지부터는 POST 요청으로 pageIndex 전송
                data = {"pageIndex": str(page)}
                print(f"  POST 요청 데이터: {data}")
                lr = http_post(sess, list_url, data)
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

        # 온맘 사이트는 총 41페이지까지 있음
        has_next = page < 41
        if not has_next:
            print(" - 마지막 페이지(41)에 도달하여 종료합니다.")
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
    crawl(max_pages=41)  # 테스트를 위해 3페이지만 크롤링
