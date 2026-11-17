# 안양시수리장애인종합복지관 자료 수집기 (2026-11 사이트 개편 반영)
# 게시판 이름이 bo_table=notice 에서 숫자로 바뀌었다 — 공지사항 1004 · 복지 정보 1009 · 발간자료 1012
# pip install requests beautifulsoup4
import os, re, csv, time, html, random
import requests, urllib3, certifi
from urllib.parse import urljoin, urlparse, unquote
from bs4 import BeautifulSoup

# ================= 공통 설정 =================
SAVE_ROOT = "anyang_downloads"
HEADERS = {"User-Agent": "Mozilla/5.0"}
TIMEOUT, RETRY = 15, 3
SLEEP_LIST, SLEEP_FILE = 0.3, 0.15

# 저장 허용 확장자 (원하시면 비우거나 추가하세요)
ALLOWED_EXTS = {".pdf", ".hwp", ".hwpx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".jpg", ".jpeg", ".png"}

# ================ 파일명 복원 (깨짐 방지) ================
from email.header import decode_header as mime_decode

# SSL 예외 도메인: 인증서 체인 문제로 검증을 끄는 호스트(최소화 권장)
INSECURE_HOSTS = {"www.ajwc.or.kr"}  # 관악장애인종합복지관

# HTTPS 경고 끔(verify=False 사용 호스트만 해당)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _clean_name(s: str) -> str:
    s = html.unescape(s or "").strip()
    s = re.sub(r'[\\/:*?"<>|\r\n\t]+', " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:180] or "file"

def _try_unquote(v: str) -> str:
    # 이중 인코딩(%25EA...)까지 대비
    try:
        v1 = unquote(v)
        v2 = unquote(v1)
        return v2
    except Exception:
        return v

def _looks_mojibake_kr(s: str) -> bool:
    # CP949가 latin-1로 잘못 해석된 흔적(³´¼½¾ÀÁÂÃ...) 탐지
    return bool(re.search(r"[³´¼½¾ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßµ]", s))

def decode_header_filename(content_disposition: str) -> str | None:
    """Content-Disposition에서 안전하게 파일명 복원"""
    if not content_disposition:
        return None
    cd = content_disposition

    # 1) RFC 5987: filename*=UTF-8''...
    m = re.search(r"filename\*\s*=\s*(?:UTF-8''|)([^;]+)", cd, flags=re.I)
    if m:
        raw = m.group(1).strip().strip('"')
        return _clean_name(_try_unquote(raw))

    # 2) MIME encoded-word (= ?UTF-8?B?...?=)
    m = re.search(r'filename\s*=\s*("?=?[^";]+?=?"?)\s*(?:;|$)', cd, flags=re.I)
    if m:
        raw = m.group(1).strip().strip('"')
        if raw.startswith("=?") and raw.endswith("?="):
            try:
                parts = mime_decode(raw)
                text = "".join(
                    (p.decode(cs or "utf-8", "ignore") if isinstance(p, bytes) else p)
                    for p, cs in parts
                )
                return _clean_name(text)
            except Exception:
                pass

        # 3) 일반 filename= 값
        cand = raw
        try:
            cand = _try_unquote(cand)
        except Exception:
            pass
        cand = _clean_name(cand)
        if not _looks_mojibake_kr(cand):
            return cand

        # b) latin-1로 재인코딩 → cp949로 재해석 (모지부크 복구)
        try:
            cand_bytes = cand.encode("latin-1", "ignore")
            cand_kr = cand_bytes.decode("cp949", "ignore")
            cand_kr = _clean_name(cand_kr)
            return cand_kr or cand
        except Exception:
            return cand

    return None

def pick_filename(link_text: str | None, url: str, resp, title_fallback: str) -> str:
    """
    파일명 결정 우선순위:
      1) 링크 텍스트(보이는 파일명) - 확장자 있으면 최우선
      2) Content-Disposition 복원값
      3) URL basename
      4) 게시글 제목 + 기본 확장자(.pdf)
    (정규화는 하지 않음: 한글 자모 분리 방지, 금지문자만 제거)
    """
    # 1) 링크 텍스트
    if link_text:
        lt = _clean_name(link_text)
        base, ext = os.path.splitext(lt)
        if ext.lower() in ALLOWED_EXTS:
            return lt

    # 2) 헤더
    name = decode_header_filename(resp.headers.get("Content-Disposition", "")) or ""
    name = _clean_name(name)

    # 3) URL 경로 보조
    if not os.path.splitext(name)[1]:
        from_url = os.path.basename(urlparse(url).path)
        if from_url:
            from_url = _clean_name(_try_unquote(from_url))
            base, ext = os.path.splitext(from_url)
            if ext.lower() in ALLOWED_EXTS:
                name = from_url

    # 4) 최종 보정
    if not os.path.splitext(name)[1]:
        name = _clean_name(title_fallback) + ".pdf"

    return name
    
# ================== HTTP 유틸 (SSL 처리 포함) ==================
def _verify_flag_for(url: str):
    host = urlparse(url).hostname or ""
    if host in INSECURE_HOSTS:
        return False
    try:
        return certifi.where()
    except Exception:
        return True  # certifi 사용 불가 시 시스템 기본
    

# ================== HTTP 유틸 ==================
def http_get(sess, url, **kw):
    last = None
    verify_flag = kw.pop("verify", None)
    if verify_flag is None:
        verify_flag = _verify_flag_for(url)

    for i in range(RETRY):
        try:
            r = sess.get(
                url,
                headers=HEADERS,
                timeout=TIMEOUT,
                allow_redirects=True,
                verify=verify_flag,  # ← 핵심
                **kw
            )
            if r.status_code == 200:
                return r
            last = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last = e
        time.sleep(0.5 + 0.3*i + random.uniform(0, 0.2))
    raise last

def save_stream(sess, file_url: str, title: str, link_text: str | None, folder: str) -> str | None:
    r = http_get(sess, file_url, stream=True)
    fname = pick_filename(link_text, file_url, r, title)
    ext = os.path.splitext(fname.lower())[1]
    if ext and ALLOWED_EXTS and ext not in ALLOWED_EXTS:
        return None
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, fname)
    base, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(path):
        path = f"{base}_{i}{ext}"; i += 1
    with open(path, "wb") as f:
        for chunk in r.iter_content(8192):
            if chunk: f.write(chunk)
    return path

# ================= 기관별 설정 =================
CONFIGS = [
    # 안양시수리장애인종합복지관 — 공지사항
    {
        "name": "안양시수리장애인종합복지관_공지사항",
        "base": "https://www.asrc.or.kr",
        "list_url": "https://www.asrc.or.kr/bbs/board.php?bo_table=1004",
        "detail_link_sel": "a[href*='bo_table=1004'][href*='wr_id=']",
        "attach_link_sel": "#bo_v_file a, .view_file a, .bo_v_file a, a[href*='download.php'], a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], a[href$='.docx'], a[href$='.xls'], a[href$='.xlsx'], a[href$='.zip']",
        "page_param": "page",
    },
    # 안양시수리장애인종합복지관 — 복지정보
    {
        "name": "안양시수리장애인종합복지관_복지정보",
        "base": "https://www.asrc.or.kr",
        "list_url": "https://www.asrc.or.kr/bbs/board.php?bo_table=1009",
        "detail_link_sel": "a[href*='bo_table=1009'][href*='wr_id=']",
        "attach_link_sel": "#bo_v_file a, .view_file a, .bo_v_file a, a[href*='download.php'], a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], a[href$='.docx'], a[href$='.xls'], a[href$='.xlsx'], a[href$='.zip']",
        "page_param": "page",
    },
    # 안양시수리장애인종합복지관 — 발간자료
    {
        "name": "안양시수리장애인종합복지관_발간자료",
        "base": "https://www.asrc.or.kr",
        "list_url": "https://www.asrc.or.kr/bbs/board.php?bo_table=1012",
        "detail_link_sel": "a[href*='bo_table=1012'][href*='wr_id=']",
        "attach_link_sel": "#bo_v_file a, .view_file a, .bo_v_file a, a[href*='download.php'], a[href$='.pdf'], a[href$='.hwp'], a[href$='.hwpx'], a[href$='.doc'], a[href$='.docx'], a[href$='.xls'], a[href$='.xlsx'], a[href$='.zip']",
        "page_param": "page",
    },
]

# ================= 크롤링 로직 =================
# 그누보드 게시판: 목록 page=N → 상세(wr_id) → 첨부(download.php) 저장.
#  - 상단 고정 공지는 모든 쪽에 다시 나오므로, 한 쪽에서 새 게시글이 하나도 없으면 끝으로 본다
#    (마지막 쪽 뒤에도 고정 공지만 보이는 게시판에서 무한히 넘어가지 않게).
#  - 작업 폴더의 download_log.csv 에 이미 있는 첨부 주소는 다시 받지 않는다 — 분기마다 다시 돌리므로
#    처음 실행 뒤에는 새 게시글의 첨부만 받는다.
MAX_PAGES = int(os.getenv("INST_MAX_PAGES", "500"))   # 안전 상한(시험 실행 때 작게 준다)

def extract_detail_links(list_html, list_url, sel):
    soup = BeautifulSoup(list_html, "html.parser")
    links = []
    for a in soup.select(sel):
        href = a.get("href")
        if href:
            links.append(urljoin(list_url, href))
    # 보조: 그누보드 공통 제목 셀렉터
    if not links:
        for a in soup.select(".bo_tit a, .td_subject a, .subject a"):
            href = a.get("href")
            if href and "wr_id=" in href:
                links.append(urljoin(list_url, href))
    # 같은 글의 쪽 번호·검색 인자만 다른 주소는 하나로 본다
    norm = []
    for u in links:
        u = re.sub(r"&(page|sca|sfl|stx|sst|sod|spt)=[^&]*", "", u)
        norm.append(u)
    return list(dict.fromkeys(norm))

def extract_attachments(detail_html, detail_url, attach_sel):
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    for a in soup.select(attach_sel):
        href = a.get("href")
        text = a.get_text(" ", strip=True)
        if href and not href.startswith("javascript"):
            links.append((urljoin(detail_url, href), text))
    seen, uniq = set(), []
    for u, t in links:
        if u not in seen:
            seen.add(u); uniq.append((u, t))
    return uniq

def _attach_name(text: str) -> str:
    """그누보드 첨부 링크 글자 '파일명.hwp (123.4K)' 에서 크기 표시를 뗀다."""
    t = re.sub(r"\s*\([0-9.,]+\s*[KMG]?B?\)\s*$", "", text or "", flags=re.I)
    return t.strip()

def crawl_institution(cfg):
    name = cfg["name"]
    list_url = cfg["list_url"]
    detail_sel = cfg["detail_link_sel"]
    attach_sel = cfg["attach_link_sel"]
    page_param = cfg.get("page_param") or "page"

    inst_folder = os.path.join(SAVE_ROOT, name)
    os.makedirs(inst_folder, exist_ok=True)

    log_csv = os.path.join(inst_folder, "download_log.csv")
    done = set()
    if os.path.exists(log_csv):
        with open(log_csv, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) >= 4:
                    done.add(row[3])
    else:
        with open(log_csv, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["inst", "title", "detail_url", "file_url", "saved_path"])

    sess = requests.Session()
    seen_posts = set()
    total_posts, total_files, skipped = 0, 0, 0

    for page in range(1, MAX_PAGES + 1):
        url = f"{list_url}{'&' if '?' in list_url else '?'}{page_param}={page}"
        print(f"\n[{name}] 리스트 {page}페이지: {url}")
        try:
            lr = http_get(sess, url)
        except Exception as e:
            print("  - 리스트 실패:", e)
            break

        details = [d for d in extract_detail_links(lr.text, url, detail_sel) if d not in seen_posts]
        if not details:
            print("  - 새 게시물이 없습니다. 종료.")
            break
        seen_posts.update(details)

        for durl in details:
            try:
                dr = http_get(sess, durl)
            except Exception as e:
                print("  - 상세 실패:", durl, "→", e); continue

            dsoup = BeautifulSoup(dr.text, "html.parser")
            t_el = dsoup.select_one("#bo_v_title .bo_v_tit, #bo_v_title, h2#bo_v_title")
            title = t_el.get_text(" ", strip=True) if t_el else (dsoup.title.get_text(strip=True) if dsoup.title else durl)
            title_safe = _clean_name(title)

            attaches = extract_attachments(dr.text, durl, attach_sel)
            if not attaches:
                continue

            print(f"  ▶ [{title_safe}] 첨부 {len(attaches)}건")
            total_posts += 1
            for file_url, link_text in attaches:
                if file_url in done:
                    skipped += 1
                    continue
                try:
                    saved = save_stream(sess, file_url, title_safe, _attach_name(link_text), inst_folder)
                    if saved:
                        total_files += 1
                        done.add(file_url)
                        print("    - 저장:", os.path.basename(saved))
                        with open(log_csv, "a", newline="", encoding="utf-8") as f:
                            csv.writer(f).writerow([name, title_safe, durl, file_url, saved])
                    else:
                        print("    - 스킵(확장자 비허용/판단불가):", file_url)
                except Exception as e:
                    print("    - 다운로드 실패:", file_url, "→", e)
                time.sleep(SLEEP_FILE)
        time.sleep(SLEEP_LIST)

    print(f"\n[{name}] 완료: 첨부 있는 게시글 {total_posts}건, 새 파일 {total_files}건, 이미 받은 첨부 {skipped}건 → {inst_folder}")

def main():
    os.makedirs(SAVE_ROOT, exist_ok=True)
    for cfg in CONFIGS:
        crawl_institution(cfg)

if __name__ == "__main__":
    main()
