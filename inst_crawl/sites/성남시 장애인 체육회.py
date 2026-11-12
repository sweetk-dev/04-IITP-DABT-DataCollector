# -*- coding: utf-8 -*-
# pip install requests beautifulsoup4 certifi
import os, re, csv, time, html, random
import requests, certifi
from urllib.parse import urljoin, urlparse, unquote, urlencode
from bs4 import BeautifulSoup

BASE = "https://www.snsad.or.kr"
OUTER_URL = f"{BASE}/sub05-01.jsp"     # 겉 페이지(공지)
LIST_HINTS = ("q&a/list.jsp", "list.jsp")
VIEW_URL  = f"{BASE}/q&a/view.jsp"     # 상세 iframe (POST sNo)

SAVE_DIR = "seongnam_sports_dl"
LOG_CSV  = os.path.join(SAVE_DIR, "download_log.csv")

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; SeongnamSportsCrawler/3.2)"}
TIMEOUT, RETRY = 15, 3
SLEEP = 0.25

# 첨부 선택자(상세 view.jsp 내부 table.tb_QA)
ATTACH_SEL_STRICT = "table.tb_QA td a[href^='./upload/'], table.tb_QA td a[href*='/upload/']"
ATTACH_SEL_LOOSE  = ("td a[target='_blank'][href$='.pdf'], "
                     "td a[href$='.hwp'], td a[href$='.hwpx'], td a[href$='.doc'], td a[href$='.docx'], "
                     "td a[href$='.jpg'], td a[href$='.jpeg'], td a[href$='.png']")
ALLOWED_EXTS = {".pdf",".hwp",".hwpx",".doc",".docx",".jpg",".jpeg",".png"}

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
        time.sleep(SLEEP + 0.3*i + random.uniform(0,0.15))
    raise last

def http_post(sess, url, data: dict, referer: str):
    verify = certifi.where()
    last = None
    for i in range(RETRY):
        try:
            r = sess.post(url, headers={**HEADERS, "Referer": referer},
                          data=data, timeout=TIMEOUT, allow_redirects=True, verify=verify)
            if r.status_code == 200:
                _apply_encoding(r); return r
            last = RuntimeError(f"HTTP {r.status_code}")
        except Exception as e:
            last = e
        time.sleep(SLEEP + 0.3*i + random.uniform(0,0.15))
    raise last

# ---------- 파서 ----------
def find_iframe_src(outer_html: str, base_url: str, hints=LIST_HINTS) -> str | None:
    soup = BeautifulSoup(outer_html, "html.parser")
    for hint in hints:
        tag = soup.select_one(f"iframe[src*='{hint}']")
        if tag and tag.get("src"):
            return urljoin(base_url, tag["src"])
    tag = soup.find("iframe", src=True)
    return urljoin(base_url, tag["src"]) if tag else None

def extract_form_defaults(list_html: str) -> dict:
    """리스트 iframe(form1)의 숨김값(subjecthead, page, keyword 등) 수집"""
    soup = BeautifulSoup(list_html, "html.parser")
    form = soup.find("form", attrs={"name":"form1"}) or soup
    base = {}
    for inp in form.select("input[type='hidden'][name]"):
        name = (inp.get("name") or "").strip()
        val  = (inp.get("value") or "").strip()
        if name:
            base[name] = val
    base.setdefault("subjecthead", base.get("subjecthead") or "snsad01")
    base.setdefault("page", base.get("page") or "1")
    base.pop("sNo", None)  # sNo는 상세마다 주입
    return base

def extract_rno_list(list_html: str):
    """fnViewCall(m) 순서와 hidden r_no 순서 매핑 → sNo 배열"""
    soup = BeautifulSoup(list_html, "html.parser")
    form = soup.find("form", attrs={"name":"form1"}) or soup

    calls = []
    for el in form.select("a[onclick], button[onclick]"):
        onclick = (el.get("onclick") or "").replace(" ", "")
        m = re.search(r"fnViewCall\((\d+)\)", onclick)
        if m: calls.append(int(m.group(1)))

    rnos = [ (inp.get("value") or "").strip()
             for inp in form.select("input[name='r_no'], input[name='r_no[]'], input#r_no") ]
    rnos = [v for v in rnos if v]
    if not calls or not rnos:
        return []

    n = min(len(calls), len(rnos))
    ordered = [None]*n
    for idx in range(n):
        m = calls[idx]
        if 0 <= m < n:
            ordered[m] = rnos[idx]
    fill = [v for v in rnos[:n] if v not in ordered]
    for i in range(n):
        if ordered[i] is None and fill:
            ordered[i] = fill.pop(0)
    return [v for v in ordered if v]

def find_max_page(list_html: str) -> int | None:
    """페이지 네비에서 fnGotoPage(N) 최대값 추정. 없으면 None."""
    # 예: <a href="#" onclick="fnGotoPage(7); return false;">7</a>
    nums = [int(x) for x in re.findall(r"fnGotoPage\((\d+)\)", list_html)]
    return max(nums) if nums else None

def parse_attachments_from_html(detail_html: str, base_url: str):
    soup = BeautifulSoup(detail_html, "html.parser")
    links = []
    # 엄격
    for a in soup.select(ATTACH_SEL_STRICT):
        href = a.get("href")
        if not href: continue
        links.append((urljoin(base_url, href), a.get_text(" ", strip=True)))
    # 보조
    for a in soup.select(ATTACH_SEL_LOOSE):
        href = a.get("href")
        if not href: continue
        links.append((urljoin(base_url, href), a.get_text(" ", strip=True)))

    seen, uniq = set(), []
    for u, t in links:
        if u not in seen:
            seen.add(u); uniq.append((u, t))

    title = soup.title.get_text(strip=True) if soup.title else "상세"
    return title, uniq

def extract_pretty_from_link_text(t: str) -> str | None:
    if not t: return None
    t = _clean_name(t)
    t = re.sub(r"\s*\(\s*\d[\d,]*\s*byte\s*\)\s*$", "", t, flags=re.I)
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

# ---------- 리스트 페이지 로더(페이지네이션) ----------
def load_list_page(sess, iframe_list_url: str, form_defaults: dict, page: int) -> requests.Response:
    """브라우저의 fnGotoPage(n)과 동일: form1.page=n; form submit (POST list.jsp)"""
    payload = {**form_defaults, "page": str(page)}
    referer = iframe_list_url
    # list.jsp는 같은 URL에 POST하는 구조라 보통 referer는 iframe_list_url이면 충분
    return http_post(sess, iframe_list_url, payload, referer=referer)

# ---------- 메인 ----------
def crawl_all(max_pages: int | None = None):
    ensure_dir(SAVE_DIR)
    if not os.path.exists(LOG_CSV):
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["page","sNo","detail_title","file_url","link_text","saved_path"])

    sess = requests.Session()

    # 겉 → 리스트 iframe
    print(f"[성남시 장애인체육회] 겉 페이지: {OUTER_URL}")
    outer = http_get(sess, OUTER_URL)
    iframe_list = find_iframe_src(outer.text, OUTER_URL, hints=LIST_HINTS)
    if not iframe_list:
        print(" ! iframe(list.jsp)를 찾지 못했습니다."); return
    print(" - 리스트 iframe:", iframe_list)

    # 1페이지 GET으로 기준폼/최대페이지 파악
    r1 = http_get(sess, iframe_list)
    form_defaults = extract_form_defaults(r1.text)
    last_page = find_max_page(r1.text)
    if max_pages is None:
        max_pages = last_page or 99999  # 네비가 없으면 '끝날 때까지' 방식

    print(f" - form defaults: {form_defaults}")
    print(f" - last page hint: {last_page}, run up to: {max_pages}")

    total_saved = 0
    empty_in_a_row = 0

    # 페이지 루프
    for page in range(1, max_pages + 1):
        # 1페이지는 이미 받아둔 r1를 사용, 그 외는 POST로 page 전환
        if page == 1:
            lr = r1
        else:
            lr = load_list_page(sess, iframe_list, form_defaults, page)

        rnos = extract_rno_list(lr.text)
        print(f"\n[Page {page}] r_no: {len(rnos)}건")
        if not rnos:
            empty_in_a_row += 1
            # 연속 2페이지 비면 종료(네비 없이 끝을 만났다고 가정)
            if empty_in_a_row >= 2 or last_page is None:
                print(" - 더 이상 게시글이 없어서 종료합니다.")
                break
            else:
                continue
        else:
            empty_in_a_row = 0

        # 상세 처리
        for idx, sNo in enumerate(rnos):
            try:
                # 상세는 리스트 폼 상태 + sNo가 필요
                payload = {**form_defaults, "page": str(page), "sNo": sNo}
                dr = http_post(sess, VIEW_URL, payload, referer=iframe_list)

                detail_title, attaches = parse_attachments_from_html(dr.text, VIEW_URL)
                if not attaches:
                    # 동일 파라미터로 GET 재시도
                    vr = http_get(sess, f"{VIEW_URL}?{urlencode(payload)}")
                    detail_title, attaches = parse_attachments_from_html(vr.text, VIEW_URL)

                print(f"  - [{idx+1}/{len(rnos)}] sNo={sNo} 첨부 {len(attaches)}건")

                for file_url, link_text in attaches:
                    try:
                        saved_path = save_file(sess, file_url, link_text, detail_title)
                        if saved_path:
                            total_saved += 1
                            print("    · 저장:", os.path.basename(saved_path))
                            with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
                                csv.writer(f).writerow([page, sNo, detail_title, file_url, link_text, saved_path])
                        else:
                            print("    · 스킵(확장자 비허용/판단불가):", file_url)
                    except Exception as e:
                        print("    · 실패:", file_url, "→", e)
                    time.sleep(SLEEP)
            except Exception as e:
                print(f"  ! 상세 실패 sNo={sNo} → {e}")
                time.sleep(SLEEP)

        # 네비가 있는 사이트면 마지막 페이지 도달 시 종료
        if last_page is not None and page >= last_page:
            print(" - 네비 기준 마지막 페이지 도달"); break

    print(f"\n완료: 총 {total_saved}개 파일 저장 → {os.path.abspath(SAVE_DIR)}")

if __name__ == "__main__":
    # max_pages를 지정하지 않으면 페이지 네비의 마지막까지(없으면 자동 종료) 순회
    crawl_all(max_pages=None)
