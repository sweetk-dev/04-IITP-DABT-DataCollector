# -*- coding: utf-8 -*-
"""
VisitKorea 열린관광(무장애) 이미지 다운로더 (페이지 2~30 수집)
- 리스트: https://access.visitkorea.or.kr/ms/list.do#^^31^^modifiedDate^{page}
- 상세: swiper background-image URL 추출, a 텍스트(예: "서해수호관 1")로 저장
"""
import os, re, csv, time, html, unicodedata
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm

# Selenium
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

# ====== 설정 ======
PAGE_START, PAGE_END = 31, 40
LIST_URL_FMT = "https://access.visitkorea.or.kr/ms/list.do#^^31^^modifiedDate^{page}"  # 경기도(31), 최신순
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

# ---------- 리스트: 여러 페이지 순회 ----------
# 기존 collect_detail_links_multi_pages 함수를 이걸로 교체

def collect_detail_links_multi_pages(page_start: int, page_end: int) -> list[str]:
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1280,2400")
    options.add_experimental_option("excludeSwitches", ["enable-logging"])

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    wait = WebDriverWait(driver, SEL_WAIT)

    all_urls, seen = [], set()

    try:
        prev_first_href = None

        for page in range(page_start, page_end + 1):
            # ① 캐시버스터 추가(서버는 무시하지만 브라우저는 강제 새로고침)
            cachebuster = int(time.time() * 1000)
            url = LIST_URL_FMT.format(page=page)
            url_with_cb = url.replace("list.do", f"list.do?_={cachebuster}")

            # 로드
            driver.get(url_with_cb)

            # ② 첫 렌더 대기
            wait.until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, LIST_SELECTOR)))

            # ③ "실제로 페이지가 바뀌었는지" 확인 (첫 카드 href 변화 감시)
            ok = False
            for _ in range(15):
                anchors_now = driver.find_elements(By.CSS_SELECTOR, LIST_SELECTOR)
                if not anchors_now:
                    time.sleep(0.3)
                    continue
                first_href = anchors_now[0].get_attribute("href") or ""
                if first_href and first_href != prev_first_href:
                    prev_first_href = first_href
                    ok = True
                    break
                # 스크립트로 hashchange 유도 및 살짝 대기
                driver.execute_script("window.dispatchEvent(new HashChangeEvent('hashchange'));")
                time.sleep(0.4)

            if not ok:
                print(f"[WARN] 페이지 {page}: 콘텐츠 변화 감지 실패(같은 목록일 수 있음). 계속 진행합니다.")

            # ④ 무한스크롤 로딩 (필요한 만큼 아래로 내리기)
            prev_count, tries = 0, 0
            while tries < MAX_SCROLL_TRIES:
                count_now = len(driver.find_elements(By.CSS_SELECTOR, LIST_SELECTOR))
                driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                time.sleep(SCROLL_PAUSE)
                count_after = len(driver.find_elements(By.CSS_SELECTOR, LIST_SELECTOR))
                if count_after <= count_now:
                    tries += 1
                else:
                    tries = 0
                if count_after == prev_count:
                    # 한 번 더 스크롤 후 변화 없으면 종료
                    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
                    time.sleep(SCROLL_PAUSE)
                    if len(driver.find_elements(By.CSS_SELECTOR, LIST_SELECTOR)) == prev_count:
                        break
                prev_count = count_after

            # ⑤ 해당 페이지의 링크 수집
            anchors = driver.find_elements(By.CSS_SELECTOR, LIST_SELECTOR)
            page_urls = []
            for a in anchors:
                href = a.get_attribute("href") or ""
                if not href:
                    continue
                abs_url = urljoin(BASE + "/ms/", href)
                if "detail.do" in abs_url and abs_url not in seen:
                    seen.add(abs_url)
                    page_urls.append(abs_url)
                    all_urls.append(abs_url)

            print(f"페이지 {page}: 수집 {len(page_urls)}건 (누적 {len(all_urls)}건)")

        return all_urls

    finally:
        driver.quit()


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

        print(f"[1/3] 페이지 {PAGE_START}~{PAGE_END} 리스트 수집…")
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
                    p = download(img_url, SAVE_DIR, title, referer=du)
                    if p:
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
