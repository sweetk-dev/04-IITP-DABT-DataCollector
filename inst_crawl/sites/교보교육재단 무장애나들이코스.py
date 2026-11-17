import os
import re
import time
import csv
import unicodedata
from urllib.parse import urljoin, urlparse
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from tqdm import tqdm



BASE = "https://www.kbedu.or.kr"
LIST_URL = "https://www.kbedu.or.kr/ud/bbs.html?Table=ins_bbs38"
OUT_DIR = Path("kbedu_images")
OUT_DIR.mkdir(parents=True, exist_ok=True)
CSV_PATH = OUT_DIR / "download_log.csv"


def sanitize_filename(text: str, max_len: int = 120) -> str:
    """캡션 텍스트를 파일명으로 안전하게 변환."""
    if not text:
        text = "untitled"

    # 정규화 & 공백 정리
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text).strip()

    # 윈도우/맥/리눅스 금지 문자 제거
    text = re.sub(r'[\\/:*?"<>|]', "_", text)

    # 이모지/비문자 제거(남기고 싶으면 아래 라인 주석처리)
    text = "".join(ch for ch in text if ch.isprintable())

    # 너무 긴 파일명 자르기 — 리눅스 파일명 한도는 255 바이트(한글 1자 3바이트)라 글자 수와 바이트를 함께 본다
    if len(text) > max_len:
        text = text[:max_len].rstrip()
    while len(text.encode("utf-8")) > 180:
        text = text[:-1].rstrip()

    # 빈 문자열 방지
    return text or "untitled"


def ensure_ext_from_url(url: str, default_ext=".jpg") -> str:
    parsed = urlparse(url)
    basename = os.path.basename(parsed.path)
    _, ext = os.path.splitext(basename)
    if ext.lower() in [".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"]:
        return ext
    return default_ext


def fetch_html(url: str, headers=None, timeout=15) -> str:
    headers = headers or {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36"
    }
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    r.encoding = r.apparent_encoding
    return r.text


AJAX_URL = BASE + "/ud/php_bin/course_ajax.php"
PER_PAGE = 20                                     # 목록 페이지의 더보기 버튼 o_n 값
MAX_PAGES = int(os.getenv("INST_MAX_PAGES", "200"))  # 안전 상한(시험 실행 때 작게 준다)


def _uids(html_text: str) -> list:
    return list(dict.fromkeys(re.findall(r"Table=ins_bbs38&(?:amp;)?mode=view&(?:amp;)?uid=(\d+)", html_text)))


def get_all_post_links() -> list:
    """목록 첫 쪽(20건)과 '더보기' ajax(POST course_ajax.php page=2,3…)로 모든 게시글 링크를 모은다.

    2026-11 목록이 dl.list 구조에서 div.news-list-wrap + 더보기 ajax 로 바뀌어 selenium 선택자가 맞지 않게 됐다.
    ajax 응답은 목록에 덧붙일 HTML 조각이고, 더 없으면 빈 문자열이다.
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
               "Referer": LIST_URL, "X-Requested-With": "XMLHttpRequest"}
    first = fetch_html(LIST_URL, headers=headers)
    uids = _uids(first)
    m = re.search(r'newsroom_more_btn"[^>]*total_data="(\d+)"', first) or re.search(r'total_data="(\d+)"', first)
    total = int(m.group(1)) if m else None
    for page in range(2, MAX_PAGES + 1):
        if total is not None and (page - 1) * PER_PAGE >= total:
            break
        r = requests.post(AJAX_URL, data={"page": page, "search": "", "o_n": PER_PAGE}, headers=headers, timeout=20)
        r.encoding = r.apparent_encoding
        chunk = (r.text or "").strip()
        new = [u for u in _uids(chunk) if u not in uids]
        if not chunk or not new:
            break
        uids.extend(new)
        time.sleep(0.3)
    print(f" - 목록 전체 {total if total is not None else '?'}건 중 링크 {len(uids)}개")
    return [f"{BASE}/ud/bbs.html?Table=ins_bbs38&mode=view&uid={u}" for u in uids]


def pair_images_and_captions(soup: BeautifulSoup):
    """
    페이지 안에서 본문 이미지와 캡션(<p class="body_img_table3">)을 최대한 짝지어 반환.
    반환: [(img_url, caption_text), ...]
    """
    pairs = []

    # 1) 본문 구조: <table.body_img_table.body_img_center> 안에
    #    <div.body_img_table2><img ...></div>
    #    <p class="body_img_table3">캡션</p>
    blocks = soup.select("table.body_img_table.body_img_center")
    for block in blocks:
        img = block.select_one("div.body_img_table2 img")
        cap = block.select_one("p.body_img_table3")
        if img and img.get("src"):
            img_src = img.get("src").strip()
            if img_src.startswith("//"):
                img_src = "https:" + img_src
            elif img_src.startswith("/"):
                img_src = urljoin(BASE, img_src)
            elif not img_src.startswith("http"):
                img_src = urljoin(BASE, img_src)

            caption = ""
            if cap:
                caption = cap.get_text(strip=True)
            pairs.append((img_src, caption))

    # 2) 혹시 위 패턴 외에도 본문 내 img와 바로 뒤/근처의 p.body_img_table3가 있을 수 있어 보조 탐색
    if not pairs:
        imgs = soup.select("img")
        for img in imgs:
            if not img.get("src"):
                continue
            img_src = img.get("src").strip()
            if img_src.startswith("//"):
                img_src = "https:" + img_src
            elif img_src.startswith("/"):
                img_src = urljoin(BASE, img_src)
            elif not img_src.startswith("http"):
                img_src = urljoin(BASE, img_src)

            # 인접한 형제 중 캡션 p 찾기(너무 공격적이면 주석처리 가능)
            cap_tag = None
            next_el = img.parent
            for _ in range(4):  # 근처 4단계 안에서 탐색
                if not next_el:
                    break
                candidate = next_el.find("p", class_="body_img_table3")
                if candidate:
                    cap_tag = candidate
                    break
                next_el = next_el.parent

            caption = cap_tag.get_text(strip=True) if cap_tag else ""
            pairs.append((img_src, caption))

    # 중복 제거
    uniq = []
    seen = set()
    for u, c in pairs:
        key = (u, c)
        if key not in seen and u.lower().startswith("http"):
            uniq.append((u, c))
            seen.add(key)
    return uniq


def download_image(url: str, save_path: Path, headers=None, timeout=30) -> bool:
    headers = headers or {
        "User-Agent": "Mozilla/5.0"
    }
    with requests.get(url, headers=headers, stream=True, timeout=timeout) as r:
        if r.status_code != 200:
            return False
        with open(save_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
    return True


def main():
    print("[1/4] 리스트에서 모든 상세 링크 수집 중…")
    detail_urls = get_all_post_links()
    print(f" - 수집된 상세 링크: {len(detail_urls)}개")

    # CSV 헤더 준비
    is_new_csv = not CSV_PATH.exists()
    # 지난 실행에서 받은 사진 주소 — 분기마다 다시 돌리므로 새 사진만 받는다
    done_urls = set()
    if not is_new_csv:
        with open(CSV_PATH, newline="", encoding="utf-8-sig") as f:
            done_urls = {row[1] for row in csv.reader(f) if len(row) > 1}
    with open(CSV_PATH, "a", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile)
        if is_new_csv:
            writer.writerow(["post_url", "image_url", "saved_filename", "caption"])

        print("[2/4] 상세 페이지 순회하며 이미지/캡션 추출 & 다운로드…")
        for post_url in tqdm(detail_urls):
            try:
                html = fetch_html(post_url)
            except Exception as e:
                print(f"  ! 상세 페이지 로드 실패: {post_url} ({e})")
                continue

            soup = BeautifulSoup(html, "html.parser")
            pairs = pair_images_and_captions(soup)

            if not pairs:
                # 이미지가 없을 수도 있음
                continue

            # 글별 폴더(선택): uid 기준으로 폴더를 만들어 정리하려면 아래 주석 해제
            # uid_match = re.search(r"[?&]uid=(\d+)", post_url)
            # post_dir = OUT_DIR / (uid_match.group(1) if uid_match else "misc")
            # post_dir.mkdir(exist_ok=True)
            # save_base = post_dir

            save_base = OUT_DIR

            # 글 내 여러 이미지 처리
            for idx, (img_url, caption) in enumerate(pairs, start=1):
                if img_url in done_urls:
                    continue
                # 파일명 생성
                base_name = sanitize_filename(caption or "image")
                ext = ensure_ext_from_url(img_url)
                # 글 안에서 중복 방지용 인덱스 부여
                filename = f"{base_name}"
                candidate = save_base / f"{filename}{ext}"

                # 동일 파일명 존재 시 뒤에 (n) 붙이기
                n = 2
                while candidate.exists():
                    candidate = save_base / f"{filename} ({n}){ext}"
                    n += 1

                # 다운로드
                try:
                    ok = download_image(img_url, candidate)
                except Exception as e:
                    print(f"  ! 다운로드 실패: {img_url} ({e})")
                    ok = False

                if ok:
                    done_urls.add(img_url)
                    writer.writerow([post_url, img_url, candidate.name, caption])
                else:
                    print(f"  ! 상태 비정상으로 스킵: {img_url}")

        print(f"[3/4] 저장 경로: {OUT_DIR.resolve()}")
        print(f"[4/4] CSV 로그: {CSV_PATH.resolve()}")
        print("완료!")


if __name__ == "__main__":
    main()
