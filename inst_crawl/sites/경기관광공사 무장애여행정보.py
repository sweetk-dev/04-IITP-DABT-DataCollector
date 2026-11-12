# pip install playwright requests
# playwright install chromium
import os, re, html, asyncio, time
import requests
from urllib.parse import urljoin, urlparse
from playwright.async_api import async_playwright

BASE = "https://ggtour.or.kr"
LIST_URL = f"{BASE}/bf/information?contentTypeCd=TOURIST"
SAVE_DIR = "ggtour_bf_images"
os.makedirs(SAVE_DIR, exist_ok=True)

# ---------- utils ----------
def clean_filename(s: str) -> str:
    s = html.unescape(s or "").strip()
    s = re.sub(r'[\\/:*?"<>|\r\n\t]+', " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:180] or "image"

def guess_ext(url: str) -> str:
    m = re.search(r"\.(jpg|jpeg|png|gif|webp|bmp|tif|tiff)(?:\?|#|$)", urlparse(url).path.lower())
    return f".{m.group(1)}" if m else ".jpg"

def save_image(img_url: str, place: str, idx: int, referer: str):
    """<장소>_<상세 페이지 안 순번>.<확장자> 로 저장한다. 같은 이름이 이미 있으면 다시 받지 않는다.

    장소명은 분류(관람_시설·관람_자연 등)를 장소 단위로 정하는 데 쓴다.
    """
    path = os.path.join(SAVE_DIR, f"{clean_filename(place)}_{idx}{guess_ext(img_url)}")
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return None
    headers = {"User-Agent": "Mozilla/5.0", "Referer": referer}
    with requests.get(img_url, headers=headers, timeout=30, stream=True) as r:
        r.raise_for_status()
        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk: f.write(chunk)
    return path

# ---------- crawler ----------
async def crawl():
    total_saved = 0
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx = await browser.new_context(locale="ko-KR",
                                        user_agent=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                                    "Chrome/124.0.0.0 Safari/537.36"))
        page = await ctx.new_page()

        # 1) 목록 진입
        print("[List] open →", LIST_URL)
        await page.goto(LIST_URL, wait_until="networkidle", timeout=45000)

        # 목록 렌더링 대기 (정확히 ul.information)
        try:
            await page.wait_for_selector("ul.information li a.link_box", timeout=20000)
        except Exception as e:
            print(" - 목록 대기 실패:", e)
            await page.screenshot(path="debug_list_first.png", full_page=True)
            with open("debug_list_first.html", "w", encoding="utf-8") as f:
                f.write(await page.content())
            await browser.close()
            return

        # 페이징을 “다음” 버튼으로 순회 (최대 30회 안전한 한도)
        visited_pages = set()
        page_turns = 0
        while True:
            page_turns += 1
            # 현재 페이지 인덱스 로깅
            current_idx = await page.eval_on_selector(
                "a.btn_page.on", "el => el?.getAttribute('data-page-number') || ''"
            )
            print(f"\n[List] 현재 data-page-number={current_idx or '0(or 없음)'}")

            # 2) 상세 링크 수집 (절대경로 변환)
            detail_hrefs = await page.eval_on_selector_all(
                "ul.information li a.link_box",
                "els => els.map(a => a.getAttribute('href'))"
            )
            details = []
            seen = set()
            for h in detail_hrefs:
                if not h: continue
                absurl = urljoin(LIST_URL, h.strip())
                if absurl not in seen:
                    seen.add(absurl); details.append(absurl)
            print(f" - 상세 링크 {len(details)}건 (예시): {details[:3]}")

            if not details:
                # 디버깅 덤프
                await page.screenshot(path=f"debug_list_no_details_{page_turns}.png", full_page=True)
                with open(f"debug_list_no_details_{page_turns}.html", "w", encoding="utf-8") as f:
                    f.write(await page.content())

            # 3) 상세에서 이미지 추출/저장
            for durl in details:
                dpage = await ctx.new_page()
                try:
                    await dpage.goto(durl, wait_until="networkidle", timeout=45000)
                    # 상세 이미지(지연 로딩 포함)
                    await dpage.wait_for_selector("div.img_list div.inner_box img", timeout=15000)
                    imgs = await dpage.eval_on_selector_all(
                        "div.img_list div.inner_box img",
                        """els => els.map(img => ({
                                src: img.getAttribute('data-src') || img.getAttribute('src') || '',
                                alt: img.getAttribute('alt') || ''
                            }))"""
                    )
                    # 장소명: 페이지 제목 "<장소> | 무장애 관광지 | ..." 의 첫 부분
                    place = ((await dpage.title()) or "").split("|")[0].strip()
                    if not place:
                        place = (await dpage.eval_on_selector("p.tit", "el => el?.textContent || ''")).strip() or "장소미상"
                    print(f"   - [{durl}] {place} 이미지 {len(imgs)}건")
                    for idx, it in enumerate(imgs, 1):
                        src = (it.get("src") or "").strip()
                        if not src: continue
                        abs_img = urljoin(durl, src)
                        try:
                            saved_path = save_image(abs_img, place, idx, referer=durl)
                            if saved_path is None:
                                continue
                            total_saved += 1
                            print("     · 저장:", os.path.basename(saved_path))
                        except Exception as e:
                            print("     · 저장 실패:", abs_img, "→", e)
                except Exception as e:
                    print("   ! 상세 실패:", durl, "→", e)
                    await dpage.screenshot(path="debug_detail_fail.png", full_page=True)
                    with open("debug_detail_fail.html", "w", encoding="utf-8") as f:
                        f.write(await dpage.content())
                finally:
                    await dpage.close()

            # 4) 다음 페이지로 이동
            #    - data-page-number 기반 클릭, 또는 '다음' 버튼 클릭
            #    - 이미 방문한 index면 루프 종료
            visited_key = current_idx or f"turn-{page_turns}"
            if visited_key in visited_pages:
                print(" - 같은 페이지 재탐지 → 종료")
                break
            visited_pages.add(visited_key)

            # 다음 버튼이 비활성/미노출이면 종료
            has_next = await page.locator("a.btn_next").is_visible()
            if not has_next:
                print(" - 다음 버튼 없음 → 종료")
                break

            # 다음 클릭 후 목록 대기
            try:
                await page.click("a.btn_next")
                await page.wait_for_selector("ul.information li a.link_box", timeout=20000)
                time.sleep(0.1)
            except Exception as e:
                print(" - 다음 페이지 이동 실패:", e)
                await page.screenshot(path=f"debug_next_fail_{page_turns}.png", full_page=True)
                with open(f"debug_next_fail_{page_turns}.html", "w", encoding="utf-8") as f:
                    f.write(await page.content())
                break

            # 안전장치: 너무 많이 돌면 종료
            if page_turns >= 30:
                print(" - 안전 종료(30페이지 한도)")
                break

        await browser.close()
    print(f"\n완료: 총 {total_saved}개 이미지 저장 → {os.path.abspath(SAVE_DIR)}")

if __name__ == "__main__":
    asyncio.run(crawl())
