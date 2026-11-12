# 기관 자료실 정기 수집 — `inst_crawl/`

장애인 복지관·가족지원센터·체육회·권익옹호기관·공공기관 자료실에 올라오는 첨부 문서와,
무장애 여행 안내 사이트의 사진을 기관별 수집기로 정기적으로 받는다(v1.4.0).
2025년에 기초 데이터 수집에 쓴 기관별 수집기를 그대로 묶어 분기마다 다시 돌리고,
지난번에 없던 파일만 골라 목록으로 남긴다.

```
sites/<기관>.py   →   작업 폴더(<work>/<기관>/)   →   새 파일 고르기   →   <out>/<기간>/
 (기관별 수집기)       (받은 파일이 쌓임)            (잡파일·중복 제외)    manifest.csv · summary.json
```

## 대상

`sites.json` 에 수집기마다 구분·분류·사용 여부를 적는다.

| 구분 | 남기는 파일 | 수집기 |
|---|---|---|
| 기초 | 문서(pdf·hwp·hwpx·doc(x)·xls(x)·ppt(x)·zip·alz·txt·csv), 1KB 이상 | 기관 자료실 21개(사용 18) |
| 이동권 | 사진(jpg·png·gif·webp·bmp), 10KB 이상 | 무장애 여행 3개(사용 1) |

분류는 2025년 제출 분류를 그대로 쓴다 — 기관 자료실은 기관 11군, 무장애 여행 사진은 장소별 유형(관람_시설·관람_자연·체험·활동·카페 등, 아래 「새 파일 고르기」).
`enabled: false` 는 사이트 구조가 바뀌어 지금 수집기로는 받지 못하는 곳이다(`note` 에 이유). 고치면 `true` 로 돌린다.

## 실행

```bash
pip install -r requirements.txt -r inst_crawl/requirements.txt

# 분기 정기 실행 (cron 등에서)
scripts/run_inst_crawl.sh

# 직접 실행
python -m inst_crawl.runner --work out/inst_work --out out/inst
python -m inst_crawl.runner --work out/inst_work --out out/inst --only 한국장애인개발원
python -m inst_crawl.runner --work out/inst_work --out out/inst --no-run      # 받아 둔 파일만 다시 정리
python -m inst_crawl.runner ... --seed-hashes base_sha256.txt                 # 이전에 제출·보관한 파일 해시 더하기(처음 한 번)
```

| 환경변수 | 기본값 | 의미 |
|---|---|---|
| `INST_WORK_DIR` | `out/inst_work` | 수집기 작업 폴더. 지우지 않으면 다음 실행 때 이미 받은 첨부는 건너뛴다 |
| `INST_OUT_DIR` | `out/inst` | 기간별 새 파일·목록 |
| `INST_PARALLEL` | `4` | 동시에 돌리는 수집기 수 |
| `INST_TIMEOUT` | `14400` | 수집기 1개당 최대 실행 초 |
| `INST_PYTHON` | 실행 중인 python | 수집기를 돌릴 python |

사진 수집기(경기관광공사)는 Playwright(Chromium)를 쓴다 — `playwright install chromium`. 꺼 둔 교보·한국관광공사 수집기는 selenium·Chrome.

## 새 파일 고르기

1. 작업 폴더의 모든 파일을 본다. 수집기 코드·실행 로그·`download_log.csv`·오류 화면 캡처(`debug_*`)는 대상이 아니다.
2. 구분별 확장자·최소 크기에 맞지 않으면 거른다(아이콘·썸네일·빈 파일).
3. 내용 해시(SHA-256)가 원장 `<work>/_ledger.tsv` 에 있으면 이미 받은 파일로 보고 건너뛴다.
   원장에는 지난 실행에서 고른 파일과 `--seed-hashes` 로 넣은 기준 해시가 쌓인다.
4. 처음 보는 파일만 `<out>/<기간>/<구분>/<분류>/<수집기>/<원래 상대경로>` 로 복사한다.

사진 수집기는 분류를 장소 단위로 정한다. `sites.json` 의 `place_types` 가 가리키는 CSV(`장소,분류,비고`)에서 파일 이름의 장소명(`<장소>_<번호>.jpg`, 공백 무시)을 찾아 분류를 붙이고, 표에 없는 새 장소는 `미분류` 로 받은 뒤 실행 로그와 `summary.json` 의 `unknown_places` 에 장소명을 남긴다. 새 장소의 분류를 정해 CSV 에 한 줄 더하고 `--no-run` 으로 다시 정리하면 된다(이미 고른 파일은 기간 폴더에서 옮겨야 한다).

`place_types/경기관광공사 무장애여행정보.csv` — 2025년 제출 때 장소별로 나눈 분류(199곳 — 2025 경기관광 사진 198곳 + 다른 출처에서 분류된 1곳). 한 장소가 두 분류에 걸쳐 있던 2곳은 비고에 적었다.

기간은 실행일의 분기(`2026Q4`)다. 같은 분기에 다시 돌리면 같은 기간 폴더에 이어서 쌓인다.

## 결과

- `manifest.csv` — `기간, 구분, 분류, 수집기, 파일, 크기, sha256, 수집일시, 자동수집`
- `summary.json` — 실행마다 수집기별 종료 코드·소요 초·본 파일·새 파일·중복·거른 수
