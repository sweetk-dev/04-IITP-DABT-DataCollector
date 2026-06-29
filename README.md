# DataCollector — 장애인 자립생활 지원 학습용 데이터 수집·생성 모듈

장애인 고용·교육·행사 도메인의 비정형 데이터(이미지/텍스트)를 수집하여 표준
CSV 로 정규화하고, 이미지로 내려받아 학습용 데이터셋으로 정리하는 도구입니다.
각 단계는 독립 실행 가능한 CLI 유틸이며, 앞 단계의 출력 파일이 다음 단계의
입력이 되도록 느슨하게 결합됩니다.

```
collect_list.py  ->  downloader.py  ->  label_assist.py  ->  dedup.py  ->  split_manifest.py
 (목록 수집)          (이미지 저장)       (라벨 정규화)        (중복 검사)     (학습셋 분할)
```

표준 입력 CSV 규격(모든 단계 공통):

- 헤더(대소문자 정확): `No,Type,Title,Img-link`
- 인코딩: UTF-8 (BOM 허용) / 줄바꿈: CRLF·LF 모두 허용
- `Img-link` 는 한 셀에 복수 URL 가능(개행·탭·콤마·세미콜론·공백 구분), `data:image/...;base64,...` Data URL 지원

## 요구 사항

- Python 3.9+
- 외부 의존성은 다운로드 단계에서만 사용: `requests`, `python-dotenv`
  (수집 계층과 보강 모듈 3종은 표준 라이브러리만 사용)

```bash
pip install -r requirements.txt
```

## 환경 설정

`env.sample` 을 `.env` 로 복사하고 값을 채웁니다.

```bash
cp env.sample .env
```

| 변수 | 설명 |
|------|------|
| `LOG_LEVEL` | 로그 레벨 (예: INFO) |
| `ROOT_DIR` | 이미지가 저장될 루트 경로 (하위에 `YYYY-MM-DD/` 생성) |
| `THREADS` | 병렬 다운로드 스레드 수 (예: 8) |
| `URL_CSV_PATH` | 입력 CSV 의 전체 경로 |
| `HEAD_CHECK` / `VERIFY_SSL` / `REQUEST_HEADERS_JSON` | 다운로드 옵션 (선택) |
| `SOURCE` | 수집 계층 기본 소스 키 (CLI `--source` 가 우선) |
| `SPLIT_RATIO` / `SPLIT_SEED` | 분할 비율·시드 (선택, split_manifest) |

## 1) 목록 수집 — `collect_list.py`

소스 어댑터를 선택해 표준 `No,Type,Title,Img-link` CSV 를 생성합니다.
소스 선택 우선순위: `--source` > `SOURCE` 환경변수 > 기본값(`SAMPLE`).

```bash
# 등록된 소스 확인
python collect_list.py --list-sources

# 참조 어댑터(SAMPLE): 내장 목 데이터로 즉시 동작
python collect_list.py --source SAMPLE --out out/collected.csv

# 참조 어댑터(SAMPLE): 로컬 파일 정규화
python collect_list.py --source SAMPLE --input insample/sample_t2.csv --out out/collected.csv
```

소스 어댑터 구조(`collectors/`):

- `SAMPLE` (`FileImportCollector`) — 로컬 파일/목 데이터를 표준 CSV 로 정규화하는 동작하는 참조 어댑터.
- `DB` / `CRAWL` / `API` — 설계상 등록된 자리표시자(파트너 DB 연계·외부 사이트·공개 API). 접속정보·키·권리 검토가 필요하여 본 패키지에는 미구현(`collectors/stubs.py`).

신규 소스 추가 = `BaseListCollector` 를 상속한 어댑터 1개 + `collectors/registry.py` 에 항목 1줄. 기존 코드는 수정하지 않습니다.

## 2) 이미지 다운로드 — `downloader.py`

표준 CSV 의 `Img-link` 를 병렬로 내려받아 `ROOT_DIR/YYYY-MM-DD/` 에 저장합니다.

```bash
python downloader.py
```

- 파일명: `No.Type-Title_ yyyy_mm_dd_hh_mm.<ext>` (Windows 안전 정규화)
- 확장자 없는 URL 은 `Content-Type` 헤더로 판별
- 실패행은 입력 CSV 옆에 `<csv_basename>_errorRow.csv` 로 기록
- 실패 사유 집계: `python analyze_errors.py <...>_errorRow.csv`

## 3) 라벨 정규화 — `label_assist.py`

수기 `Type` 의 표기 편차를 고정 카테고리 체계로 정규화·검증하고, 분류 결과가
기존 `Type` 과 다르면 검토 플래그(`needs_review`)를 답니다. 카테고리별 분포
통계도 산출합니다.

```bash
python label_assist.py out/collected.csv --out-dir out
```

출력: `*_labeled.csv`(원본 + `inferred_category`, `domain`, `match_confidence`, `needs_review`), `*_label_stats.csv` / `*_label_stats.json`.

카테고리 체계(1단계 고용 + 2단계 문화·관광 확대 대비):

- 고용: 일자리/채용, 교육, 행사, 직무/생산품
- 문화·관광: 무장애 관광지, 편의시설, 이동시설/이동경로, 숙박/음식 접근성
- 기타/미분류(룰 미스 시 `needs_review`)

## 4) 중복 이미지 검사 — `dedup.py`

내용 기반 해시로 진짜 중복을 식별합니다(파일명이 달라도 내용이 같으면 중복).
빠른 MD5 로 후보를 묶고 동일 MD5 만 SHA256 으로 재확인합니다. 기본은 리포트만
생성하고, `--apply` 옵션을 줄 때만 실제 삭제합니다.

```bash
python dedup.py ROOT_DIR/2025-08-14 --out out/dedup_report.csv      # 리포트만
python dedup.py ROOT_DIR/2025-08-14 --out out/dedup_report.csv --apply  # 실제 삭제
```

## 5) 데이터셋 분할 매니페스트 — `split_manifest.py`

라벨드 CSV(또는 이미지 디렉토리)를 카테고리별로 층화하여 train/val/test 로
분할합니다. 시드를 고정·기록하여 재현 가능합니다.

```bash
python split_manifest.py out/collected_labeled.csv --ratio 8:1:1 --seed 42 --out-dir out
```

출력: `dataset_manifest.csv` / `dataset_manifest.json`(경로·카테고리·split + 분할별·카테고리별 요약).

## 테스트

표준 라이브러리 `unittest` 기반입니다(추가 의존성 없음).

```bash
python -m unittest discover -s tests
```

## 입력 데이터 규격 주의

- 파일은 `.csv` 여야 합니다.
- 헤더는 정확히 `No,Type,Title,Img-link` (대소문자 구분).
- 인코딩은 UTF-8 (BOM 허용).
