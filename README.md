# Active Chrome Browser Extensions Tracker

[mthcht/awesome-lists](https://github.com/mthcht/awesome-lists/blob/main/Lists/Browser%20Extensions/browser_extensions_list.csv) 저장소의 브라우저 확장 프로그램 데이터 중 아래 **필터링 조건을 충족하는 활성 확장 프로그램 데이터만 선별**하여 보관하고, **GitHub Actions로 매일 자동 동기화**하는 저장소입니다.

---

## 🎯 필터링 기준

1. **`metadata_category`가 `PROXY/VPN`인 데이터 제외**
2. **`metadata_link`가 `NULL`이거나 비어있는 데이터 제외**
3. **`metadata_link`가 단순 크롬 웹스토어 주소(`https://chromewebstore.google.com/detail/~`)인 데이터 제외**
   *(악성 분석 보고서/사고 링크 등 실질적 근거가 있는 데이터만 포함)*
4. **`browser_extension_id` 기준으로 현재 크롬 웹 스토어에 존재하지 않는(삭제/차단된) 데이터 제외**

---

## 📋 저장 데이터 필드 (`browser_extensions_active.csv`)

| 필드명 | 설명 |
|---|---|
| `browser_extension` | 브라우저 확장 프로그램 명칭 |
| `browser_extension_id` | 확장 프로그램 32자리 고유 ID |
| `metadata_category` | 카테고리 정보 (malware, scam, PUP 등) |
| `metadata_link` | 출처 분석 / 보고서 링크 |

---

## 🤖 GitHub Actions 매일 자동 동기화 (`.github/workflows/daily_sync.yml`)

- **실행 주기**: **매일 1회** (UTC 00:00 / 한국 시간 오전 9:00)
- **동작 방식**:
  1. 원본 CSV를 자동으로 새로 가져옵니다.
  2. 위 필터링 조건을 충족하는 데이터만 크롬 웹 스토어에서 실시간 재검증합니다.
  3. 원본이 업데이트되었거나 크롬 웹 스토어 상태가 변경되어 diff가 발생하면, GitHub Actions 봇이 자동으로 본 저장소에 커밋 및 푸시합니다.
  4. GitHub 웹의 **Actions** 탭에서 **Run workflow**를 눌러 언제든 수동으로 즉시 동기화할 수도 있습니다.

---

## 🛠️ 수동 실행 및 개인 GitHub 동기화

### 1. 로컬에서 즉시 필터링 실행
```bash
python sync_extensions.py
```
- 실행 후 조건이 모두 충족된 최신 `browser_extensions_active.csv` 파일이 생성됩니다.

### 2. 내 개인 GitHub 저장소에 업로드
로컬에 Git이 설치되어 있지 않아도 GitHub Personal Access Token(PAT)만 있으면 업로드할 수 있습니다:
```bash
python push_to_github.py
```
- 실행 후 터미널 안내에 따라 GitHub Token 및 대상 저장소(`아이디/저장소명`)를 입력하면 파일들이 자동 푸시됩니다.
