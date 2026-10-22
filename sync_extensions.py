import sys
import os
import io
import re
import csv
import ssl
import time
import urllib.request
import concurrent.futures

# 콘솔 출력 UTF-8 인코딩 설정
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

ctx = ssl._create_unverified_context()

SOURCE_CSV_URL = "https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/Browser%20Extensions/browser_extensions_list.csv"
OUTPUT_CSV_PATH = "browser_extensions_active.csv"

TARGET_COLUMNS = [
    'browser_extension',
    'browser_extension_id',
    'metadata_category',
    'metadata_link'
]

def is_chrome_store_url(url: str) -> bool:
    """
    metadata_link가 단순 크롬 웹스토어 주소(https://chromewebstore.google.com/detail/~ 등)인지 판별
    """
    url_lower = url.strip().lower()
    return (
        'chromewebstore.google.com/detail' in url_lower or 
        'chrome.google.com/webstore/detail' in url_lower
    )

def fetch_source_rows():
    print(f"[*] 원본 CSV 다운로드 중: {SOURCE_CSV_URL}")
    req = urllib.request.Request(SOURCE_CSV_URL, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
        content = resp.read().decode('utf-8', errors='ignore')
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)

def check_webstore_active(row):
    """
    크롬 웹 스토어에 실제 존재 및 설치 가능한지 확인
    """
    ext_id = (row.get('browser_extension_id') or row.get('brwoser_extension_id') or '').strip().lower()
    url = f"https://chromewebstore.google.com/detail/{ext_id}?hl=en"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9'
    }
    
    max_retries = 2
    for _ in range(max_retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, context=ctx, timeout=8) as resp:
                body = resp.read().decode('utf-8', errors='ignore')
                canonical_match = re.search(r'<link\s+rel="canonical"\s+href="(.*?)"', body)
                canonical = canonical_match.group(1).strip() if canonical_match else ""
                
                title_match = re.search(r'<title>(.*?)</title>', body)
                raw_title = title_match.group(1).strip() if title_match else ""
                clean_title = re.sub(r'\s*-\s*Chrome Web Store$', '', raw_title, flags=re.IGNORECASE).strip()
                
                # 웹 스토어 상세 페이지가 유효한지 확인
                if canonical and '/detail/' in canonical and clean_title and clean_title != "Chrome Web Store":
                    clean_row = {
                        'browser_extension': row.get('browser_extension') or row.get('brwoser_extension') or clean_title,
                        'browser_extension_id': ext_id,
                        'metadata_category': row.get('metadata_category', '').strip(),
                        'metadata_link': row.get('metadata_link', '').strip()
                    }
                    return clean_row
                return None
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            time.sleep(1)
        except Exception:
            time.sleep(0.5)
            
    return None

def main():
    rows = fetch_source_rows()
    print(f"[*] 원본 CSV 전체 행: {len(rows)}개")
    
    # 필터링 조건:
    # 1. 'metadata_category'가 'PROXY/VPN' 제외
    # 2. 'metadata_link' NULL/빈값 제외 및 'chromewebstore.google.com/detail/~' 단순 링크 제외
    # 3. 유효한 32자리 크롬 확장 프로그램 ID 대상
    candidates = []
    seen_ids = set()
    
    for r in rows:
        cat = r.get('metadata_category', '').strip()
        link = r.get('metadata_link', '').strip()
        eid = (r.get('browser_extension_id') or r.get('brwoser_extension_id') or '').strip().lower()
        
        # 조건 1: metadata_category가 PROXY/VPN 제외
        if cat.upper() == 'PROXY/VPN':
            continue
            
        # 조건 2: metadata_link가 NULL이거나 비어있는 경우 제외
        if not link or link.upper() == 'NULL':
            continue
            
        # 조건 2-1: metadata_link가 단순 크롬 웹스토어 주소인 경우 제외 (악성 근거 링크만 포함)
        if is_chrome_store_url(link):
            continue
            
        # 유효한 크롬 확장 프로그램 ID(32자리 영문 소문자 a-p) 확인 및 중복 제거
        if len(eid) != 32 or not re.fullmatch(r'[a-p]{32}', eid):
            continue
            
        if eid in seen_ids:
            continue
            
        seen_ids.add(eid)
        candidates.append(r)
        
    print(f"[*] 조건 1 & 2 충족 후보: {len(candidates)}개 (스토어 확인 대상)")
    
    # 조건 3. 크롬 웹 스토어 실제 존재 여부 병렬 검증
    active_results = []
    start_time = time.time()
    total = len(candidates)
    completed = 0
    
    print(f"[*] 크롬 웹 스토어 실시간 검증 시작 (동시 15스레드)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        future_to_row = {executor.submit(check_webstore_active, row): row for row in candidates}
        for future in concurrent.futures.as_completed(future_to_row):
            completed += 1
            res = future.result()
            if res:
                active_results.append(res)
            if completed % 200 == 0 or completed == total:
                elapsed = time.time() - start_time
                print(f"    - 진행률: {completed}/{total} 완료 ({len(active_results)}개 활성 확인됨) [{elapsed:.1f}초]")
                
    print(f"[+] 모든 조건 충족된 최종 활성 확장 프로그램: {len(active_results)}개")
    
    # ID 기준으로 정렬하여 git diff 최소화
    active_results.sort(key=lambda x: x['browser_extension_id'])
    
    # CSV 저장 (UTF-8-BOM)
    with open(OUTPUT_CSV_PATH, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=TARGET_COLUMNS)
        writer.writeheader()
        writer.writerows(active_results)
        
    print(f"[+] 최종 결과 파일 저장 완료: {OUTPUT_CSV_PATH}")

if __name__ == "__main__":
    main()
