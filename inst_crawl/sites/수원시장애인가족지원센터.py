import requests
from bs4 import BeautifulSoup
import os
import time
import urllib.parse
from urllib.parse import urljoin, urlparse
import re

def download_file(url, folder_path, filename):
    """파일을 다운로드하는 함수"""
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        
        # 파일 경로 생성
        file_path = os.path.join(folder_path, filename)
        
        # 파일 저장
        with open(file_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        
        print(f"다운로드 완료: {filename}")
        return True
    except Exception as e:
        print(f"다운로드 실패: {filename} - {e}")
        return False

def get_file_extension(url):
    """URL에서 파일 확장자를 추출하는 함수"""
    parsed_url = urlparse(url)
    path = parsed_url.path
    filename = os.path.basename(path)
    
    # 파일 확장자 추출
    if '.' in filename:
        return os.path.splitext(filename)[1]
    else:
        # URL에 확장자가 없는 경우 기본값
        return '.html'

def clean_filename(filename):
    """파일명에서 특수문자 제거"""
    # 파일명에 사용할 수 없는 문자들을 언더스코어로 변경
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # 공백을 언더스코어로 변경
    filename = re.sub(r'\s+', '_', filename)
    return filename

def crawl_suwon_family():
    """수원시장애인가족지원센터 사이트 크롤링"""
    base_url = "http://swfamily.or.kr"
    main_url = "http://swfamily.or.kr/page/0402.php"
    
    # 다운로드 폴더 생성
    download_folder = "suwon_family_dl"
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
    print("수원시장애인가족지원센터 크롤링 시작...")
    
    # 페이지네이션 설정
    max_pages = 14  # 테스트를 위해 최대 5페이지까지만 처리
    downloaded_count = 0
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for page_num in range(1, max_pages + 1):
        try:
            # 페이지별 URL 생성
            page_url = f"{main_url}?Page={page_num}"
            print(f"\n=== 페이지 {page_num} 처리 중 ===")
            print(f"URL: {page_url}")
            
            # 페이지 접속
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 게시글 목록 찾기 (table 구조)
            # td class="l" 안의 링크들을 찾기
            title_cells = soup.find_all('td', class_='l')
            if not title_cells:
                print(f"페이지 {page_num}에서 게시글 목록을 찾을 수 없습니다.")
                continue
            
            print(f"페이지 {page_num}에서 {len(title_cells)}개의 게시글을 찾았습니다.")
            
            if len(title_cells) == 0:
                print(f"페이지 {page_num}에 게시글이 없습니다. 크롤링 종료.")
                break
            
            # 각 게시글 처리
            for i, cell in enumerate(title_cells, 1):
                try:
                    # 제목 링크 찾기
                    title_link = cell.find('div', class_='title').find('a')
                    if not title_link:
                        continue
                    
                    href = title_link.get('href')
                    title = title_link.get('title', title_link.get_text().strip())
                    
                    if not href or not title:
                        continue
                    
                    # 첨부파일 존재 여부 확인
                    file_div = cell.find('div', class_='file')
                    has_attachment = False
                    if file_div and file_div.get_text().strip() == '첨부파일':
                        has_attachment = True
                    
                    if not has_attachment:
                        print(f"  [{i}/{len(title_cells)}] 첨부파일 없음: {title}")
                        continue
                    
                    print(f"\n[{i}/{len(title_cells)}] 첨부파일 있는 게시글 처리 중: {title}")
                    
                    # 상대 URL을 절대 URL로 변환
                    if href.startswith('?'):
                        full_url = base_url + "/page/0402.php" + href
                    else:
                        full_url = urljoin(base_url, href)
                    
                    # 게시글 상세 페이지 접속
                    article_response = requests.get(full_url, headers=headers)
                    article_response.raise_for_status()
                    article_soup = BeautifulSoup(article_response.content, 'html.parser')
                    
                    # 첨부파일 영역 찾기
                    filelists_div = article_soup.find('div', class_='filelists')
                    if filelists_div:
                        print("  - 첨부파일 영역을 찾았습니다.")
                        
                        # fileview div 안의 링크들 찾기
                        fileview_div = filelists_div.find('div', id='fileview')
                        if fileview_div:
                            file_links = fileview_div.find_all('a')
                            print(f"  - 총 {len(file_links)}개의 첨부파일을 찾았습니다.")
                            
                            for j, file_link in enumerate(file_links, 1):
                                file_href = file_link.get('href')
                                file_text = file_link.get_text().strip()
                                
                                print(f"    첨부파일 {j}: {file_text}")
                                
                                if file_href and file_text:
                                    # onclick 이벤트에서 URL 추출 시도
                                    onclick = file_link.get('onclick')
                                    if onclick and 'window.open' in onclick:
                                        # window.open() 함수에서 URL 추출
                                        match = re.search(r"window\.open\('([^']+)'", onclick)
                                        if match:
                                            file_href = match.group(1)
                                            print(f"    onclick에서 URL 추출: {file_href}")
                                    
                                    # 파일 다운로드 URL 생성
                                    if not file_href.startswith('http'):
                                        file_url = urljoin(base_url, file_href)
                                    else:
                                        file_url = file_href
                                    
                                    print(f"    다운로드 URL: {file_url}")
                                    
                                    # 파일 확장자 확인 - 텍스트에서 직접 추출
                                    file_ext = ''
                                    if '.' in file_text:
                                        # 파일명에 확장자가 있는 경우
                                        file_ext = '.' + file_text.split('.')[-1].lower()
                                    else:
                                        # URL에서 확장자 추출 시도
                                        url_ext = get_file_extension(file_url)
                                        if url_ext and url_ext != '.php' and url_ext != '.html':
                                            file_ext = url_ext
                                        else:
                                            file_ext = '.pdf'  # 기본값
                                    
                                    # 파일명 정리
                                    clean_file_name = clean_filename(file_text)
                                    # 이미 확장자가 있으면 추가하지 않음
                                    if not clean_file_name.endswith(file_ext):
                                        clean_file_name += file_ext
                                    
                                    # 파일 다운로드
                                    if download_file(file_url, download_folder, clean_file_name):
                                        downloaded_count += 1
                                    
                                    time.sleep(1)  # 서버 부하 방지
                                else:
                                    print(f"    파일명을 찾을 수 없습니다.")
                        else:
                            print("  - fileview 영역을 찾을 수 없습니다.")
                    else:
                        print("  - 첨부파일 영역을 찾을 수 없습니다.")
                        # 전체 페이지에서 download.php 링크 검색
                        all_download_links = article_soup.find_all('a', href=lambda x: x and 'download.php' in x)
                        print(f"  - 전체 페이지에서 {len(all_download_links)}개의 download.php 링크를 찾았습니다.")
                        
                        for download_link in all_download_links:
                            file_href = download_link.get('href')
                            file_text = download_link.get_text().strip()
                            
                            if file_href and file_text:
                                file_url = urljoin(base_url, file_href)
                                print(f"    다운로드 URL: {file_url}")
                                
                                # 파일 확장자 확인 - 텍스트에서 직접 추출
                                file_ext = ''
                                if '.' in file_text:
                                    # 파일명에 확장자가 있는 경우
                                    file_ext = '.' + file_text.split('.')[-1].lower()
                                else:
                                    # URL에서 확장자 추출 시도
                                    url_ext = get_file_extension(file_url)
                                    if url_ext and url_ext != '.php' and url_ext != '.html':
                                        file_ext = url_ext
                                    else:
                                        file_ext = '.pdf'  # 기본값
                                
                                # 파일명 정리
                                clean_file_name = clean_filename(file_text)
                                # 이미 확장자가 있으면 추가하지 않음
                                if not clean_file_name.endswith(file_ext):
                                    clean_file_name += file_ext
                                
                                # 파일 다운로드
                                if download_file(file_url, download_folder, clean_file_name):
                                    downloaded_count += 1
                                
                                time.sleep(1)  # 서버 부하 방지
                    
                    time.sleep(2)  # 게시글 간 딜레이
                
                except Exception as e:
                    print(f"  - 오류 발생: {e}")
                    continue
            
            # 페이지 간 딜레이
            time.sleep(3)
            
        except Exception as e:
            print(f"페이지 {page_num} 처리 중 오류 발생: {e}")
            continue
    
    print(f"\n크롤링 완료! 총 {downloaded_count}개의 파일을 다운로드했습니다.")
    print(f"다운로드 위치: {os.path.abspath(download_folder)}")

if __name__ == "__main__":
    crawl_suwon_family()
