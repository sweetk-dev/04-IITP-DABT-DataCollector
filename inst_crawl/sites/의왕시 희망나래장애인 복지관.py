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

def crawl_uiwang_nare():
    """의왕시 희망나래장애인복지관 사이트 크롤링"""
    base_url = "https://uwnare.or.kr"
    main_url = "https://uwnare.or.kr/page/0301.php"
    
    # 다운로드 폴더 생성
    download_folder = "uiwang_nare_dl"
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    
    print("의왕시 희망나래장애인복지관 크롤링 시작...")
    
    # 페이지네이션 설정
    max_pages = 21  # 테스트를 위해 최대 5페이지까지만 처리
    downloaded_count = 0
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    for page_num in range(1, max_pages + 1):
        try:
            # 페이지별 URL 생성
            page_url = f"{main_url}?Page={page_num}&Year=&Month=&Day=&SearchKey=&Key=&Kind=0301&Code=03&Category=%EC%A0%84%EC%B2%B4&StageNum=none"
            print(f"\n=== 페이지 {page_num} 처리 중 ===")
            print(f"URL: {page_url}")
            
            # 페이지 접속
            response = requests.get(page_url, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 게시글 목록 찾기
            blog_observe = soup.find('div', class_='blog_observe')
            if not blog_observe:
                print(f"페이지 {page_num}에서 게시글 목록을 찾을 수 없습니다.")
                continue
            
            # 게시글 링크들 찾기
            links = blog_observe.find_all('a')
            print(f"페이지 {page_num}에서 {len(links)}개의 게시글을 찾았습니다.")
            
            if len(links) == 0:
                print(f"페이지 {page_num}에 게시글이 없습니다. 크롤링 종료.")
                break
            
            # 각 게시글 처리
            for i, link in enumerate(links, 1):
                try:
                    href = link.get('href')
                    title = link.get('title', link.get_text().strip())
                
                    if not href or not title:
                        continue
                
                    # 상대 URL을 절대 URL로 변환
                    full_url = urljoin(base_url, href)
                
                    print(f"\n[{i}/{len(links)}] 처리 중: {title}")
                
                    # 첨부파일 존재 여부 확인
                    parent_li = link.find_parent('li', class_='td')
                    has_attachment = False
                    if parent_li:
                        file_div = parent_li.find('div', class_='file')
                        if file_div and file_div.get_text().strip() == '첨부파일':
                            has_attachment = True
                
                    if has_attachment:
                        print("  - 첨부파일이 있는 게시글입니다.")
                    
                        # 게시글 상세 페이지 접속
                        article_response = requests.get(full_url, headers=headers)
                        article_response.raise_for_status()
                        article_soup = BeautifulSoup(article_response.content, 'html.parser')
                    
                        # 첨부파일 영역 찾기 - 여러 방법으로 시도
                        blog_file = article_soup.find('div', class_='blog_file')
                        if blog_file:
                            print("  - blog_file 영역을 찾았습니다.")
                        
                            # 모든 링크 검색
                            all_links = blog_file.find_all('a')
                            print(f"  - 총 {len(all_links)}개의 링크를 찾았습니다.")
                        
                            for j, file_link in enumerate(all_links, 1):
                                file_href = file_link.get('href')
                                file_text = file_link.get_text().strip()
                            
                                print(f"    링크 {j}: {file_text} -> {file_href}")
                            
                                if file_href:
                                    # 다양한 첨부파일 링크 패턴 확인
                                    if ('download.php' in file_href or 
                                        'fileview' in file_href or 
                                        's_board' in file_href or
                                        file_href.startswith('#') or
                                        'window.open' in file_href):
                                    
                                        # onclick 이벤트에서 URL 추출 시도
                                        onclick = file_link.get('onclick')
                                        if onclick and 'window.open' in onclick:
                                            # window.open() 함수에서 URL 추출
                                            import re
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
                                    
                                        # 파일명 추출
                                        if file_text:
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
                                        print(f"    첨부파일로 보이지 않는 링크입니다: {file_href}")
                        else:
                            print("  - blog_file 영역을 찾을 수 없습니다.")
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
    crawl_uiwang_nare()
