# src/downloader.py
import requests
import concurrent.futures
from typing import List, Dict, Optional, Tuple


def download_content(url: str, timeout: int = 30, retries: int = 3) -> Tuple[Optional[str], int]:
    """下载单个 URL 内容

    Args:
        url: 订阅 URL
        timeout: 超时时间（秒）
        retries: 重试次数

    Returns:
        (内容字符串, 规则数量)，失败返回 (None, 0)
    """
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'AdGuardMerger/1.0'
            })
            response.raise_for_status()
            content = response.text
            # 统计非空非注释行数
            count = len([line for line in content.split('\n')
                        if line.strip() and not line.strip().startswith('!')])
            return content, count
        except Exception as e:
            if attempt == retries - 1:
                print(f"Failed to download {url} after {retries} attempts: {e}")
                return None, 0
            continue
    return None, 0


def download_all(sources: List[Dict]) -> List[Dict]:
    """并行下载多个订阅源

    Args:
        sources: 订阅源列表，每项包含 name 和 url

    Returns:
        下载结果列表，每项包含 name, url, content, count
    """
    results = []

    def download_one(source: Dict) -> Dict:
        url = source['url']
        name = source['name']
        content, count = download_content(url)
        return {
            'name': name,
            'url': url,
            'content': content,
            'count': count,
            'success': content is not None
        }

    # 使用线程池并行下载
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(download_one, source) for source in sources]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    return results
