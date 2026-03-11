# src/downloader.py
import requests
import concurrent.futures
from typing import List, Dict, Optional, Tuple


# 本地/阻止 IP 集合（用于识别 hosts 风格阻断规则）
BLOCK_IPS = {
    '0.0.0.0', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1',
    '127.0.1.1', '255.255.255.255'
}


def _is_blocking_hosts(line: str) -> bool:
    """检查是否为屏蔽类型的 hosts 规则（指向阻止 IP）"""
    import re
    hosts_pattern = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
        r'\[?([0-9a-fA-F:]+)\]?)\s+'
        r'(\S+)'
    )
    match = hosts_pattern.match(line)
    if not match:
        return True  # 不是 hosts 格式，保留
    ip = match.group(1)
    return ip in BLOCK_IPS


def _count_rules(content: str) -> int:
    """统计内容中的有效规则数量（与 merger.parse_rules 逻辑一致）

    统计标准：
    - 非空行
    - 非注释行（不以 ! 开头）
    - 非屏蔽类型的 hosts 规则（127.0.0.1, 0.0.0.0, ::1 等）
    """
    count = 0
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        # 过滤非屏蔽 hosts 规则
        if not _is_blocking_hosts(line):
            continue
        count += 1
    return count


def download_content(url: str, timeout: int = 30, retries: int = 3) -> Tuple[Optional[str], int]:
    """下载单个 URL 内容

    Args:
        url: 订阅 URL
        timeout: 超时时间（秒）
        retries: 重试次数

    Returns:
        (内容字符串, 规则数量)，失败返回 (None, 0)
    """
    last_error = None
    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=timeout, headers={
                'User-Agent': 'AdGuardMerger/1.0'
            })
            response.raise_for_status()
            content = response.text
            # 统计有效规则数（与 merger.parse_rules 逻辑一致）
            count = _count_rules(content)
            return content, count
        except Exception as e:
            last_error = e

    print(f"Failed to download {url} after {retries} attempts: {last_error}")
    return None, 0


def download_all(sources: List[Dict]) -> List[Dict]:
    """并行下载多个订阅源，结果顺序与 sources 输入顺序保持一致

    Args:
        sources: 订阅源列表，每项包含 name 和 url

    Returns:
        下载结果列表，每项包含 name, url, content, count，顺序与输入一致
    """
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

    # 使用线程池并行下载，按提交顺序收集结果以保持与 sources 一致的顺序
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(download_one, source) for source in sources]
        results = [future.result() for future in futures]

    return results
