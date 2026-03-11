import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Union

from .semantic.deduplicator import SemanticDeduplicator

# 本地/阻止 IP 集合（用于识别 hosts 风格阻断规则）
BLOCK_IPS = {
    '0.0.0.0', '127.0.0.1', '::1', '0:0:0:0:0:0:0:0:1',
    '127.0.1.1', '255.255.255.255'
}

# Hosts 风格规则匹配模式
HOSTS_PATTERN = re.compile(
    r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
    r'\[?([0-9a-fA-F:]+)\]?)\s+'              # IPv6
    r'(\S+)'                                    # 域名
)


def _is_blocking_hosts(line: str) -> bool:
    """检查是否为屏蔽类型的 hosts 规则（指向阻止 IP）"""
    match = HOSTS_PATTERN.match(line)
    if not match:
        return True  # 不是 hosts 格式，保留
    ip = match.group(1)
    return ip in BLOCK_IPS


def parse_rules(content: str) -> List[str]:
    if not content:
        return []
    rules = []
    seen = set()
    skipped_non_blocking = 0
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        # 过滤非屏蔽 hosts 规则（如指向真实 IP 的 mtalk.google.com）
        if not _is_blocking_hosts(line):
            skipped_non_blocking += 1
            continue
        if line not in seen:
            seen.add(line)
            rules.append(line)
    if skipped_non_blocking > 0:
        print(f"    Filtered {skipped_non_blocking} non-blocking hosts")
    return rules


def merge_rules(sources: List[Dict]) -> Tuple[List[str], List[Dict]]:
    all_rules = []
    seen = set()
    source_stats = []
    for source in sources:
        if not source['success'] or not source['content']:
            source_stats.append({
                'name': source['name'],
                'total': 0,
                'count': 0,
                'percentage': 0.0,
                'url': source['url']
            })
            continue
        rules = parse_rules(source['content'])
        total_count = len(rules)
        actual_count = 0
        for rule in rules:
            if rule not in seen:
                seen.add(rule)
                all_rules.append(rule)
                actual_count += 1
        percentage = (actual_count / total_count * 100) if total_count > 0 else 0.0
        source_stats.append({
            'name': source['name'],
            'total': total_count,
            'count': actual_count,
            'percentage': percentage,
            'url': source['url']
        })
    return all_rules, source_stats


def generate_header(title: str, total: int, source_stats: List[Dict]) -> str:
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"! Title: {title}",
        f"! Updated: {timestamp}",
        f"! Total: {total} rules",
        "! Sources:",
    ]
    for stat in source_stats:
        total_rules = stat.get('total', stat['count'])
        used_rules = stat['count']
        percentage = stat.get('percentage', 100.0)
        lines.append(f"!   - {stat['name']}: {total_rules} total, {used_rules} used ({percentage:.1f}%) - {stat['url']}")
    lines.append("!")
    lines.append("")
    return '\n'.join(lines)


def write_output(filepath: Union[Path, str], header: str, rules: List[str]) -> None:
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('\n'.join(rules))
        if rules:
            f.write('\n')


def merge_rules_semantic(sources: List[Dict]) -> Tuple[List[str], List[Dict]]:
    """
    使用语义去重合并规则

    替代原有的简单文本去重，支持识别语法不同但功能相同的规则
    """
    deduplicator = SemanticDeduplicator()
    all_rules = []
    source_stats = []

    for source in sources:
        if not source['success'] or not source['content']:
            source_stats.append({
                'name': source['name'],
                'total': 0,
                'count': 0,
                'percentage': 0.0,
                'url': source['url']
            })
            continue

        # 解析规则列表
        rules = parse_rules(source['content'])
        total_count = len(rules)

        # 使用语义去重处理
        kept_rules = deduplicator.process_batch(rules)
        actual_count = len(kept_rules)

        all_rules.extend(kept_rules)

        percentage = (actual_count / total_count * 100) if total_count > 0 else 0.0
        source_stats.append({
            'name': source['name'],
            'total': total_count,
            'count': actual_count,
            'percentage': percentage,
            'url': source['url']
        })

    # 获取去重统计
    dedup_stats = deduplicator.get_stats()
    print(f"  Semantic dedup: {dedup_stats['total']} processed, "
          f"{dedup_stats['kept']} kept, {dedup_stats['deduped']} deduped, "
          f"{dedup_stats['replaced']} replaced")

    return all_rules, source_stats
