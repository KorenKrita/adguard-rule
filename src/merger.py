from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Union

from .semantic.deduplicator import SemanticDeduplicator


def parse_rules(content: str) -> List[str]:
    if not content:
        return []
    rules = []
    seen = set()
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('!'):
            continue
        if line not in seen:
            seen.add(line)
            rules.append(line)
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
