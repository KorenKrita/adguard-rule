from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Union


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
            continue
        rules = parse_rules(source['content'])
        actual_count = 0
        for rule in rules:
            if rule not in seen:
                seen.add(rule)
                all_rules.append(rule)
                actual_count += 1
        source_stats.append({
            'name': source['name'],
            'count': actual_count,
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
        lines.append(f"!   - {stat['name']}: {stat['count']} rules ({stat['url']})")
    lines.append("!")
    lines.append("")
    return '\n'.join(lines)


def write_output(filepath: Union[Path, str], header: str, rules: List[str]) -> None:
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(header)
        f.write('\n'.join(rules))
        if rules:
            f.write('\n')
