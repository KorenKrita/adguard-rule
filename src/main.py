#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import List, Dict, Tuple

from src.config import (
    load_config, save_config, sort_urls_by_count,
    get_filter_urls, get_filter_manual_rules,
    get_whitelist_urls, get_whitelist_manual_rules,
    get_dns_urls, get_dns_manual_rules
)
from src.downloader import download_all
from src.merger import merge_rules, generate_header, write_output


def process_rules(
    sources: List[Dict],
    manual_rules: List[str],
    title: str,
    output_path: Path,
    label: str,
) -> List[Dict]:
    """下载、合并、去重并写出规则文件

    Args:
        sources: 订阅源列表（含 name/url）
        manual_rules: 手动配置的规则列表
        title: 输出文件标题
        output_path: 输出文件路径
        label: 用于打印日志的文件名标识

    Returns:
        统计信息列表
    """
    all_rules: List[str] = []
    all_stats: List[Dict] = []

    if sources:
        results = download_all(sources)
        rules, stats = merge_rules(results)
        all_rules.extend(rules)
        all_stats.extend(stats)

    if manual_rules:
        seen = set(all_rules)
        manual_total = len(manual_rules)
        manual_count = 0
        for rule in manual_rules:
            if rule not in seen:
                seen.add(rule)
                all_rules.append(rule)
                manual_count += 1
        if manual_count > 0:
            percentage = (manual_count / manual_total * 100) if manual_total > 0 else 0.0
            all_stats.append({
                'name': 'Manual Rules',
                'total': manual_total,
                'count': manual_count,
                'percentage': percentage,
                'url': 'config.yaml'
            })

    if all_rules:
        header = generate_header(title, len(all_rules), all_stats)
        write_output(output_path, header, all_rules)
        print(f"  -> {len(all_rules)} rules written to {label}")
    else:
        print(f"  -> No sources configured for {label}")

    return all_stats


def main():
    """主程序入口"""
    config_path = Path("config.yaml")

    print("Loading configuration...")
    config = load_config(config_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 1. 处理广告过滤规则
    print("\n[1/3] Processing filter rules...")
    filter_stats = process_rules(
        sources=get_filter_urls(config),
        manual_rules=get_filter_manual_rules(config),
        title="Merged Filter",
        output_path=output_dir / "filter.txt",
        label="output/filter.txt",
    )

    # 2. 处理白名单规则
    print("\n[2/3] Processing whitelist rules...")
    whitelist_stats = process_rules(
        sources=get_whitelist_urls(config),
        manual_rules=get_whitelist_manual_rules(config),
        title="Merged Whitelist",
        output_path=output_dir / "whitelist.txt",
        label="output/whitelist.txt",
    )

    # 3. 处理 DNS 过滤规则
    print("\n[3/3] Processing DNS filter rules...")
    dns_stats = process_rules(
        sources=get_dns_urls(config),
        manual_rules=get_dns_manual_rules(config),
        title="Merged DNS Filter",
        output_path=output_dir / "dns.txt",
        label="output/dns.txt",
    )

    # 4. 根据本次运行统计排序配置并保存
    print("\n[4/4] Optimizing config order...")
    sort_urls_by_count(config, 'filters', filter_stats)
    sort_urls_by_count(config, 'whitelist', whitelist_stats)
    sort_urls_by_count(config, 'dns', dns_stats)

    try:
        save_config(config, config_path)
        print("  -> Config order updated")
    except Exception as e:
        print(f"  -> Failed to save config: {e}")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
