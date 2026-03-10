#!/usr/bin/env python3
import sys
from pathlib import Path
from typing import List, Dict, Tuple

from src.config import load_config, get_filter_urls, get_filter_manual_rules, get_whitelist_urls, get_whitelist_rules, get_dns_urls
from src.downloader import download_all
from src.merger import merge_rules, generate_header, write_output


def process_rules(
    sources: List[Dict],
    manual_rules: List[str],
    title: str,
    output_path: Path,
    label: str,
) -> None:
    """下载、合并、去重并写出规则文件

    Args:
        sources: 订阅源列表（含 name/url）
        manual_rules: 手动配置的规则列表
        title: 输出文件标题
        output_path: 输出文件路径
        label: 用于打印日志的文件名标识
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
        manual_count = 0
        for rule in manual_rules:
            if rule not in seen:
                seen.add(rule)
                all_rules.append(rule)
                manual_count += 1
        if manual_count > 0:
            all_stats.append({
                'name': 'Manual Rules',
                'count': manual_count,
                'url': 'config.yaml'
            })

    if all_rules:
        header = generate_header(title, len(all_rules), all_stats)
        write_output(output_path, header, all_rules)
        print(f"  -> {len(all_rules)} rules written to {label}")
    else:
        print(f"  -> No sources configured for {label}")


def main():
    """主程序入口"""
    config_path = Path("config.yaml")

    print("Loading configuration...")
    config = load_config(config_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 1. 处理广告过滤规则
    print("\n[1/3] Processing filter rules...")
    process_rules(
        sources=get_filter_urls(config),
        manual_rules=get_filter_manual_rules(config),
        title="Merged Filter",
        output_path=output_dir / "filter.txt",
        label="output/filter.txt",
    )

    # 2. 处理白名单规则
    print("\n[2/3] Processing whitelist rules...")
    process_rules(
        sources=get_whitelist_urls(config),
        manual_rules=get_whitelist_rules(config),
        title="Merged Whitelist",
        output_path=output_dir / "whitelist.txt",
        label="output/whitelist.txt",
    )

    # 3. 处理 DNS 过滤规则
    print("\n[3/3] Processing DNS filter rules...")
    dns_sources = get_dns_urls(config)
    if dns_sources:
        results = download_all(dns_sources)
        rules, stats = merge_rules(results)
        header = generate_header("Merged DNS Filter", len(rules), stats)
        write_output(output_dir / "dns.txt", header, rules)
        print(f"  -> {len(rules)} rules written to output/dns.txt")
    else:
        print("  -> No DNS sources configured")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
