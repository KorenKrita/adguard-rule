#!/usr/bin/env python3
import sys
from pathlib import Path

from src.config import load_config, get_filter_urls, get_filter_manual_rules, get_whitelist_urls, get_whitelist_rules, get_dns_urls
from src.downloader import download_all
from src.merger import merge_rules, generate_header, write_output


def main():
    """主程序入口"""
    config_path = Path("config.yaml")

    print("Loading configuration...")
    config = load_config(config_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 1. 处理广告过滤规则
    print("\n[1/3] Processing filter rules...")
    filter_sources = get_filter_urls(config)
    filter_manual_rules = get_filter_manual_rules(config)

    all_filter_rules = []
    all_filter_stats = []

    if filter_sources:
        results = download_all(filter_sources)
        rules, stats = merge_rules(results)
        all_filter_rules.extend(rules)
        all_filter_stats.extend(stats)

    if filter_manual_rules:
        seen = set(all_filter_rules)
        manual_count = 0
        for rule in filter_manual_rules:
            if rule not in seen:
                seen.add(rule)
                all_filter_rules.append(rule)
                manual_count += 1
        if manual_count > 0:
            all_filter_stats.append({
                'name': 'Manual Rules',
                'count': manual_count,
                'url': 'config.yaml'
            })

    if all_filter_rules:
        header = generate_header("Merged Filter", len(all_filter_rules), all_filter_stats)
        write_output(output_dir / "filter.txt", header, all_filter_rules)
        print(f"  -> {len(all_filter_rules)} rules written to output/filter.txt")
    else:
        print("  -> No filter sources configured")

    # 2. 处理白名单规则
    print("\n[2/3] Processing whitelist rules...")
    whitelist_url_sources = get_whitelist_urls(config)
    whitelist_manual_rules = get_whitelist_rules(config)

    all_whitelist_rules = []
    all_whitelist_stats = []

    if whitelist_url_sources:
        results = download_all(whitelist_url_sources)
        rules, stats = merge_rules(results)
        all_whitelist_rules.extend(rules)
        all_whitelist_stats.extend(stats)

    if whitelist_manual_rules:
        seen = set(all_whitelist_rules)
        manual_count = 0
        for rule in whitelist_manual_rules:
            if rule not in seen:
                seen.add(rule)
                all_whitelist_rules.append(rule)
                manual_count += 1
        if manual_count > 0:
            all_whitelist_stats.append({
                'name': 'Manual Rules',
                'count': manual_count,
                'url': 'config.yaml'
            })

    if all_whitelist_rules:
        header = generate_header("Merged Whitelist", len(all_whitelist_rules), all_whitelist_stats)
        write_output(output_dir / "whitelist.txt", header, all_whitelist_rules)
        print(f"  -> {len(all_whitelist_rules)} rules written to output/whitelist.txt")
    else:
        print("  -> No whitelist sources configured")

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
