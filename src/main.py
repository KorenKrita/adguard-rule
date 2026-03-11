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
from src.semantic.deduplicator import SemanticDeduplicator
from src.variant_generator import VariantGenerator


def process_rules(
    sources: List[Dict],
    manual_rules: List[str],
    title: str,
    output_path: Path,
    label: str,
) -> Tuple[Dict, List[Dict], List[str]]:
    """下载、合并、去重并写出规则文件

    Args:
        sources: 订阅源列表（含 name/url）
        manual_rules: 手动配置的规则列表
        title: 输出文件标题
        output_path: 输出文件路径
        label: 用于打印日志的文件名标识

    Returns:
        (汇总统计, 详细统计信息列表)
        汇总统计包含: total(原始总数), count(去重后数量)
    """
    all_rules: List[str] = []
    all_stats: List[Dict] = []
    total_input = 0

    if sources:
        results = download_all(sources)
        rules, stats = merge_rules(results)
        all_rules.extend(rules)
        all_stats.extend(stats)
        # 计算原始总数
        for stat in stats:
            total_input += stat.get('total', 0)

    if manual_rules:
        seen = set(all_rules)
        manual_total = len(manual_rules)
        manual_count = 0
        for rule in manual_rules:
            if rule not in seen:
                seen.add(rule)
                all_rules.append(rule)
                manual_count += 1
        total_input += manual_total
        if manual_count > 0:
            percentage = (manual_count / manual_total * 100) if manual_total > 0 else 0.0
            all_stats.append({
                'name': 'Manual Rules',
                'total': manual_total,
                'count': manual_count,
                'percentage': percentage,
                'url': 'config.yaml'
            })

    # 阶段2：语义去重（识别功能等价但语法不同的规则，保留更强的规则）
    semantic_deduped_count = 0
    if all_rules:
        deduplicator = SemanticDeduplicator()
        final_rules = deduplicator.process_batch(all_rules)
        semantic_deduped_count = len(all_rules) - len(final_rules)
        all_rules = final_rules

    if all_rules:
        header = generate_header(title, len(all_rules), all_stats)
        write_output(output_path, header, all_rules)
        total_filtered = total_input - len(all_rules)
        print(f"  -> {len(all_rules)} rules written to {label} (filtered {total_filtered} duplicates")
        if semantic_deduped_count > 0:
            print(f"      including {semantic_deduped_count} semantic duplicates)")
        else:
            print(")")
    else:
        print(f"  -> No sources configured for {label}")

    summary = {
        'total': total_input,
        'count': len(all_rules)
    }
    return summary, all_stats, all_rules  # Return rules for variant generation


def main():
    """主程序入口"""
    config_path = Path("config.yaml")

    print("Loading configuration...")
    config = load_config(config_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 1. 处理广告过滤规则
    print("\n[1/3] Processing filter rules...")
    filter_summary, filter_stats, filter_rules = process_rules(
        sources=get_filter_urls(config),
        manual_rules=get_filter_manual_rules(config),
        title="Merged Filter",
        output_path=output_dir / "filter.txt",
        label="output/filter.txt",
    )

    # 2. 处理白名单规则
    print("\n[2/3] Processing whitelist rules...")
    whitelist_summary, whitelist_stats, whitelist_rules = process_rules(
        sources=get_whitelist_urls(config),
        manual_rules=get_whitelist_manual_rules(config),
        title="Merged Whitelist",
        output_path=output_dir / "whitelist.txt",
        label="output/whitelist.txt",
    )

    # 3. 处理 DNS 过滤规则
    print("\n[3/3] Processing DNS filter rules...")
    dns_summary, dns_stats, dns_rules = process_rules(
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

    # 5. 生成高级变体文件
    print("\n[5/5] Generating variant files...")
    generator = VariantGenerator()
    variants = generator.generate(
        filter_rules=filter_rules,
        dns_rules=dns_rules,
        whitelist_rules=whitelist_rules
    )

    # 写入变体文件
    variant_names = {
        'dns_full': ("Merged DNS Full (DNS Priority)", "dns-full"),
        'filter_lite': ("Merged Filter Lite (DNS Priority)", "filter-lite"),
        'dns_lite': ("Merged DNS Lite (Filter Priority)", "dns-lite"),
        'filter_full': ("Merged Filter Full (Filter Priority)", "filter-full"),
    }

    for name, rules in variants.items():
        title, filename = variant_names[name]
        output_path = output_dir / f"{filename}.txt"
        header = generate_header(title, len(rules), [])
        write_output(output_path, header, rules)
        print(f"  -> {len(rules)} rules written to output/{filename}.txt")

    # 6. 输出去重统计（供 GitHub Actions 使用）
    print("\n[Dedup Stats]")
    print(f"FILTER_TOTAL={filter_summary['total']}")
    print(f"FILTER_COUNT={filter_summary['count']}")
    print(f"WHITELIST_TOTAL={whitelist_summary['total']}")
    print(f"WHITELIST_COUNT={whitelist_summary['count']}")
    print(f"DNS_TOTAL={dns_summary['total']}")
    print(f"DNS_COUNT={dns_summary['count']}")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
