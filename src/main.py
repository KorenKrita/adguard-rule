#!/usr/bin/env python3
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple, Any

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


class Timer:
    """简单的计时器上下文管理器"""
    def __init__(self, name: str, stats: Dict[str, Any]):
        self.name = name
        self.stats = stats
        self.start_time = 0.0
        self.elapsed = 0.0

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.elapsed = time.perf_counter() - self.start_time
        self.stats[self.name] = self.elapsed


def process_rules(
    sources: List[Dict],
    manual_rules: List[str],
    title: str,
    output_path: Path,
    label: str,
    timings: Dict[str, float],
) -> Tuple[Dict[str, int], List[Dict], List[str]]:
    """下载、合并、去重并写出规则文件

    Args:
        sources: 订阅源列表（含 name/url）
        manual_rules: 手动配置的规则列表
        title: 输出文件标题
        output_path: 输出文件路径
        label: 用于打印日志的文件名标识
        timings: 用于记录各阶段耗时的字典

    Returns:
        Tuple[summary, source_stats, all_rules]:
        - summary: 汇总统计，包含 total(原始总数), count(去重后数量)
        - source_stats: 各来源详细统计信息列表
        - all_rules: 处理后的规则列表
    """
    all_rules: List[str] = []
    source_stats: List[Dict] = []
    total_input = 0

    if sources:
        with Timer('download', timings):
            results = download_all(sources)
        with Timer('merge', timings):
            rules, merge_stats = merge_rules(results)
        all_rules.extend(rules)
        source_stats.extend(merge_stats)
        # 计算原始总数
        for stat in merge_stats:
            total_input += stat.get('total', 0)

    if manual_rules:
        with Timer('manual_rules', timings):
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
                source_stats.append({
                    'name': 'Manual Rules',
                    'total': manual_total,
                    'count': manual_count,
                    'percentage': percentage,
                    'url': 'config.yaml'
                })

    # 阶段2：语义去重（识别功能等价但语法不同的规则，保留更强的规则）
    semantic_deduped_count = 0
    if all_rules:
        with Timer('semantic_dedup', timings):
            deduplicator = SemanticDeduplicator()
            final_rules = deduplicator.process_batch(all_rules)
            semantic_deduped_count = len(all_rules) - len(final_rules)
            all_rules = final_rules

    if all_rules:
        with Timer('write_output', timings):
            header = generate_header(title, len(all_rules), source_stats)
            write_output(output_path, header, all_rules)
        total_filtered = total_input - len(all_rules)
        print(f"  -> {len(all_rules)} rules written to {label} (filtered {total_filtered} duplicates")
        if semantic_deduped_count > 0:
            print(f"      including {semantic_deduped_count} semantic duplicates)")
        else:
            print(")")
    else:
        print(f"  -> No sources configured for {label}")

    summary: Dict[str, int] = {
        'total': total_input,
        'count': len(all_rules)
    }
    return summary, source_stats, all_rules


def format_time(seconds: float) -> str:
    """格式化时间显示"""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    return f"{seconds:.2f}s"


def main():
    """主程序入口"""
    total_start = time.perf_counter()
    config_path = Path("config.yaml")

    # 各阶段耗时统计
    timings: Dict[str, float] = {}

    print("Loading configuration...")
    config = load_config(config_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # 1. 处理广告过滤规则
    print("\n[1/5] Processing filter rules...")
    filter_timings: Dict[str, float] = {}
    filter_summary, filter_source_stats, filter_rules = process_rules(
        sources=get_filter_urls(config),
        manual_rules=get_filter_manual_rules(config),
        title="Merged Filter",
        output_path=output_dir / "filter.txt",
        label="output/filter.txt",
        timings=filter_timings,
    )
    timings['filter'] = sum(filter_timings.values())

    # 2. 处理白名单规则
    print("\n[2/5] Processing whitelist rules...")
    whitelist_timings: Dict[str, float] = {}
    whitelist_summary, whitelist_source_stats, whitelist_rules = process_rules(
        sources=get_whitelist_urls(config),
        manual_rules=get_whitelist_manual_rules(config),
        title="Merged Whitelist",
        output_path=output_dir / "whitelist.txt",
        label="output/whitelist.txt",
        timings=whitelist_timings,
    )
    timings['whitelist'] = sum(whitelist_timings.values())

    # 3. 处理 DNS 过滤规则
    print("\n[3/5] Processing DNS filter rules...")
    dns_timings: Dict[str, float] = {}
    dns_summary, dns_source_stats, dns_rules = process_rules(
        sources=get_dns_urls(config),
        manual_rules=get_dns_manual_rules(config),
        title="Merged DNS Filter",
        output_path=output_dir / "dns.txt",
        label="output/dns.txt",
        timings=dns_timings,
    )
    timings['dns'] = sum(dns_timings.values())

    # 4. 根据本次运行统计排序配置并保存
    print("\n[4/5] Optimizing config order...")
    sort_start = time.perf_counter()
    sort_urls_by_count(config, 'filters', filter_source_stats)
    sort_urls_by_count(config, 'whitelist', whitelist_source_stats)
    sort_urls_by_count(config, 'dns', dns_source_stats)

    try:
        save_config(config, config_path)
        print("  -> Config order updated")
    except Exception as e:
        print(f"  -> Failed to save config: {e}")
    timings['config_save'] = time.perf_counter() - sort_start

    # 5. 生成高级变体文件
    print("\n[5/5] Generating variant files...")
    variant_start = time.perf_counter()
    generator = VariantGenerator()
    variants = generator.generate(
        filter_rules=filter_rules,
        dns_rules=dns_rules,
        whitelist_rules=whitelist_rules
    )
    timings['variant_generation'] = time.perf_counter() - variant_start

    # 写入变体文件
    variant_meta = {
        'dns_full': ("Merged DNS Full (DNS Priority)", "dns-full",
                     f"DNS priority variant: original DNS {dns_summary['count']}, whitelist {whitelist_summary['count']} applied"),
        'filter_lite': ("Merged Filter Lite (DNS Priority)", "filter-lite",
                        f"DNS priority variant: original Filter {filter_summary['count']}, DNS duplicates removed"),
        'dns_lite': ("Merged DNS Lite (Filter Priority)", "dns-lite",
                     f"Filter priority variant: original DNS {dns_summary['count']}, Filter duplicates removed"),
        'filter_full': ("Merged Filter Full (Filter Priority)", "filter-full",
                        f"Filter priority variant: original Filter {filter_summary['count']}, whitelist {whitelist_summary['count']} applied"),
    }

    for name, rules in variants.items():
        title, filename, description = variant_meta[name]
        output_path = output_dir / f"{filename}.txt"
        # 为变体文件生成简要统计
        variant_stats = [{
            'name': description,
            'total': len(rules),
            'count': len(rules),
            'percentage': 100.0,
            'url': 'variant'
        }]
        header = generate_header(title, len(rules), variant_stats)
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

    # 7. 输出变体统计（供 GitHub Actions 使用）
    print("\n[Variant Stats]")
    print(f"DNS_FULL_COUNT={len(variants['dns_full'])}")
    print(f"FILTER_LITE_COUNT={len(variants['filter_lite'])}")
    print(f"DNS_LITE_COUNT={len(variants['dns_lite'])}")
    print(f"FILTER_FULL_COUNT={len(variants['filter_full'])}")
    # 计算去重数量
    dns_full_filtered = dns_summary['count'] + whitelist_summary['count'] - len(variants['dns_full'])
    filter_lite_filtered = filter_summary['count'] + whitelist_summary['count'] - len(variants['filter_lite'])
    dns_lite_filtered = dns_summary['count'] + whitelist_summary['count'] - len(variants['dns_lite'])
    filter_full_filtered = filter_summary['count'] + whitelist_summary['count'] - len(variants['filter_full'])
    print(f"DNS_FULL_FILTERED={dns_full_filtered}")
    print(f"FILTER_LITE_FILTERED={filter_lite_filtered}")
    print(f"DNS_LITE_FILTERED={dns_lite_filtered}")
    print(f"FILTER_FULL_FILTERED={filter_full_filtered}")

    # 8. 输出性能统计
    total_elapsed = time.perf_counter() - total_start
    timings['total'] = total_elapsed

    print("\n" + "=" * 60)
    print("处理完成！性能统计:")
    print("=" * 60)
    print(f"\n总耗时: {format_time(total_elapsed)}")
    print("\n各阶段耗时:")
    print(f"  Filter 处理:     {format_time(timings['filter']):>10}")
    print(f"  Whitelist 处理:  {format_time(timings['whitelist']):>10}")
    print(f"  DNS 处理:        {format_time(timings['dns']):>10}")
    print(f"  配置保存:        {format_time(timings['config_save']):>10}")
    print(f"  变体生成:        {format_time(timings['variant_generation']):>10}")

    # 处理速度统计
    total_rules = filter_summary['count'] + whitelist_summary['count'] + dns_summary['count']
    if total_elapsed > 0:
        speed = total_rules / total_elapsed
        print(f"\n处理速度: {speed:,.0f} 规则/秒")
    print("=" * 60)

    print("\nDone!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
