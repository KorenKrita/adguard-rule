import yaml
from pathlib import Path
from typing import Union, List, Dict


def _validate_source_list(sources: list, section: str) -> None:
    """校验订阅源列表，每项必须包含 name 和 url 字段"""
    for i, item in enumerate(sources):
        if not isinstance(item, dict):
            raise ValueError(
                f"Config error: {section}[{i}] must be a mapping, got {type(item).__name__}"
            )
        for field in ('name', 'url'):
            if field not in item:
                raise ValueError(
                    f"Config error: {section}[{i}] is missing required field '{field}'"
                )


def load_config(config_path: Union[str, Path] = "config.yaml") -> dict:
    """加载并校验 YAML 配置文件"""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    if not isinstance(config, dict):
        raise ValueError("Config file must be a YAML mapping at the top level")

    # 校验 filters
    filters = config.get('filters', {})
    if isinstance(filters, list):
        _validate_source_list(filters, 'filters')
    elif isinstance(filters, dict):
        _validate_source_list(filters.get('urls', []), 'filters.urls')

    # 校验 whitelist
    whitelist = config.get('whitelist', {})
    if isinstance(whitelist, dict):
        _validate_source_list(whitelist.get('urls', []), 'whitelist.urls')

    # 校验 dns
    _validate_source_list(config.get('dns', []), 'dns')

    return config


def get_filter_urls(config: dict) -> list:
    """获取广告过滤订阅 URL 列表"""
    filters = config.get('filters', {})
    return filters.get('urls', []) if isinstance(filters, dict) else filters


def get_filter_manual_rules(config: dict) -> list:
    """获取手动配置的广告过滤规则"""
    filters = config.get('filters', {})
    if isinstance(filters, dict):
        return filters.get('manual_rules', [])
    return []


def get_whitelist_urls(config: dict) -> list:
    """获取白名单订阅 URL 列表"""
    whitelist = config.get('whitelist', {})
    return whitelist.get('urls', [])


def get_whitelist_rules(config: dict) -> list:
    """获取独立白名单规则"""
    whitelist = config.get('whitelist', {})
    return whitelist.get('rules', [])


def get_dns_urls(config: dict) -> list:
    """获取 DNS 过滤订阅 URL 列表"""
    return config.get('dns', [])


def _sort_urls_by_stats(urls: list, stats: List[Dict]) -> list:
    """根据统计信息中的 count 降序排序 urls

    Args:
        urls: 原始订阅源列表
        stats: 统计信息列表，每项包含 'name' 和 'count'

    Returns:
        按 count 降序排列的新列表
    """
    # 创建 name -> count 的映射
    count_map = {s['name']: s.get('count', 0) for s in stats}

    # 按 count 降序排序，未找到统计的默认 0
    sorted_urls = sorted(urls, key=lambda x: count_map.get(x.get('name', ''), 0), reverse=True)
    return sorted_urls


def sort_urls_by_count(config: dict, section: str, stats: List[Dict]) -> dict:
    """根据本次运行统计排序配置中的订阅源

    Args:
        config: 配置字典
        section: 要排序的区块 ('filters', 'whitelist', 'dns')
        stats: 该区块的统计信息

    Returns:
        修改后的配置字典（原地修改）
    """
    if section == 'filters':
        filters = config.get('filters', {})
        if isinstance(filters, dict) and 'urls' in filters:
            filters['urls'] = _sort_urls_by_stats(filters['urls'], stats)
    elif section == 'whitelist':
        whitelist = config.get('whitelist', {})
        if isinstance(whitelist, dict) and 'urls' in whitelist:
            whitelist['urls'] = _sort_urls_by_stats(whitelist['urls'], stats)
    elif section == 'dns':
        if 'dns' in config:
            config['dns'] = _sort_urls_by_stats(config['dns'], stats)

    return config


def save_config(config: dict, config_path: Union[str, Path] = "config.yaml") -> None:
    """安全地保存配置到 YAML 文件

    先写入临时文件，成功后再替换原文件，确保不会损坏配置。

    Args:
        config: 配置字典
        config_path: 配置文件路径
    """
    path = Path(config_path)
    temp_path = path.with_suffix('.yaml.tmp')
    backup_path = path.with_suffix('.yaml.bak')

    try:
        # 写入临时文件
        with open(temp_path, 'w', encoding='utf-8') as f:
            yaml.dump(
                config,
                f,
                allow_unicode=True,
                sort_keys=False,
                default_flow_style=False,
                indent=2,
                width=1000
            )

        # 备份原文件（如果存在）
        if path.exists():
            path.rename(backup_path)

        # 临时文件替换为正式文件
        temp_path.rename(path)

        # 删除备份文件
        if backup_path.exists():
            backup_path.unlink()

    except Exception as e:
        # 恢复备份
        if backup_path.exists() and not path.exists():
            backup_path.rename(path)
        raise RuntimeError(f"Failed to save config: {e}")
