import yaml
from pathlib import Path
from typing import Union


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
