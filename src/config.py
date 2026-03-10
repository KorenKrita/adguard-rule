import yaml
from pathlib import Path


def load_config(config_path: str = "config.yaml") -> dict:
    """加载 YAML 配置文件"""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

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
