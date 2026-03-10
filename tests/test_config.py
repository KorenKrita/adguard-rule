import pytest
import tempfile
import os
from src.config import load_config, get_filter_urls, get_filter_manual_rules, get_whitelist_urls, get_whitelist_rules, get_dns_urls


def test_load_config_valid():
    """测试正常读取配置（新格式：filters 为 dict）"""
    config_content = """
filters:
  manual_rules:
    - "||manual.example.com^"
  urls:
    - name: "Test Filter"
      url: "https://example.com/filter.txt"

whitelist:
  urls:
    - name: "Test Allow"
      url: "https://example.com/allow.txt"
  rules:
    - "@@||test.com^"

dns:
  - name: "Test DNS"
    url: "https://example.com/dns.txt"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = f.name

    try:
        config = load_config(config_path)

        # 测试 get_filter_urls
        filter_urls = get_filter_urls(config)
        assert len(filter_urls) == 1
        assert filter_urls[0]['name'] == "Test Filter"
        assert filter_urls[0]['url'] == "https://example.com/filter.txt"

        # 测试 get_filter_manual_rules
        manual_rules = get_filter_manual_rules(config)
        assert len(manual_rules) == 1
        assert manual_rules[0] == "||manual.example.com^"

        # 测试 get_whitelist_urls
        whitelist_urls = get_whitelist_urls(config)
        assert len(whitelist_urls) == 1
        assert whitelist_urls[0]['name'] == "Test Allow"

        # 测试 get_whitelist_rules
        whitelist_rules = get_whitelist_rules(config)
        assert len(whitelist_rules) == 1
        assert whitelist_rules[0] == "@@||test.com^"

        # 测试 get_dns_urls
        dns_urls = get_dns_urls(config)
        assert len(dns_urls) == 1
        assert dns_urls[0]['name'] == "Test DNS"
    finally:
        os.unlink(config_path)


def test_load_config_filters_list_compat():
    """测试旧格式兼容：filters 为列表时 get_filter_urls 应返回列表本身"""
    config_content = """
filters:
  - name: "Test Filter"
    url: "https://example.com/filter.txt"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = f.name

    try:
        config = load_config(config_path)
        filter_urls = get_filter_urls(config)
        assert len(filter_urls) == 1
        assert filter_urls[0]['name'] == "Test Filter"

        # 旧格式没有 manual_rules
        manual_rules = get_filter_manual_rules(config)
        assert manual_rules == []
    finally:
        os.unlink(config_path)


def test_load_config_empty_sections():
    """测试空配置段返回空列表"""
    config_content = """
filters: {}
whitelist: {}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = f.name

    try:
        config = load_config(config_path)
        assert get_filter_urls(config) == []
        assert get_filter_manual_rules(config) == []
        assert get_whitelist_urls(config) == []
        assert get_whitelist_rules(config) == []
        assert get_dns_urls(config) == []
    finally:
        os.unlink(config_path)


def test_load_config_missing_name_field():
    """测试订阅源缺少 name 字段时抛出 ValueError"""
    config_content = """
dns:
  - url: "https://example.com/dns.txt"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="missing required field 'name'"):
            load_config(config_path)
    finally:
        os.unlink(config_path)


def test_load_config_missing_url_field():
    """测试订阅源缺少 url 字段时抛出 ValueError"""
    config_content = """
whitelist:
  urls:
    - name: "Test Allow"
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write(config_content)
        f.flush()
        config_path = f.name

    try:
        with pytest.raises(ValueError, match="missing required field 'url'"):
            load_config(config_path)
    finally:
        os.unlink(config_path)


def test_load_config_file_not_found():
    """测试文件不存在时抛出异常"""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/config.yaml")
