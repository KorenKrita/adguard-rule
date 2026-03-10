import pytest
import tempfile
import os
from src.config import load_config


def test_load_config_valid():
    """测试正常读取配置"""
    config_content = """
filters:
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
        assert len(config['filters']) == 1
        assert config['filters'][0]['name'] == "Test Filter"
        assert len(config['whitelist']['urls']) == 1
        assert len(config['whitelist']['rules']) == 1
        assert len(config['dns']) == 1
    finally:
        os.unlink(config_path)


def test_load_config_file_not_found():
    """测试文件不存在时抛出异常"""
    with pytest.raises(FileNotFoundError):
        load_config("/nonexistent/config.yaml")
