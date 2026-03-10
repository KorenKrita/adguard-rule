# tests/test_downloader.py
import pytest
from unittest.mock import patch, MagicMock
from src.downloader import download_content, download_all


def test_download_content_success():
    """测试成功下载"""
    mock_response = MagicMock()
    mock_response.text = "||example.com^\n||test.com^"
    mock_response.status_code = 200

    with patch('src.downloader.requests.get', return_value=mock_response):
        content, count = download_content("https://example.com/filter.txt")
        assert content == "||example.com^\n||test.com^"
        assert count == 2


def test_download_content_failure():
    """测试下载失败返回 None"""
    with patch('src.downloader.requests.get', side_effect=Exception("Network error")):
        content, count = download_content("https://example.com/filter.txt")
        assert content is None
        assert count == 0


def test_download_all():
    """测试批量下载"""
    sources = [
        {"name": "Source1", "url": "https://a.com/1.txt"},
        {"name": "Source2", "url": "https://b.com/2.txt"},
    ]

    mock_response = MagicMock()
    mock_response.text = "||a.com^"
    mock_response.status_code = 200

    with patch('src.downloader.requests.get', return_value=mock_response):
        results = download_all(sources)
        assert len(results) == 2
        assert results[0]['name'] == "Source1"
        assert results[0]['content'] == "||a.com^"
        assert results[0]['count'] == 1
