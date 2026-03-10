import pytest
from src.merger import parse_rules, merge_rules, generate_header


def test_parse_rules_basic():
    content = """
! This is a comment
||example.com^
||test.com^

! Another comment
@@||whitelist.com^
"""
    rules = parse_rules(content)
    assert len(rules) == 3
    assert "||example.com^" in rules
    assert "||test.com^" in rules
    assert "@@||whitelist.com^" in rules


def test_parse_rules_dedup():
    content = """
||example.com^
||example.com^
||example.com^
"""
    rules = parse_rules(content)
    assert len(rules) == 1


def test_merge_rules():
    sources = [
        {'name': 'Source1', 'content': '||a.com^\n||b.com^', 'count': 2, 'success': True, 'url': 'https://source1.com'},
        {'name': 'Source2', 'content': '||b.com^\n||c.com^', 'count': 2, 'success': True, 'url': 'https://source2.com'},
    ]
    all_rules, source_stats = merge_rules(sources)
    assert len(all_rules) == 3
    assert len(source_stats) == 2


def test_generate_header():
    header = generate_header(
        title="Test Filter",
        total=100,
        source_stats=[{'name': 'Source1', 'total': 60, 'count': 60, 'percentage': 100.0, 'url': 'https://a.com'},
                      {'name': 'Source2', 'total': 40, 'count': 40, 'percentage': 100.0, 'url': 'https://b.com'}]
    )
    assert "Test Filter" in header
    assert "Total: 100" in header
    assert "60 total, 60 used (100.0%)" in header
    assert "40 total, 40 used (100.0%)" in header
