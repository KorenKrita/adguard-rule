"""Tests for semantic/types.py"""
import pytest

from src.semantic.types import RuleType, ParsedRule


class TestRuleType:
    def test_rule_type_enum_values(self):
        assert RuleType.DNS_FILTER is not None
        assert RuleType.AD_BLOCK is not None
        assert RuleType.HOSTS is not None
        assert RuleType.DOMAIN_ONLY is not None
        assert RuleType.EXCEPTION is not None
        assert RuleType.COSMETIC is not None
        assert RuleType.HTML_FILTER is not None
        assert RuleType.SCRIPTLET is not None
        assert RuleType.COMMENT is not None
        assert RuleType.UNKNOWN is not None


class TestParsedRule:
    def test_parsed_rule_creation(self):
        rule = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={"important": True},
            is_exception=False,
            strength_score=10,
            normalized_domain="example.com"
        )
        assert rule.raw == "||example.com^"
        assert rule.rule_type == RuleType.DNS_FILTER
        assert rule.pattern == "||example.com^"
        assert rule.modifiers == {"important": True}
        assert rule.is_exception is False
        assert rule.strength_score == 10
        assert rule.normalized_domain == "example.com"

    def test_parsed_rule_default_values(self):
        rule = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False
        )
        assert rule.strength_score == 0
        assert rule.normalized_domain is None

    def test_parsed_rule_equality(self):
        rule1 = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False
        )
        rule2 = ParsedRule(
            raw="example.com",
            rule_type=RuleType.HOSTS,
            pattern="example.com",
            modifiers={"ip": "127.0.0.1"},
            is_exception=False
        )
        # Equality is based on raw string
        assert rule1 == rule2

    def test_parsed_rule_inequality(self):
        rule1 = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False
        )
        rule2 = ParsedRule(
            raw="example.org",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.org",
            modifiers={},
            is_exception=False
        )
        assert rule1 != rule2

    def test_parsed_rule_hash(self):
        rule = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False
        )
        assert hash(rule) == hash("example.com")
