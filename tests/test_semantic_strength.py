"""Tests for semantic/strength.py"""
import pytest

from src.semantic.strength import StrengthEvaluator
from src.semantic.types import ParsedRule, RuleType


class TestStrengthHosts:
    def test_hosts_127_0_0_1(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="127.0.0.1 example.com",
            rule_type=RuleType.HOSTS,
            pattern="example.com",
            modifiers={'ip': '127.0.0.1'},
            is_exception=False,
            normalized_domain="example.com"
        )
        assert evaluator.evaluate(rule) == 5

    def test_hosts_0_0_0_0(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="0.0.0.0 example.com",
            rule_type=RuleType.HOSTS,
            pattern="example.com",
            modifiers={'ip': '0.0.0.0'},
            is_exception=False,
            normalized_domain="example.com"
        )
        assert evaluator.evaluate(rule) == 6  # 5 base + 1 for 0.0.0.0


class TestStrengthDomainOnly:
    def test_domain_only(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        assert evaluator.evaluate(rule) == 5


class TestStrengthDNSFilter:
    def test_dns_filter_basic(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        # 10 for subdomain match
        assert evaluator.evaluate(rule) == 10

    def test_dns_filter_with_important(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="||example.com^$important",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={'important': True},
            is_exception=False,
            normalized_domain="example.com"
        )
        # 10 for subdomain + 20 for important + 2 for modifier
        assert evaluator.evaluate(rule) == 32


class TestStrengthAdBlock:
    def test_adblock_with_path(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="||example.com/ads/script.js",
            rule_type=RuleType.AD_BLOCK,
            pattern="||example.com/ads/script.js",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        # 10 for subdomain + 6 for path depth (2 slashes * 3)
        assert evaluator.evaluate(rule) == 16

    def test_adblock_with_modifiers(self):
        evaluator = StrengthEvaluator()
        rule = ParsedRule(
            raw="||example.com^$script,third-party",
            rule_type=RuleType.AD_BLOCK,
            pattern="||example.com^",
            modifiers={'script': True, 'third-party': True},
            is_exception=False,
            normalized_domain="example.com"
        )
        # 10 for subdomain + 4 for 2 modifiers
        assert evaluator.evaluate(rule) == 14


class TestStrengthCompare:
    def test_compare_stronger(self):
        evaluator = StrengthEvaluator()
        strong = ParsedRule(
            raw="||example.com^$important",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={'important': True},
            is_exception=False,
            normalized_domain="example.com",
            strength_score=32
        )
        weak = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com",
            strength_score=5
        )

        assert evaluator.compare(strong, weak) > 0
        assert evaluator.compare(weak, strong) < 0
        assert evaluator.is_stronger(strong, weak)
        assert not evaluator.is_stronger(weak, strong)


class TestStrengthCovers:
    def test_wildcard_covers_exact(self):
        evaluator = StrengthEvaluator()
        wildcard = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        exact = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )

        assert evaluator.covers(wildcard, exact)
        assert not evaluator.covers(exact, wildcard)

    def test_wildcard_covers_subdomain(self):
        evaluator = StrengthEvaluator()
        parent = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        sub = ParsedRule(
            raw="||sub.example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||sub.example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="sub.example.com"
        )

        assert evaluator.covers(parent, sub)
        assert not evaluator.covers(sub, parent)

    def test_exact_same_domain(self):
        evaluator = StrengthEvaluator()
        rule1 = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        rule2 = ParsedRule(
            raw="example.com",
            rule_type=RuleType.DOMAIN_ONLY,
            pattern="example.com",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )

        assert evaluator.covers(rule1, rule2)

    def test_exception_incompatible(self):
        evaluator = StrengthEvaluator()
        normal = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )
        exception = ParsedRule(
            raw="@@||example.com^",
            rule_type=RuleType.EXCEPTION,
            pattern="||example.com^",
            modifiers={},
            is_exception=True,
            normalized_domain="example.com"
        )

        assert not evaluator.covers(normal, exception)
        assert not evaluator.covers(exception, normal)

    def test_no_domain_info(self):
        evaluator = StrengthEvaluator()
        rule1 = ParsedRule(
            raw="##.ad",
            rule_type=RuleType.COSMETIC,
            pattern=".ad",
            modifiers={'domains': '*'},
            is_exception=False,
            normalized_domain=None
        )
        rule2 = ParsedRule(
            raw="##.banner",
            rule_type=RuleType.COSMETIC,
            pattern=".banner",
            modifiers={'domains': '*'},
            is_exception=False,
            normalized_domain=None
        )

        assert not evaluator.covers(rule1, rule2)
