"""Tests for semantic/parser.py"""
import pytest

from src.semantic.parser import RuleParser, MAX_RULE_LENGTH
from src.semantic.types import RuleType


class TestRuleParserHosts:
    def test_parse_hosts_127_0_0_1(self):
        parser = RuleParser()
        rule = parser.parse("127.0.0.1 example.com")
        assert rule is not None
        assert rule.rule_type == RuleType.HOSTS
        assert rule.pattern == "example.com"
        assert rule.modifiers['ip'] == "127.0.0.1"
        assert rule.normalized_domain == "example.com"
        assert rule.strength_score == 5

    def test_parse_hosts_0_0_0_0(self):
        parser = RuleParser()
        rule = parser.parse("0.0.0.0 example.com")
        assert rule is not None
        assert rule.rule_type == RuleType.HOSTS
        assert rule.pattern == "example.com"
        assert rule.modifiers['ip'] == "0.0.0.0"

    def test_parse_hosts_ipv6(self):
        parser = RuleParser()
        rule = parser.parse("::1 example.com")
        assert rule is not None
        assert rule.rule_type == RuleType.HOSTS
        assert rule.pattern == "example.com"


class TestRuleParserDomainOnly:
    def test_parse_domain_only(self):
        parser = RuleParser()
        rule = parser.parse("example.com")
        assert rule is not None
        assert rule.rule_type == RuleType.DOMAIN_ONLY
        assert rule.pattern == "example.com"
        assert rule.normalized_domain == "example.com"

    def test_parse_domain_only_subdomain(self):
        parser = RuleParser()
        rule = parser.parse("sub.example.com")
        assert rule is not None
        assert rule.rule_type == RuleType.DOMAIN_ONLY
        assert rule.pattern == "sub.example.com"


class TestRuleParserDNSFilter:
    def test_parse_dns_filter_basic(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^")
        assert rule is not None
        assert rule.rule_type == RuleType.DNS_FILTER
        assert rule.pattern == "||example.com^"
        assert rule.normalized_domain == "example.com"

    def test_parse_dns_filter_with_important(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$important")
        assert rule is not None
        assert rule.rule_type == RuleType.DNS_FILTER
        assert rule.modifiers.get('important') is True

    def test_parse_dns_filter_with_dnsrewrite(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$dnsrewrite=127.0.0.1")
        assert rule is not None
        assert rule.rule_type == RuleType.DNS_FILTER
        assert rule.modifiers.get('dnsrewrite') == "127.0.0.1"


class TestRuleParserAdBlock:
    def test_parse_adblock_with_path(self):
        parser = RuleParser()
        rule = parser.parse("||example.com/ads/*")
        assert rule is not None
        assert rule.rule_type == RuleType.AD_BLOCK

    def test_parse_adblock_with_modifiers(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$script,third-party")
        assert rule is not None
        # No path in pattern, so it's classified as DNS_FILTER
        assert rule.rule_type == RuleType.DNS_FILTER
        assert rule.modifiers.get('script') is True
        assert rule.modifiers.get('third-party') is True


class TestRuleParserException:
    def test_parse_exception_dns(self):
        parser = RuleParser()
        rule = parser.parse("@@||example.com^")
        assert rule is not None
        assert rule.rule_type == RuleType.EXCEPTION
        assert rule.is_exception is True
        assert rule.pattern == "||example.com^"

    def test_parse_exception_adblock(self):
        parser = RuleParser()
        rule = parser.parse("@@||example.com/ads/*")
        assert rule is not None
        assert rule.rule_type == RuleType.EXCEPTION
        assert rule.is_exception is True


class TestRuleParserCosmetic:
    def test_parse_cosmetic_basic(self):
        parser = RuleParser()
        rule = parser.parse("example.com##.ad-banner")
        assert rule is not None
        assert rule.rule_type == RuleType.COSMETIC
        assert rule.pattern == ".ad-banner"
        assert rule.modifiers.get('domains') == "example.com"

    def test_parse_cosmetic_generic(self):
        parser = RuleParser()
        rule = parser.parse("##.ad-banner")
        assert rule is not None
        assert rule.rule_type == RuleType.COSMETIC
        assert rule.pattern == ".ad-banner"


class TestRuleParserComments:
    def test_parse_comment_bang(self):
        parser = RuleParser()
        rule = parser.parse("! This is a comment")
        assert rule is None

    def test_parse_comment_hash(self):
        parser = RuleParser()
        rule = parser.parse("# This is a comment")
        assert rule is None

    def test_parse_empty_line(self):
        parser = RuleParser()
        rule = parser.parse("")
        assert rule is None
        rule = parser.parse("   ")
        assert rule is None


class TestRuleParserEdgeCases:
    def test_parse_long_rule(self):
        parser = RuleParser()
        long_rule = "A" * (MAX_RULE_LENGTH + 1)
        rule = parser.parse(long_rule)
        assert rule is not None
        assert rule.rule_type == RuleType.UNKNOWN
        assert rule.raw == long_rule

    def test_parse_unknown_rule(self):
        parser = RuleParser()
        rule = parser.parse("some random text that doesn't match anything")
        assert rule is not None
        assert rule.rule_type == RuleType.UNKNOWN


class TestRuleParserModifiers:
    def test_parse_modifiers_with_equals(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$domain=test.com")
        assert rule.modifiers.get('domain') == "test.com"

    def test_parse_modifiers_multiple(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$script,image,document")
        assert rule.modifiers.get('script') is True
        assert rule.modifiers.get('image') is True
        assert rule.modifiers.get('document') is True

    def test_parse_modifiers_with_pipe_separator(self):
        parser = RuleParser()
        rule = parser.parse("||example.com^$script|image")
        assert rule.modifiers.get('script') is True
        assert rule.modifiers.get('image') is True
