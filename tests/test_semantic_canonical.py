"""Tests for semantic/canonical.py"""
import pytest

from src.semantic.canonical import CanonicalFormBuilder
from src.semantic.types import ParsedRule, RuleType


class TestCanonicalHosts:
    def test_hosts_127_0_0_1_equivalence(self):
        builder = CanonicalFormBuilder()

        r1 = ParsedRule(
            raw="127.0.0.1 example.com",
            rule_type=RuleType.HOSTS,
            pattern="example.com",
            modifiers={'ip': '127.0.0.1'},
            is_exception=False,
            normalized_domain="example.com"
        )
        r2 = ParsedRule(
            raw="0.0.0.0 example.com",
            rule_type=RuleType.HOSTS,
            pattern="example.com",
            modifiers={'ip': '0.0.0.0'},
            is_exception=False,
            normalized_domain="example.com"
        )

        assert builder.build_canonical_key(r1) == builder.build_canonical_key(r2)
        assert builder.build_canonical_key(r1) == "dns:block:exact:example.com"


class TestCanonicalDNSFilter:
    def test_dns_filter_wildcard(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="||example.com^",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={},
            is_exception=False,
            normalized_domain="example.com"
        )

        assert builder.build_canonical_key(rule) == "dns:block:wildcard:example.com"

    def test_dns_filter_with_important(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="||example.com^$important",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={'important': True},
            is_exception=False,
            normalized_domain="example.com"
        )

        # Important modifier doesn't change canonical key for DNS rules
        assert builder.build_canonical_key(rule) == "dns:block:wildcard:example.com"

    def test_dns_filter_with_dnsrewrite(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="||example.com^$dnsrewrite=127.0.0.1",
            rule_type=RuleType.DNS_FILTER,
            pattern="||example.com^",
            modifiers={'dnsrewrite': '127.0.0.1'},
            is_exception=False,
            normalized_domain="example.com"
        )

        assert builder.build_canonical_key(rule) == "dns:rewrite:example.com:NOERROR;A;127.0.0.1"


class TestCanonicalAdBlock:
    def test_adblock_basic(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="||example.com^$doc",
            rule_type=RuleType.AD_BLOCK,
            pattern="||example.com^",
            modifiers={'doc': True},
            is_exception=False,
            normalized_domain="example.com"
        )

        key = builder.build_canonical_key(rule)
        assert key.startswith("filter:block:")
        assert "document" in key  # 'doc' should be normalized to 'document'

    def test_adblock_exception(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="@@||example.com^$document",
            rule_type=RuleType.EXCEPTION,
            pattern="||example.com^",
            modifiers={'document': True},
            is_exception=True,
            normalized_domain="example.com"
        )

        key = builder.build_canonical_key(rule)
        assert "allow" in key


class TestCanonicalCosmetic:
    def test_cosmetic_basic(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="example.com##.ad",
            rule_type=RuleType.COSMETIC,
            pattern=".ad",
            modifiers={'domains': 'example.com'},
            is_exception=False
        )

        assert builder.build_canonical_key(rule) == "cosmetic:block:example.com:.ad"

    def test_cosmetic_generic(self):
        builder = CanonicalFormBuilder()

        rule = ParsedRule(
            raw="##.ad",
            rule_type=RuleType.COSMETIC,
            pattern=".ad",
            modifiers={'domains': '*'},
            is_exception=False
        )

        assert builder.build_canonical_key(rule) == "cosmetic:block:*:.ad"


class TestCanonicalModifierAliases:
    def test_doc_alias(self):
        builder = CanonicalFormBuilder()
        modifiers = builder._normalize_modifiers({'doc': True})
        assert 'document' in modifiers
        assert 'doc' not in modifiers

    def test_css_alias(self):
        builder = CanonicalFormBuilder()
        modifiers = builder._normalize_modifiers({'css': True})
        assert 'stylesheet' in modifiers

    def test_3p_alias(self):
        builder = CanonicalFormBuilder()
        modifiers = builder._normalize_modifiers({'3p': True})
        assert 'third-party' in modifiers

    def test_all_modifier_expansion(self):
        builder = CanonicalFormBuilder()
        modifiers = builder._normalize_modifiers({'all': True})
        assert 'document' in modifiers
        assert 'script' in modifiers
        assert 'image' in modifiers


class TestCanonicalPatternNormalization:
    def test_domain_wildcard_pattern(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_pattern("||Example.COM")
        assert normalized == "[DOMAIN]example.com"

    def test_start_pattern(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_pattern("|http://Example.COM")
        assert normalized == "[START]http://example.com"

    def test_end_pattern(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_pattern(".swf|")
        assert normalized == "[END].swf"


class TestCanonicalDNSRewrite:
    def test_dnsrewrite_ip(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_dnsrewrite("192.168.1.1")
        assert normalized == "NOERROR;A;192.168.1.1"

    def test_dnsrewrite_ipv6(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_dnsrewrite("::1")
        assert normalized == "NOERROR;AAAA;::1"

    def test_dnsrewrite_refused(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_dnsrewrite("REFUSED")
        assert normalized == "REFUSED;;"

    def test_dnsrewrite_full_format(self):
        builder = CanonicalFormBuilder()
        normalized = builder._normalize_dnsrewrite("NOERROR;A;1.2.3.4")
        assert normalized == "NOERROR;A;1.2.3.4"
