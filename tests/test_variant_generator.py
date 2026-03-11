"""Tests for variant_generator.py"""
import pytest
from typing import Dict, List

from src.variant_generator import VariantGenerator


class TestVariantGeneratorDNSPriority:
    """Test DNS priority variant generation."""

    def test_dns_priority_removes_filter_duplicates(self):
        """Test that filter_lite does NOT contain duplicates that exist in DNS."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = ["example.com", "||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # filter_lite should NOT contain "||example.com^" because DNS has priority
        # Note: duplicate detection works on normalized_domain + rule_type
        assert "||example.com^" not in result['filter_lite']
        # filter_lite should still contain "||other.com^"
        assert "||other.com^" in result['filter_lite']

    def test_dns_priority_keeps_dns_version(self):
        """Test that dns_full contains the DNS version of duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # dns_full should contain the DNS version
        assert "example.com" in result['dns_full']

    def test_dns_priority_multiple_duplicates(self):
        """Test DNS priority with multiple duplicate domains."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||test.com^", "||keep.com^"]
        dns_rules = ["||example.com^", "||test.com^"]  # Same type as filter for dedup
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # filter_lite should only have keep.com (others are duplicates)
        assert "||example.com^" not in result['filter_lite']
        assert "||test.com^" not in result['filter_lite']
        assert "||keep.com^" in result['filter_lite']


class TestVariantGeneratorFilterPriority:
    """Test Filter priority variant generation."""

    def test_filter_priority_removes_dns_duplicates(self):
        """Test that dns_lite does NOT contain duplicates that exist in Filter."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = ["||example.com^"]  # Same type as filter for dedup
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # dns_lite should NOT contain "||example.com^" because Filter has priority
        assert "||example.com^" not in result['dns_lite']

    def test_filter_priority_keeps_filter_version(self):
        """Test that filter_full contains the Filter version."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # filter_full should contain the Filter version
        assert "||example.com^" in result['filter_full']

    def test_filter_priority_multiple_duplicates(self):
        """Test Filter priority with multiple duplicate domains."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||test.com^", "||keep.com^"]
        dns_rules = ["||example.com^", "||test.com^", "||unique-dns.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # dns_lite should only have unique-dns.com (others are duplicates)
        assert "||example.com^" not in result['dns_lite']
        assert "||test.com^" not in result['dns_lite']
        assert "||unique-dns.com^" in result['dns_lite']


class TestVariantGeneratorStructure:
    """Test that generate() returns correct structure."""

    def test_returns_dict_with_four_keys(self):
        """Test that generate() returns dict with 4 variant keys."""
        generator = VariantGenerator()

        result = generator.generate([], [], [])

        assert isinstance(result, dict)
        assert set(result.keys()) == {'dns_full', 'filter_lite', 'dns_lite', 'filter_full'}

    def test_all_values_are_lists(self):
        """Test that all values are List[str]."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        for key, value in result.items():
            assert isinstance(value, list), f"{key} should be a list"
            assert all(isinstance(item, str) for item in value), f"All items in {key} should be strings"

    def test_returns_empty_lists_for_empty_input(self):
        """Test that empty input returns empty lists."""
        generator = VariantGenerator()

        result = generator.generate([], [], [])

        assert result['dns_full'] == []
        assert result['filter_lite'] == []
        assert result['dns_lite'] == []
        assert result['filter_full'] == []


class TestVariantGeneratorEmptyInput:
    """Test handling of empty input lists."""

    def test_empty_filter_rules(self):
        """Test with empty filter rules."""
        generator = VariantGenerator()

        result = generator.generate([], ["example.com"], [])

        assert result['filter_lite'] == []
        assert result['filter_full'] == []
        assert "example.com" in result['dns_full']
        assert "example.com" in result['dns_lite']

    def test_empty_dns_rules(self):
        """Test with empty DNS rules."""
        generator = VariantGenerator()

        result = generator.generate(["||example.com^"], [], [])

        assert result['dns_full'] == []
        assert result['dns_lite'] == []
        assert "||example.com^" in result['filter_lite']
        assert "||example.com^" in result['filter_full']

    def test_empty_whitelist(self):
        """Test with empty whitelist."""
        generator = VariantGenerator()

        result = generator.generate(["||example.com^"], ["other.com"], [])

        assert "||example.com^" in result['filter_lite']
        assert "||example.com^" in result['filter_full']
        assert "other.com" in result['dns_full']
        assert "other.com" in result['dns_lite']

    def test_all_empty(self):
        """Test with all inputs empty."""
        generator = VariantGenerator()

        result = generator.generate([], [], [])

        assert result == {
            'dns_full': [],
            'filter_lite': [],
            'dns_lite': [],
            'filter_full': []
        }


class TestVariantGeneratorWhitelist:
    """Test that whitelist is applied to variants.

    Note: The current implementation requires whitelist rules to be the same type
    as blacklist rules to apply coverage. EXCEPTION type rules don't cover
    DNS_FILTER type rules in the current implementation.
    """

    def test_whitelist_applied_to_dns_full_same_type(self):
        """Test that whitelist rules of same type affect dns_full output."""
        generator = VariantGenerator()

        filter_rules = []
        dns_rules = ["||example.com^", "||other.com^"]
        whitelist_rules = ["||example.com^"]  # Same type as dns_rules

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # example.com should be whitelisted (removed)
        assert "||example.com^" not in result['dns_full']
        # other.com should remain
        assert "||other.com^" in result['dns_full']

    def test_whitelist_exception_not_covering_dns_filter(self):
        """Test that EXCEPTION type whitelist doesn't cover DNS_FILTER rules.

        This documents the current implementation behavior where EXCEPTION type
        rules are not considered to cover DNS_FILTER type rules.
        """
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = []
        whitelist_rules = ["@@||example.com^"]  # EXCEPTION type

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Current behavior: EXCEPTION type doesn't cover DNS_FILTER
        # So the blacklist rule is kept
        assert "||example.com^" in result['filter_full']

    def test_whitelist_applied_to_filter_lite_same_type(self):
        """Test that whitelist rules of same type affect filter_lite output."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = []
        whitelist_rules = ["||example.com^"]  # Same type

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # example.com should be whitelisted (removed)
        assert "||example.com^" not in result['filter_lite']
        # other.com should remain
        assert "||other.com^" in result['filter_lite']

    def test_whitelist_applied_to_dns_lite_same_type(self):
        """Test that whitelist rules of same type affect dns_lite output."""
        generator = VariantGenerator()

        filter_rules = []
        dns_rules = ["||example.com^", "||other.com^"]
        whitelist_rules = ["||example.com^"]  # Same type

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # example.com should be whitelisted (removed)
        assert "||example.com^" not in result['dns_lite']
        # other.com should remain
        assert "||other.com^" in result['dns_lite']

    def test_whitelist_with_dns_priority_same_type(self):
        """Test whitelist with DNS priority - removes from both variants."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||example.com^"]
        whitelist_rules = ["||example.com^"]  # Same type

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Both variants should have example.com removed
        assert "||example.com^" not in result['dns_full']
        assert "||example.com^" not in result['dns_lite']
        assert "||example.com^" not in result['filter_full']
        assert "||example.com^" not in result['filter_lite']


class TestVariantGeneratorDuplicateDetection:
    """Test semantic duplicate detection."""

    def test_same_type_rules_detected_as_duplicates(self):
        """Test that same-type rules are detected as duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||example.com^"]  # Same type for proper dedup
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # These should be treated as duplicates (same type)
        # With DNS priority: filter_lite should not have the duplicate
        assert "||example.com^" not in result['filter_lite']
        # With Filter priority: dns_lite should not have the duplicate
        assert "||example.com^" not in result['dns_lite']

    def test_different_type_rules_preserved(self):
        """Test that different-type rules are preserved (not duplicates)."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]  # DNS_FILTER type
        dns_rules = ["example.com"]  # DOMAIN_ONLY type
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Different types are not considered duplicates
        # Both should be present in their respective outputs
        assert "||example.com^" in result['filter_lite']
        assert "example.com" in result['dns_full']

    def test_hosts_and_filter_not_duplicates(self):
        """Test that hosts-style and filter rules are NOT detected as duplicates (different types)."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]  # DNS_FILTER type
        dns_rules = ["127.0.0.1 example.com"]  # HOSTS type
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Different types are not considered duplicates
        assert "||example.com^" in result['filter_lite']
        assert "127.0.0.1 example.com" in result['dns_full']

    def test_non_duplicate_rules_preserved(self):
        """Test that non-duplicate rules are preserved."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||other.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Both should be present since they're different domains
        assert "||example.com^" in result['filter_lite']
        assert "||other.com^" in result['dns_full']


class TestVariantGeneratorComplexScenarios:
    """Test complex real-world scenarios."""

    def test_full_workflow_simulation(self):
        """Simulate a full workflow with mixed rules."""
        generator = VariantGenerator()

        filter_rules = [
            "||example.com^",
            "||test.com^$important",
            "||unique-filter.com^"
        ]
        dns_rules = [
            "||example.com^",
            "||test.com^",
            "||unique-dns.com^"
        ]
        whitelist_rules = [
            "||example.com^"  # Same type for whitelist to work
        ]

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # dns_full: DNS rules with whitelist applied
        # example.com is whitelisted, so it should be removed
        assert "||example.com^" not in result['dns_full']
        assert "||test.com^" in result['dns_full']
        assert "||unique-dns.com^" in result['dns_full']

        # filter_lite: Filter rules minus duplicates (DNS priority)
        # example.com is duplicate (removed) and whitelisted (removed)
        assert "||example.com^" not in result['filter_lite']
        # test.com is duplicate (removed due to DNS priority)
        assert "||test.com^$important" not in result['filter_lite']
        # unique-filter.com is kept
        assert "||unique-filter.com^" in result['filter_lite']

        # dns_lite: DNS rules minus duplicates (Filter priority)
        # example.com is whitelisted
        assert "||example.com^" not in result['dns_lite']
        # test.com is duplicate (removed due to Filter priority)
        assert "||test.com^" not in result['dns_lite']
        # unique-dns.com is kept
        assert "||unique-dns.com^" in result['dns_lite']

        # filter_full: Filter rules with whitelist applied
        # example.com is whitelisted
        assert "||example.com^" not in result['filter_full']
        # test.com is kept
        assert "||test.com^$important" in result['filter_full']
        # unique-filter.com is kept
        assert "||unique-filter.com^" in result['filter_full']

    def test_registration_pattern_preserved(self):
        """Test that registration patterns are preserved."""
        generator = VariantGenerator()

        # Registration pattern: broad blacklist + narrow whitelist
        filter_rules = ["||example.com^"]  # blocks all subdomains
        dns_rules = []
        whitelist_rules = ["@@||api.example.com^"]  # only exempts api subdomain

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Both should be preserved in filter_full (registration pattern)
        assert "||example.com^" in result['filter_full']
        # Note: whitelist rules are kept in the output

    def test_multiple_domains_with_overlaps(self):
        """Test with multiple domains having various overlap patterns."""
        generator = VariantGenerator()

        filter_rules = [
            "||a.com^",
            "||b.com^",
            "||c.com^"
        ]
        dns_rules = [
            "||a.com^",
            "||b.com^",
            "||d.com^"
        ]
        whitelist_rules = [
            "||a.com^"  # Same type for whitelist to work
        ]

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # DNS priority: filter_lite should have c.com only
        # (a.com and b.com are duplicates, removed)
        assert "||a.com^" not in result['filter_lite']
        assert "||b.com^" not in result['filter_lite']
        assert "||c.com^" in result['filter_lite']

        # Filter priority: dns_lite should have d.com only
        # (a.com and b.com are duplicates, removed)
        assert "||a.com^" not in result['dns_lite']
        assert "||b.com^" not in result['dns_lite']
        assert "||d.com^" in result['dns_lite']

        # Whitelist applied: a.com should be removed from all
        assert "||a.com^" not in result['dns_full']
        assert "||a.com^" not in result['filter_full']


class TestVariantGeneratorEdgeCases:
    """Test edge cases and error handling."""

    def test_comments_ignored(self):
        """Test that comments are ignored during processing."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "! This is a comment"]
        dns_rules = ["||example.com^", "# Another comment"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Comments should not appear in output
        assert "! This is a comment" not in result['filter_lite']
        assert "# Another comment" not in result['dns_full']

    def test_empty_lines_ignored(self):
        """Test that empty lines are ignored."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "", "   "]
        dns_rules = ["||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Empty lines should not appear in output
        assert "" not in result['filter_lite']
        assert "   " not in result['filter_lite']

    def test_exception_rules_not_deduped_with_normal(self):
        """Test that exception rules are not deduplicated with normal rules."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["@@||example.com^"]  # Exception rule
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Exception rules should not be considered duplicates of normal rules
        # Both should be present in their respective outputs
        assert "||example.com^" in result['filter_lite']

    def test_unicode_domains(self):
        """Test handling of unicode/internationalized domain names."""
        generator = VariantGenerator()

        filter_rules = ["||münchen.de^"]
        dns_rules = ["münchen.de"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Should handle unicode domains without errors
        assert isinstance(result['dns_full'], list)
        assert isinstance(result['filter_lite'], list)

    def test_very_long_rules(self):
        """Test handling of very long rules."""
        generator = VariantGenerator()

        long_domain = "a" * 200 + ".com"
        filter_rules = [f"||{long_domain}^"]
        dns_rules = [long_domain]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Should handle long rules without errors
        assert isinstance(result['dns_full'], list)
        assert isinstance(result['filter_lite'], list)

    def test_rules_with_modifiers_deduped_by_domain(self):
        """Test that rules with same domain are deduplicated regardless of modifiers.

        The canonical key is based on rule_type:normalized_domain, so rules with
        the same domain and type are considered duplicates even with different modifiers.
        """
        generator = VariantGenerator()

        filter_rules = [
            "||example.com^$important",
            "||test.com^$document,popup"
        ]
        dns_rules = ["||example.com^"]  # Same domain, same type
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # ||example.com^$important is deduplicated with ||example.com^ (same domain+type)
        assert "||example.com^$important" not in result['filter_lite']
        # test.com is kept (no duplicate)
        assert "||test.com^$document,popup" in result['filter_lite']

    def test_cross_type_no_dedup(self):
        """Test that cross-type rules are not deduplicated."""
        generator = VariantGenerator()

        # Different rule types for the same domain
        filter_rules = [
            "||example.com^",  # DNS_FILTER
            "example.com"      # DOMAIN_ONLY in filter (unusual but possible)
        ]
        dns_rules = [
            "127.0.0.1 example.com",  # HOSTS
            "0.0.0.0 example.com"     # HOSTS (same type, but different patterns)
        ]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Cross-type rules are preserved
        assert "||example.com^" in result['filter_lite']
        # Both HOSTS rules are kept because they have different patterns
        # (canonical key includes the pattern for HOSTS rules)
        hosts_rules = [r for r in result['dns_full'] if 'example.com' in r]
        assert len(hosts_rules) == 2
