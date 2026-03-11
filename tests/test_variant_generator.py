"""Tests for variant_generator.py"""
import pytest
from typing import Dict, List

from src.variant_generator import VariantGenerator


class TestVariantGeneratorDNSPriority:
    """Test DNS priority variant generation."""

    def test_dns_priority_removes_filter_duplicates(self):
        """filter_lite should NOT contain duplicates that exist in DNS."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = ["||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # filter_lite should NOT contain "||example.com^" because DNS has priority
        assert "||example.com^" not in result['filter_lite']
        assert "||other.com^" in result['filter_lite']

    def test_dns_priority_keeps_dns_version(self):
        """dns_full contains the DNS version of duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "example.com" in result['dns_full']

    def test_dns_priority_multiple_duplicates(self):
        """DNS priority with multiple duplicate domains."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||test.com^", "||keep.com^"]
        dns_rules = ["||example.com^", "||test.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['filter_lite']
        assert "||test.com^" not in result['filter_lite']
        assert "||keep.com^" in result['filter_lite']


class TestVariantGeneratorFilterPriority:
    """Test Filter priority variant generation."""

    def test_filter_priority_removes_dns_duplicates(self):
        """dns_lite should NOT contain duplicates that exist in Filter."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = ["||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['dns_lite']

    def test_filter_priority_keeps_filter_version(self):
        """filter_full contains the Filter version."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" in result['filter_full']

    def test_filter_priority_multiple_duplicates(self):
        """Filter priority with multiple duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||test.com^", "||keep.com^"]
        dns_rules = ["||example.com^", "||test.com^", "||unique-dns.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['dns_lite']
        assert "||test.com^" not in result['dns_lite']
        assert "||unique-dns.com^" in result['dns_lite']


class TestVariantGeneratorStructure:
    """Test that generate() returns correct structure."""

    def test_returns_dict_with_four_keys(self):
        generator = VariantGenerator()
        result = generator.generate([], [], [])
        assert isinstance(result, dict)
        assert set(result.keys()) == {'dns_full', 'filter_lite', 'dns_lite', 'filter_full'}

    def test_all_values_are_lists(self):
        generator = VariantGenerator()
        result = generator.generate(["||example.com^"], ["example.com"], [])
        for key, value in result.items():
            assert isinstance(value, list), f"{key} should be a list"
            assert all(isinstance(item, str) for item in value)

    def test_returns_empty_lists_for_empty_input(self):
        generator = VariantGenerator()
        result = generator.generate([], [], [])
        assert result == {'dns_full': [], 'filter_lite': [], 'dns_lite': [], 'filter_full': []}


class TestVariantGeneratorEmptyInput:
    """Test handling of empty input lists."""

    def test_empty_filter_rules(self):
        generator = VariantGenerator()
        result = generator.generate([], ["example.com"], [])

        assert result['filter_lite'] == []
        assert result['filter_full'] == []
        assert "example.com" in result['dns_full']
        assert "example.com" in result['dns_lite']

    def test_empty_dns_rules(self):
        generator = VariantGenerator()
        result = generator.generate(["||example.com^"], [], [])

        assert result['dns_full'] == []
        assert result['dns_lite'] == []
        assert "||example.com^" in result['filter_lite']
        assert "||example.com^" in result['filter_full']

    def test_empty_whitelist(self):
        generator = VariantGenerator()
        result = generator.generate(["||example.com^"], ["other.com"], [])

        assert "||example.com^" in result['filter_lite']
        assert "||example.com^" in result['filter_full']
        assert "other.com" in result['dns_full']
        assert "other.com" in result['dns_lite']

    def test_all_empty(self):
        generator = VariantGenerator()
        result = generator.generate([], [], [])
        assert result == {
            'dns_full': [], 'filter_lite': [],
            'dns_lite': [], 'filter_full': []
        }


class TestVariantGeneratorWhitelist:
    """Test that whitelist is properly merged into variants.

    Whitelist rules are merged into output. After conflict resolution:
    - Full coverage → both whitelist and blacklist eliminated
    - Registration pattern → both whitelist and blacklist preserved
    - Partial coverage → covered blacklist eliminated, whitelist preserved
    """

    def test_whitelist_same_type_eliminates_blacklist(self):
        """Same-type whitelist covers blacklist → both eliminated."""
        generator = VariantGenerator()

        filter_rules = []
        dns_rules = ["||example.com^", "||other.com^"]
        whitelist_rules = ["||example.com^"]  # Same type, full cover

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['dns_full']
        assert "||other.com^" in result['dns_full']

    def test_exception_whitelist_covers_dns_filter(self):
        """@@-prefixed whitelist SHOULD cover DNS blacklists (fixed behavior)."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||other.com^"]
        dns_rules = []
        whitelist_rules = ["@@||example.com^"]  # EXCEPTION type

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # @@||example.com^ should cover ||example.com^ → both eliminated
        assert "||example.com^" not in result['filter_full']
        assert "||other.com^" in result['filter_full']

    def test_whitelist_registration_pattern_preserved(self):
        """Registration pattern → both whitelist and blacklist in output."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]  # broad blacklist
        dns_rules = []
        whitelist_rules = ["@@||api.example.com^"]  # narrow exception

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Registration pattern: both should be preserved
        assert "||example.com^" in result['filter_full']
        assert "@@||api.example.com^" in result['filter_full']

    def test_whitelist_merged_into_output(self):
        """Surviving whitelist rules should appear in the output."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = []
        whitelist_rules = ["@@||api.example.com^"]  # registration pattern → survives

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # The white rule survives (registration pattern) and is in output
        assert "@@||api.example.com^" in result['filter_full']
        assert "@@||api.example.com^" in result['filter_lite']

    def test_whitelist_with_dns_priority_removes_from_all(self):
        """Full-coverage whitelist removes blacklist from ALL variants."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||example.com^"]
        whitelist_rules = ["||example.com^"]  # Same type, full cover

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['dns_full']
        assert "||example.com^" not in result['dns_lite']
        assert "||example.com^" not in result['filter_full']
        assert "||example.com^" not in result['filter_lite']


class TestVariantGeneratorDuplicateDetection:
    """Test semantic duplicate detection using CanonicalFormBuilder."""

    def test_same_type_rules_detected_as_duplicates(self):
        """Same canonical key → detected as duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" not in result['filter_lite']
        assert "||example.com^" not in result['dns_lite']

    def test_different_type_rules_preserved(self):
        """Different canonical keys → not duplicates."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]  # DNS_FILTER → dns:block:wildcard:example.com
        dns_rules = ["example.com"]  # DOMAIN_ONLY → dns:block:exact:example.com
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Different canonical keys → not duplicates
        assert "||example.com^" in result['filter_lite']
        assert "example.com" in result['dns_full']

    def test_hosts_and_filter_not_duplicates(self):
        """Hosts-style and DNS filter have different canonical keys."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["127.0.0.1 example.com"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" in result['filter_lite']
        assert "127.0.0.1 example.com" in result['dns_full']

    def test_non_duplicate_rules_preserved(self):
        """Different domains → preserved."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["||other.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" in result['filter_lite']
        assert "||other.com^" in result['dns_full']


class TestVariantGeneratorComplexScenarios:
    """Test complex real-world scenarios."""

    def test_full_workflow_simulation(self):
        """Simulate a full workflow with mixed rules."""
        generator = VariantGenerator()

        filter_rules = [
            "||example.com^",
            "||unique-filter.com^"
        ]
        dns_rules = [
            "||example.com^",
            "||unique-dns.com^"
        ]
        whitelist_rules = [
            "||example.com^"  # Same type, full cover → eliminates example.com
        ]

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # dns_full: DNS rules with whitelist applied
        assert "||example.com^" not in result['dns_full']
        assert "||unique-dns.com^" in result['dns_full']

        # filter_lite: filter minus dns duplicates, then whitelist
        assert "||example.com^" not in result['filter_lite']
        assert "||unique-filter.com^" in result['filter_lite']

        # dns_lite: dns minus filter duplicates, then whitelist
        assert "||example.com^" not in result['dns_lite']
        assert "||unique-dns.com^" in result['dns_lite']

        # filter_full: filter with whitelist
        assert "||example.com^" not in result['filter_full']
        assert "||unique-filter.com^" in result['filter_full']

    def test_registration_pattern_preserved(self):
        """Registration patterns preserved in all variants."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = []
        whitelist_rules = ["@@||api.example.com^"]

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        assert "||example.com^" in result['filter_full']
        assert "@@||api.example.com^" in result['filter_full']

    def test_multiple_domains_with_overlaps(self):
        """Multiple domains with various overlap patterns."""
        generator = VariantGenerator()

        filter_rules = ["||a.com^", "||b.com^", "||c.com^"]
        dns_rules = ["||a.com^", "||b.com^", "||d.com^"]
        whitelist_rules = ["||a.com^"]

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # DNS priority: filter_lite = c.com only (a+b are duplicates)
        assert "||a.com^" not in result['filter_lite']
        assert "||b.com^" not in result['filter_lite']
        assert "||c.com^" in result['filter_lite']

        # Filter priority: dns_lite = d.com only (a+b are duplicates)
        assert "||a.com^" not in result['dns_lite']
        assert "||b.com^" not in result['dns_lite']
        assert "||d.com^" in result['dns_lite']

        # Whitelist: a.com removed from full variants
        assert "||a.com^" not in result['dns_full']
        assert "||a.com^" not in result['filter_full']


class TestVariantGeneratorEdgeCases:
    """Test edge cases and error handling."""

    def test_comments_ignored(self):
        generator = VariantGenerator()
        result = generator.generate(
            ["||example.com^", "! comment"],
            ["||example.com^", "# comment"],
            []
        )
        assert "! comment" not in result['filter_lite']
        assert "# comment" not in result['dns_full']

    def test_empty_lines_ignored(self):
        generator = VariantGenerator()
        result = generator.generate(
            ["||example.com^", "", "   "],
            ["||example.com^"],
            []
        )
        assert "" not in result['filter_lite']
        assert "   " not in result['filter_lite']

    def test_exception_rules_not_deduped_with_normal(self):
        """Exception rules have different canonical keys vs normal rules."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^"]
        dns_rules = ["@@||example.com^"]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Different canonical keys (block vs allow) → not duplicates
        assert "||example.com^" in result['filter_lite']

    def test_unicode_domains(self):
        generator = VariantGenerator()
        result = generator.generate(["||münchen.de^"], ["münchen.de"], [])
        assert isinstance(result['dns_full'], list)

    def test_very_long_rules(self):
        generator = VariantGenerator()
        long_domain = "a" * 200 + ".com"
        result = generator.generate([f"||{long_domain}^"], [long_domain], [])
        assert isinstance(result['dns_full'], list)

    def test_rules_with_different_modifiers_not_deduped(self):
        """Rules with different modifiers have different canonical keys → NOT duplicates.

        CanonicalFormBuilder differentiates modifiers, unlike the old simplified key.
        """
        generator = VariantGenerator()

        filter_rules = [
            "||example.com^$important",  # Has $important modifier
            "||test.com^$document,popup"
        ]
        dns_rules = ["||example.com^"]  # No modifier
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # With CanonicalFormBuilder, $important adds a modifier to the key
        # so ||example.com^$important has a DIFFERENT canonical key than ||example.com^
        # These are NOT considered duplicates
        # BUT: the basic ||example.com^ is a duplicate (same key), so
        # both dns and filter have "dns:block:wildcard:example.com", so the base
        # version is deduped. The $important version has extra modifier → different key → kept.
        assert "||test.com^$document,popup" in result['filter_lite']

    def test_cross_type_no_dedup(self):
        """Cross-type rules with different canonical keys are preserved."""
        generator = VariantGenerator()

        filter_rules = [
            "||example.com^",  # DNS_FILTER
            "example.com"      # DOMAIN_ONLY
        ]
        dns_rules = [
            "127.0.0.1 example.com",  # HOSTS
            "0.0.0.0 example.com"     # HOSTS
        ]
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Different canonical keys → preserved
        assert "||example.com^" in result['filter_lite']

    def test_internal_dedup_removes_duplicates_within_list(self):
        """Phase 1: internal dedup removes exact duplicates within same list."""
        generator = VariantGenerator()

        filter_rules = ["||example.com^", "||example.com^", "||other.com^"]
        dns_rules = []
        whitelist_rules = []

        result = generator.generate(filter_rules, dns_rules, whitelist_rules)

        # Should only have one copy of example.com
        count = result['filter_full'].count("||example.com^")
        assert count == 1
        assert "||other.com^" in result['filter_full']
