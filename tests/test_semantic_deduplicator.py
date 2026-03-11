"""Tests for semantic/deduplicator.py"""
import pytest

from src.semantic.deduplicator import SemanticDeduplicator


class TestDeduplicatorBasic:
    def test_deduplicate_identical_rules(self):
        dedup = SemanticDeduplicator()
        rules = [
            "||example.com^",
            "||example.com^",
        ]

        result = dedup.process_batch(rules)

        assert len(result) == 1
        assert result[0] == "||example.com^"

    def test_deduplicate_equivalent_hosts(self):
        dedup = SemanticDeduplicator()
        rules = [
            "127.0.0.1 example.com",
            "0.0.0.0 example.com",
            "example.com",
        ]

        result = dedup.process_batch(rules)

        # Should keep only one
        assert len(result) == 1

    def test_keep_different_domains(self):
        dedup = SemanticDeduplicator()
        rules = [
            "||example.com^",
            "||example.org^",
        ]

        result = dedup.process_batch(rules)

        assert len(result) == 2

    def test_coverage_replacement(self):
        dedup = SemanticDeduplicator()
        rules = [
            "example.com",           # weaker: exact domain only
            "||example.com^",        # stronger: wildcard subdomain
        ]

        result = dedup.process_batch(rules)

        # Should keep the stronger wildcard rule
        assert len(result) == 1
        assert result[0] == "||example.com^"


class TestDeduplicatorComments:
    def test_skip_comments(self):
        dedup = SemanticDeduplicator()
        rules = [
            "! This is a comment",
            "||example.com^",
            "# Another comment",
        ]

        result = dedup.process_batch(rules)

        # Comments should be skipped (return None)
        assert len(result) == 1
        assert result[0] == "||example.com^"

    def test_skip_empty_lines(self):
        dedup = SemanticDeduplicator()
        rules = [
            "",
            "||example.com^",
            "   ",
        ]

        result = dedup.process_batch(rules)

        assert len(result) == 1
        assert result[0] == "||example.com^"


class TestDeduplicatorStats:
    def test_stats_tracking(self):
        dedup = SemanticDeduplicator()
        rules = [
            "127.0.0.1 example.com",
            "0.0.0.0 example.com",  # deduped (equivalent)
            "||example.com^",       # replaces above (stronger)
            "||example.org^",       # kept
        ]

        dedup.process_batch(rules)
        stats = dedup.get_stats()

        assert stats['total'] == 4
        assert stats['kept'] == 2  # example.com wildcard and example.org
        assert stats['deduped'] == 1  # 0.0.0.0 example.com
        assert stats['replaced'] == 1  # 127.0.0.1 example.com replaced by wildcard

    def test_reset(self):
        dedup = SemanticDeduplicator()
        rules = ["||example.com^"]

        dedup.process_batch(rules)
        stats1 = dedup.get_stats()
        assert stats1['total'] == 1

        dedup.reset()
        stats2 = dedup.get_stats()
        assert stats2['total'] == 0
        assert stats2['kept'] == 0


class TestDeduplicatorExceptions:
    def test_exception_not_deduped_with_normal(self):
        dedup = SemanticDeduplicator()
        rules = [
            "||example.com^",
            "@@||example.com^",  # Exception, should not be deduped
        ]

        result = dedup.process_batch(rules)

        # Both should be kept (exception and normal are different)
        assert len(result) == 2

    def test_two_exceptions_same_domain(self):
        dedup = SemanticDeduplicator()
        rules = [
            "@@||example.com^",
            "@@||example.com^",  # Identical exception
        ]

        result = dedup.process_batch(rules)

        assert len(result) == 1


class TestDeduplicatorModifierEquivalence:
    def test_doc_document_equivalence(self):
        dedup = SemanticDeduplicator()
        rules = [
            "||example.com^$doc",
            "||example.com^$document",
        ]

        result = dedup.process_batch(rules)

        # Should be treated as equivalent after canonicalization
        assert len(result) == 1


class TestDeduplicatorComplexScenarios:
    def test_multiple_sources_simulation(self):
        """Simulate merging from multiple sources"""
        dedup = SemanticDeduplicator()

        # Source 1: hosts style
        source1 = [
            "127.0.0.1 example.com",
            "127.0.0.1 test.com",
        ]

        # Source 2: DNS filter style (some overlap)
        source2 = [
            "||example.com^",  # Should replace 127.0.0.1 example.com
            "||newsite.com^",
        ]

        all_rules = source1 + source2
        result = dedup.process_batch(all_rules)

        # Should have: ||example.com^, test.com, ||newsite.com^
        assert len(result) == 3
        assert "||example.com^" in result
        assert "||newsite.com^" in result

    def test_order_independence_for_equivalence(self):
        """Order shouldn't matter for detecting equivalence"""
        dedup1 = SemanticDeduplicator()
        dedup2 = SemanticDeduplicator()

        rules1 = ["127.0.0.1 example.com", "0.0.0.0 example.com"]
        rules2 = ["0.0.0.0 example.com", "127.0.0.1 example.com"]

        result1 = dedup1.process_batch(rules1)
        result2 = dedup2.process_batch(rules2)

        assert len(result1) == len(result2)
