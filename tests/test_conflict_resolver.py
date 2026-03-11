"""
Tests for conflict_resolver.py

This module tests the ConflictResolver class which handles conflicts between
whitelist and blacklist rules according to the design in Section 7.1 of the
advanced-variants-design.md document.

Key concepts tested:
- Registration pattern: Large blacklist + small whitelist exception
- Full coverage: Whitelist covers all related blacklists (both sides eliminated)
- Partial coverage: Whitelist covers only some blacklists
- Exception (@@) rules covering DNS blacklists
- Edge cases: Empty lists, non-exception rules
"""
import pytest

from src.conflict_resolver import ConflictResolver
from src.semantic.parser import RuleParser
from src.semantic.types import ParsedRule, RuleType


class TestConflictResolverRegistrationPattern:
    """
    Test detection of "big blacklist, small whitelist" registration patterns.

    Registration pattern occurs when:
    - Blacklist has broad coverage (e.g., ||example.com^)
    - Whitelist has narrow exception (e.g., @@||api.example.com^)
    - In this case, both rules should be preserved
    """

    def test_registration_pattern_basic(self):
        """
        Blacklist: ||example.com^ (broad)
        Whitelist: @@||api.example.com^ (narrow)
        Expected: Both preserved (registration pattern)
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||example.com^")
        white = parser.parse("@@||api.example.com^")

        assert black is not None
        assert white is not None
        assert white.is_exception is True

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is True

    def test_registration_pattern_resolve(self):
        """
        Registration pattern detected → both rules preserved.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        blacklist = [parser.parse("||example.com^")]
        whitelist = [parser.parse("@@||api.example.com^")]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 1, "Blacklist should be preserved"
        assert len(kept_white) == 1, "Whitelist should be preserved"
        assert kept_black[0].raw == "||example.com^"
        assert kept_white[0].raw == "@@||api.example.com^"

    def test_registration_pattern_deep_subdomain(self):
        """
        Blacklist: ||company.com^
        Whitelist: @@||api.v2.service.company.com^
        Should still be detected as registration pattern.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||company.com^")
        white = parser.parse("@@||api.v2.service.company.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is True

    def test_not_registration_pattern_exact_match(self):
        """
        Blacklist: ||example.com^
        Whitelist: @@||example.com^
        This is full cancellation, not registration pattern.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||example.com^")
        white = parser.parse("@@||example.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False

    def test_not_registration_pattern_no_wildcard_blacklist(self):
        """
        Blacklist: example.com (exact, no ||)
        Without || prefix on blacklist, it's not a "big" blacklist.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("example.com")
        white = parser.parse("@@||api.example.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False


class TestConflictResolverFullCoverage:
    """
    Test full coverage: whitelist covers ALL related blacklists.

    When full coverage is detected, BOTH whitelist AND blacklists are
    eliminated (per requirement: '完全冲突的就完全消除掉两者').
    """

    def test_full_coverage_eliminates_both_sides(self):
        """
        Whitelist: ||company.com^
        Blacklists: [mail.company.com, docs.company.com]
        Expected: All blacklists AND the whitelist eliminated
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||company.com^")]
        blacklist = [
            parser.parse("mail.company.com"),
            parser.parse("docs.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0, "All blacklists should be eliminated"
        assert len(kept_white) == 0, "Whitelist should also be eliminated (full coverage)"

    def test_full_coverage_with_wildcards(self):
        """
        Whitelist: ||company.com^
        Blacklists: [||mail.company.com^, ||docs.company.com^]
        Expected: All eliminated including whitelist
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||company.com^")]
        blacklist = [
            parser.parse("||mail.company.com^"),
            parser.parse("||docs.company.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0
        assert len(kept_white) == 0

    def test_full_coverage_mixed_types(self):
        """
        Whitelist: ||company.com^
        Blacklists: hosts + dns_filter + domain_only
        All eliminated.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||company.com^")]
        blacklist = [
            parser.parse("0.0.0.0 mail.company.com"),
            parser.parse("||docs.company.com^"),
            parser.parse("apps.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0


class TestConflictResolverExceptionCoverage:
    """
    Test that @@-prefixed exception rules can cover DNS blacklists.

    This is a core requirement: @@||example.com^ should be able to
    cover/eliminate ||sub.example.com^ blacklist rules.
    """

    def test_exception_covers_dns_filter(self):
        """
        Whitelist: @@||example.com^ (EXCEPTION type)
        Blacklist: [sub.example.com] (DOMAIN_ONLY type)
        Expected: Blacklist eliminated by exception rule coverage.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||example.com^")]
        blacklist = [parser.parse("sub.example.com")]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0, "Exception rule should cover domain-only blacklist"

    def test_exception_covers_dns_wildcard(self):
        """
        Whitelist: @@||example.com^
        Blacklist: [||sub.example.com^]
        Expected: DNS filter blacklist eliminated.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||example.com^")]
        blacklist = [parser.parse("||sub.example.com^")]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0, "Exception rule should cover DNS filter blacklist"

    def test_exception_exact_domain_full_cancel(self):
        """
        Whitelist: @@||example.com^
        Blacklist: [||example.com^]
        Same domain → full cancellation, both eliminated.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||example.com^")]
        blacklist = [parser.parse("||example.com^")]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0
        assert len(kept_white) == 0


class TestConflictResolverPartialCoverage:
    """
    Test partial coverage: whitelist covers only SOME blacklists.
    Only covered blacklists eliminated; whitelist preserved.
    """

    def test_partial_coverage_single_subdomain(self):
        """
        Whitelist: ||api.company.com^ (only covers api)
        Blacklists: [mail.company.com, api.company.com]
        Expected: Only api.company.com eliminated, mail kept, whitelist kept
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||api.company.com^")]
        blacklist = [
            parser.parse("mail.company.com"),
            parser.parse("api.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 1
        assert kept_black[0].normalized_domain == "mail.company.com"

    def test_partial_coverage_wildcard_vs_exact(self):
        """
        Whitelist: ||api.company.com^
        Blacklists: [api.company.com, v2.api.company.com, mail.company.com]
        Expected: api+v2.api eliminated, mail kept
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||api.company.com^")]
        blacklist = [
            parser.parse("api.company.com"),
            parser.parse("v2.api.company.com"),
            parser.parse("mail.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 1
        assert kept_black[0].normalized_domain == "mail.company.com"


class TestConflictResolverNoException:
    """
    Test that non-exception rules behave correctly on the is_exception flag.
    """

    def test_no_exception_not_registration(self):
        """Non-exception whitelist should not be treated as registration pattern."""
        resolver = ConflictResolver()
        parser = RuleParser()

        white = parser.parse("||api.example.com^")
        black = parser.parse("||example.com^")

        white.is_exception = False

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False

    def test_whitelist_without_exception_marker(self):
        """A rule without @@ prefix should not have is_exception=True."""
        parser = RuleParser()

        rule = parser.parse("||example.com^")

        assert rule.is_exception is False
        assert rule.rule_type == RuleType.DNS_FILTER


class TestConflictResolverEdgeCases:
    """Test edge cases for the ConflictResolver."""

    def test_resolve_with_no_whitelist(self):
        """Empty whitelist → all blacklists preserved."""
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = []
        blacklist = [
            parser.parse("||example.com^"),
            parser.parse("||test.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 2
        assert len(kept_white) == 0

    def test_resolve_with_no_blacklist(self):
        """Empty blacklist → both empty."""
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||example.com^")]
        blacklist = []

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0

    def test_resolve_with_both_empty(self):
        """Both empty → both empty."""
        resolver = ConflictResolver()

        kept_black, kept_white = resolver.resolve([], [])

        assert len(kept_black) == 0
        assert len(kept_white) == 0

    def test_whitelist_no_related_blacklists(self):
        """Whitelist with no related blacklists → whitelist eliminated (no purpose)."""
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||unrelated.com^")]
        blacklist = [
            parser.parse("||example.com^"),
            parser.parse("||test.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 2, "All blacklists should be preserved"
        assert len(kept_white) == 0, "Orphan whitelist should be eliminated"


class TestConflictResolverMultipleWhitelists:
    """Test scenarios with multiple whitelist rules."""

    def test_multiple_whitelists_coverage(self):
        """
        Whitelist 1: ||api.company.com^ (covers api)
        Whitelist 2: ||mail.company.com^ (covers mail)
        Blacklists: [api, mail, docs]
        Expected: api and mail eliminated, docs kept
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [
            parser.parse("||api.company.com^"),
            parser.parse("||mail.company.com^")
        ]
        blacklist = [
            parser.parse("api.company.com"),
            parser.parse("mail.company.com"),
            parser.parse("docs.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 1
        assert kept_black[0].normalized_domain == "docs.company.com"

    def test_overlapping_whitelists(self):
        """
        Whitelist 1: ||company.com^ (covers all)
        Whitelist 2: ||api.company.com^ (redundant)
        Blacklists: [api.company.com, mail.company.com]
        Expected: All blacklists eliminated
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [
            parser.parse("||company.com^"),
            parser.parse("||api.company.com^")
        ]
        blacklist = [
            parser.parse("api.company.com"),
            parser.parse("mail.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0


class TestConflictResolverInternalMethods:
    """Test internal helper methods of ConflictResolver."""

    def test_group_by_domain(self):
        """Rules grouped by normalized_domain."""
        resolver = ConflictResolver()
        parser = RuleParser()

        rules = [
            parser.parse("mail.company.com"),
            parser.parse("docs.company.com"),
            parser.parse("api.test.com")
        ]

        groups = resolver._group_by_domain(rules)

        assert "mail.company.com" in groups
        assert "docs.company.com" in groups
        assert "api.test.com" in groups

    def test_find_related_blacklists(self):
        """Should find blacklists related to a given whitelist."""
        resolver = ConflictResolver()
        parser = RuleParser()

        white = parser.parse("||api.company.com^")
        blacklists = [
            parser.parse("||company.com^"),
            parser.parse("mail.company.com"),
            parser.parse("||other.com^")
        ]

        domain_groups = resolver._group_by_domain(blacklists)
        related = resolver._find_related_blacklists(white, domain_groups)

        assert len(related) >= 1
        assert any(r.normalized_domain == "company.com" for r in related)

    def test_find_covered_batch(self):
        """Should find all blacklists covered by a whitelist."""
        resolver = ConflictResolver()
        parser = RuleParser()

        white = parser.parse("||company.com^")
        blacks = [
            parser.parse("mail.company.com"),
            parser.parse("docs.company.com"),
            parser.parse("other.com")
        ]

        covered = resolver._find_covered_batch(white, blacks)

        assert len(covered) == 2
        covered_domains = {b.normalized_domain for b in covered}
        assert "mail.company.com" in covered_domains
        assert "docs.company.com" in covered_domains
        assert "other.com" not in covered_domains
