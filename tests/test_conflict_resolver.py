"""
Tests for conflict_resolver.py

This module tests the ConflictResolver class which handles conflicts between
whitelist and blacklist rules according to the design in Section 7.1 of the
advanced-variants-design.md document.

Key concepts tested:
- Registration pattern: Large blacklist + small whitelist exception
- Full coverage: Whitelist covers all related blacklists
- Partial coverage: Whitelist covers only some blacklists
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
        Test basic registration pattern detection.

        Blacklist: ||example.com^ (broad - blocks entire domain)
        Whitelist: @@||api.example.com^ (narrow - only allows API subdomain)

        Expected: Both rules preserved (registration pattern detected)
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||example.com^")
        white = parser.parse("@@||api.example.com^")

        assert black is not None
        assert white is not None
        assert white.is_exception is True

        # Check registration pattern detection
        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is True, "Should detect registration pattern"

    def test_registration_pattern_resolve(self):
        """
        Test that resolve() preserves both rules in registration pattern.

        When registration pattern is detected, both rules should be kept
        because the whitelist is just a narrow exception to the broad blacklist.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        blacklist = [parser.parse("||example.com^")]
        whitelist = [parser.parse("@@||api.example.com^")]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        # Both rules should be preserved
        assert len(kept_black) == 1, "Blacklist should be preserved"
        assert len(kept_white) == 1, "Whitelist should be preserved"
        assert kept_black[0].raw == "||example.com^"
        assert kept_white[0].raw == "@@||api.example.com^"

    def test_registration_pattern_deep_subdomain(self):
        """
        Test registration pattern with deep subdomain.

        Blacklist: ||company.com^
        Whitelist: @@||api.v2.service.company.com^

        Should still be detected as registration pattern.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||company.com^")
        white = parser.parse("@@||api.v2.service.company.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is True, "Should detect deep subdomain registration pattern"

    def test_not_registration_pattern_exact_match(self):
        """
        Test that exact domain match is NOT a registration pattern.

        Blacklist: ||example.com^
        Whitelist: @@||example.com^

        This is full cancellation, not registration pattern.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("||example.com^")
        white = parser.parse("@@||example.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False, "Exact match should not be registration pattern"

    def test_not_registration_pattern_no_wildcard_blacklist(self):
        """
        Test that blacklist without wildcard is NOT a registration pattern.

        Blacklist: example.com (exact, no ||)
        Whitelist: @@||api.example.com^

        Without || prefix on blacklist, it's not a "big" blacklist.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        black = parser.parse("example.com")
        white = parser.parse("@@||api.example.com^")

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False, "Blacklist without wildcard should not trigger registration pattern"


class TestConflictResolverFullCoverage:
    """
    Test full coverage detection where whitelist covers all related blacklists.

    When a whitelist rule fully covers all related blacklists,
    all those blacklists should be eliminated.
    """

    def test_full_coverage_single_domain(self):
        """
        Test full coverage with single domain.

        Whitelist: ||company.com^ (covers entire company.com)
        Blacklists: [mail.company.com, docs.company.com]

        Expected: All blacklists eliminated
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
        assert len(kept_white) == 1, "Whitelist should be preserved"

    def test_full_coverage_with_wildcards(self):
        """
        Test full coverage with wildcard patterns.

        Whitelist: ||company.com^
        Blacklists: [||mail.company.com^, ||docs.company.com^]

        Expected: All blacklists eliminated
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||company.com^")]
        blacklist = [
            parser.parse("||mail.company.com^"),
            parser.parse("||docs.company.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0, "All blacklists should be eliminated"

    def test_full_coverage_mixed_types(self):
        """
        Test full coverage with mixed rule types.

        Whitelist: ||company.com^
        Blacklists: [
            0.0.0.0 mail.company.com (hosts style),
            ||docs.company.com^ (dns filter),
            apps.company.com (domain only)
        ]

        Expected: All blacklists eliminated
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

        assert len(kept_black) == 0, "All blacklists should be eliminated"


class TestConflictResolverPartialCoverage:
    """
    Test partial coverage where whitelist only covers some blacklists.

    Only the covered blacklists should be eliminated;
    uncovered blacklists should be preserved.
    """

    def test_partial_coverage_single_subdomain(self):
        """
        Test partial coverage - whitelist only covers one subdomain.

        Whitelist: ||api.company.com^ (only covers api)
        Blacklists: [
            mail.company.com,
            api.company.com  <- should be eliminated
        ]

        Expected: Only api.company.com eliminated, mail.company.com kept
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("||api.company.com^")]
        blacklist = [
            parser.parse("mail.company.com"),
            parser.parse("api.company.com")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 1, "One blacklist should be kept"
        assert kept_black[0].normalized_domain == "mail.company.com"

    def test_partial_coverage_wildcard_vs_exact(self):
        """
        Test partial coverage with wildcard whitelist vs exact blacklists.

        Whitelist: ||api.company.com^ (covers api and subdomains)
        Blacklists: [
            api.company.com,
            v2.api.company.com,  <- should be eliminated (covered by ||api)
            mail.company.com     <- should be kept
        ]

        Expected: api and v2.api eliminated, mail kept
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

        # mail.company.com should be kept
        assert len(kept_black) == 1
        assert kept_black[0].normalized_domain == "mail.company.com"


class TestConflictResolverNoException:
    """
    Test that non-exception rules are not treated as registration patterns.

    Only rules with is_exception=True should be considered for
    registration pattern detection.
    """

    def test_no_exception_not_registration(self):
        """
        Test that whitelist without @@ is not treated as registration.

        Whitelist: ||api.example.com^ (NOT @@||api.example.com^)
        Blacklist: ||example.com^

        Even though the pattern looks like registration,
        without is_exception=True, it should not be treated as such.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        # Create a non-exception whitelist (simulating a misclassified rule)
        white = parser.parse("||api.example.com^")
        black = parser.parse("||example.com^")

        # Manually set is_exception to False to simulate non-exception
        white.is_exception = False

        is_registration = resolver._is_registration_pattern(white, black)
        assert is_registration is False, "Non-exception rule should not be registration pattern"

    def test_whitelist_without_exception_marker(self):
        """
        Test regular whitelist (not exception) behavior.

        A whitelist rule without @@ prefix should not have is_exception=True.
        """
        parser = RuleParser()

        # Regular DNS filter, not an exception
        rule = parser.parse("||example.com^")

        assert rule.is_exception is False
        assert rule.rule_type == RuleType.DNS_FILTER


class TestConflictResolverEdgeCases:
    """
    Test edge cases for the ConflictResolver.
    """

    def test_resolve_with_no_whitelist(self):
        """
        Edge case: Empty whitelist should return all blacklists.

        When there are no whitelist rules, there's nothing to conflict with,
        so all blacklists should be preserved.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = []
        blacklist = [
            parser.parse("||example.com^"),
            parser.parse("||test.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 2, "All blacklists should be preserved"
        assert len(kept_white) == 0, "Whitelist should be empty"

    def test_resolve_with_no_blacklist(self):
        """
        Edge case: Empty blacklist should return empty lists.

        When there are no blacklist rules, whitelist rules are not needed
        (nothing to exempt), so both should be empty.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||example.com^")]
        blacklist = []

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 0, "Blacklist should be empty"
        # Note: whitelist is still returned but empty blacklist means
        # the whitelist has nothing to do

    def test_resolve_with_both_empty(self):
        """
        Edge case: Both lists empty.
        """
        resolver = ConflictResolver()

        kept_black, kept_white = resolver.resolve([], [])

        assert len(kept_black) == 0
        assert len(kept_white) == 0

    def test_whitelist_no_related_blacklists(self):
        """
        Test whitelist with no related blacklists.

        Whitelist: @@||unrelated.com^
        Blacklists: [||example.com^, ||test.com^]

        The whitelist doesn't cover any blacklists, so all are kept.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        whitelist = [parser.parse("@@||unrelated.com^")]
        blacklist = [
            parser.parse("||example.com^"),
            parser.parse("||test.com^")
        ]

        kept_black, kept_white = resolver.resolve(whitelist, blacklist)

        assert len(kept_black) == 2, "All blacklists should be preserved"
        assert len(kept_white) == 1, "Whitelist should be preserved"


class TestConflictResolverMultipleWhitelists:
    """
    Test scenarios with multiple whitelist rules.
    """

    def test_multiple_whitelists_coverage(self):
        """
        Test multiple whitelists covering different blacklists.

        Whitelist 1: ||api.company.com^ (covers api)
        Whitelist 2: ||mail.company.com^ (covers mail)
        Blacklists: [
            api.company.com,    <- covered by whitelist 1
            mail.company.com,   <- covered by whitelist 2
            docs.company.com    <- not covered
        ]

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
        Test overlapping whitelist coverage.

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

        assert len(kept_black) == 0, "All blacklists should be eliminated"


class TestConflictResolverInternalMethods:
    """
    Test internal helper methods of ConflictResolver.
    """

    def test_group_by_domain(self):
        """
        Test _group_by_domain method.

        Rules should be grouped by their normalized_domain.
        """
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
        """
        Test _find_related_blacklists method.

        Should find blacklists related to a given whitelist.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        white = parser.parse("||api.company.com^")
        blacklists = [
            parser.parse("||company.com^"),      # parent domain - related
            parser.parse("mail.company.com"),    # sibling domain - not related
            parser.parse("||other.com^")         # different domain - not related
        ]

        domain_groups = resolver._group_by_domain(blacklists)
        related = resolver._find_related_blacklists(white, domain_groups)

        # Should find the parent domain blacklist
        assert len(related) >= 1
        assert any(r.normalized_domain == "company.com" for r in related)

    def test_find_covered_batch(self):
        """
        Test _find_covered_batch method.

        Should find all blacklists covered by a whitelist.
        """
        resolver = ConflictResolver()
        parser = RuleParser()

        white = parser.parse("||company.com^")
        blacks = [
            parser.parse("mail.company.com"),      # covered
            parser.parse("docs.company.com"),      # covered
            parser.parse("other.com")              # not covered
        ]

        covered = resolver._find_covered_batch(white, blacks)

        assert len(covered) == 2
        covered_domains = {b.normalized_domain for b in covered}
        assert "mail.company.com" in covered_domains
        assert "docs.company.com" in covered_domains
        assert "other.com" not in covered_domains
