"""
Variant Generator Module

Generates four variants of AdGuard rules based on DNS and Filter rules:
- dns_full: DNS rules with whitelist, DNS priority
- filter_lite: Filter rules minus duplicates, DNS priority
- dns_lite: DNS rules minus duplicates, Filter priority
- filter_full: Filter rules with whitelist, Filter priority
"""

from typing import Dict, List, Optional, Set, Tuple

from .semantic.parser import RuleParser
from .semantic.deduplicator import SemanticDeduplicator
from .semantic.canonical import CanonicalFormBuilder
from .semantic.types import ParsedRule, RuleType
from .conflict_resolver import ConflictResolver


class VariantGenerator:
    """
    Generates four variants of AdGuard rules.

    Processing phases (per design doc §3.4):
    1. Phase 1: Internal semantic dedup for each input list
    2. Phase 2: Priority dedup (DNS-priority or Filter-priority)
    3. Phase 3: Whitelist merge + conflict resolution + final dedup
    4. Phase 4: Output
    """

    def __init__(self):
        """Initialize the variant generator with required components."""
        self.parser = RuleParser()
        self.deduplicator = SemanticDeduplicator()
        self.canonical = CanonicalFormBuilder()
        self.conflict = ConflictResolver()

    def generate(
        self,
        filter_rules: List[str],
        dns_rules: List[str],
        whitelist_rules: List[str]
    ) -> Dict[str, List[str]]:
        """
        Generate all four variants of rules.

        Args:
            filter_rules: List of filter rule strings
            dns_rules: List of DNS rule strings
            whitelist_rules: List of whitelist rule strings

        Returns:
            Dictionary with four variant lists:
            - 'dns_full': DNS rules with whitelist, DNS priority
            - 'filter_lite': Filter rules minus duplicates, DNS priority
            - 'dns_lite': DNS rules minus duplicates, Filter priority
            - 'filter_full': Filter rules with whitelist, Filter priority
        """
        # Phase 1: Parse and internal semantic dedup for each list
        parsed_filter = self._parse_rules(filter_rules)
        parsed_dns = self._parse_rules(dns_rules)
        parsed_whitelist = self._parse_rules(whitelist_rules)

        filter_deduped = self._dedup_parsed(parsed_filter)
        dns_deduped = self._dedup_parsed(parsed_dns)
        whitelist_deduped = self._dedup_parsed(parsed_whitelist)

        # Generate DNS priority variants (Phase 2-4)
        dns_full, filter_lite = self._make_dns_priority(
            filter_deduped, dns_deduped, whitelist_deduped
        )

        # Generate Filter priority variants (Phase 2-4)
        dns_lite, filter_full = self._make_filter_priority(
            filter_deduped, dns_deduped, whitelist_deduped
        )

        return {
            'dns_full': dns_full,
            'filter_lite': filter_lite,
            'dns_lite': dns_lite,
            'filter_full': filter_full
        }

    def _make_dns_priority(
        self,
        filter_rules: List[ParsedRule],
        dns_rules: List[ParsedRule],
        whitelist_rules: List[ParsedRule]
    ) -> Tuple[List[str], List[str]]:
        """
        Create DNS priority variants.

        When DNS and Filter have duplicates, keep DNS version.
        Remove duplicates from Filter.
        Merge whitelist into both and resolve conflicts.

        Returns:
            Tuple of (dns_full, filter_lite) rule string lists
        """
        # Phase 2: Priority dedup (keep DNS, remove from filter)
        filter_unique = self._remove_duplicates(filter_rules, dns_rules)

        # Phase 3: Whitelist merge + conflict resolution
        dns_full_parsed = self._apply_whitelist(dns_rules, whitelist_rules)
        filter_lite_parsed = self._apply_whitelist(filter_unique, whitelist_rules)

        # Phase 3 final: Internal dedup after whitelist merge
        dns_full_final = self._dedup_parsed(dns_full_parsed)
        filter_lite_final = self._dedup_parsed(filter_lite_parsed)

        # Phase 4: Convert back to strings
        dns_full = [r.raw for r in dns_full_final]
        filter_lite = [r.raw for r in filter_lite_final]

        return dns_full, filter_lite

    def _make_filter_priority(
        self,
        filter_rules: List[ParsedRule],
        dns_rules: List[ParsedRule],
        whitelist_rules: List[ParsedRule]
    ) -> Tuple[List[str], List[str]]:
        """
        Create Filter priority variants.

        When DNS and Filter have duplicates, keep Filter version.
        Remove duplicates from DNS.
        Merge whitelist into both and resolve conflicts.

        Returns:
            Tuple of (dns_lite, filter_full) rule string lists
        """
        # Phase 2: Priority dedup (keep filter, remove from DNS)
        dns_unique = self._remove_duplicates(dns_rules, filter_rules)

        # Phase 3: Whitelist merge + conflict resolution
        dns_lite_parsed = self._apply_whitelist(dns_unique, whitelist_rules)
        filter_full_parsed = self._apply_whitelist(filter_rules, whitelist_rules)

        # Phase 3 final: Internal dedup after whitelist merge
        dns_lite_final = self._dedup_parsed(dns_lite_parsed)
        filter_full_final = self._dedup_parsed(filter_full_parsed)

        # Phase 4: Convert back to strings
        dns_lite = [r.raw for r in dns_lite_final]
        filter_full = [r.raw for r in filter_full_final]

        return dns_lite, filter_full

    def _remove_duplicates(
        self,
        primary: List[ParsedRule],
        reference: List[ParsedRule]
    ) -> List[ParsedRule]:
        """
        Remove semantic duplicates from primary based on reference rules.

        Uses CanonicalFormBuilder for proper semantic comparison (including
        modifiers, not just domain+type).

        Args:
            primary: List of parsed rules to deduplicate
            reference: List of parsed reference rules (higher priority)

        Returns:
            List of primary rules with duplicates removed
        """
        # Build set of canonical keys from reference rules
        reference_keys: Set[str] = set()
        for rule in reference:
            canonical_key = self.canonical.build_canonical_key(rule)
            if canonical_key:
                reference_keys.add(canonical_key)

        # Filter primary rules, removing duplicates
        result: List[ParsedRule] = []
        for rule in primary:
            canonical_key = self.canonical.build_canonical_key(rule)
            if canonical_key and canonical_key in reference_keys:
                # This rule is a semantic duplicate, skip it
                continue
            result.append(rule)

        return result

    def _dedup_parsed(self, rules: List[ParsedRule]) -> List[ParsedRule]:
        """
        Internal semantic dedup on a parsed rule list.

        Uses CanonicalFormBuilder to identify semantically equivalent rules
        and keeps only the first occurrence.

        Args:
            rules: List of parsed rules

        Returns:
            Deduplicated list of parsed rules
        """
        seen_keys: Set[str] = set()
        result: List[ParsedRule] = []

        for rule in rules:
            canonical_key = self.canonical.build_canonical_key(rule)
            if canonical_key in seen_keys:
                continue
            seen_keys.add(canonical_key)
            result.append(rule)

        return result

    def _apply_whitelist(
        self,
        rules: List[ParsedRule],
        whitelist: List[ParsedRule]
    ) -> List[ParsedRule]:
        """
        Merge whitelist rules and resolve conflicts.

        Per the original requirement: whitelist is merged INTO the rule list,
        then conflicts are resolved. Surviving whitelist rules remain in output
        (e.g., registration patterns like @@||api.example.com^).

        Args:
            rules: List of parsed rules to process (treated as blacklist)
            whitelist: List of parsed whitelist rules

        Returns:
            List of rules after applying whitelist and resolving conflicts
            (includes both surviving blacklist AND surviving whitelist rules)
        """
        if not whitelist:
            return rules

        kept_blacklist, kept_whitelist = self.conflict.resolve(whitelist, rules)
        return kept_blacklist + kept_whitelist

    def _parse_rules(self, rules: List[str]) -> List[ParsedRule]:
        """
        Parse a list of rule strings into ParsedRule objects.

        Args:
            rules: List of rule strings

        Returns:
            List of ParsedRule objects (None values filtered out)
        """
        result: List[ParsedRule] = []
        for rule in rules:
            parsed = self.parser.parse(rule)
            if parsed is not None:
                result.append(parsed)
        return result
