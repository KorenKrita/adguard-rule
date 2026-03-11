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
from .semantic.types import ParsedRule, RuleType
from .conflict_resolver import ConflictResolver


class VariantGenerator:
    """
    Generates four variants of AdGuard rules.

    Variants:
    1. dns_full: DNS rules with whitelist applied, DNS priority
    2. filter_lite: Filter rules with duplicates removed (DNS has priority), DNS priority
    3. dns_lite: DNS rules with duplicates removed (Filter has priority), Filter priority
    4. filter_full: Filter rules with whitelist applied, Filter priority
    """

    def __init__(self):
        """Initialize the variant generator with required components."""
        self.parser = RuleParser()
        self.deduplicator = SemanticDeduplicator()
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
        # Generate DNS priority variants
        dns_full, filter_lite = self._make_dns_priority(
            filter_rules, dns_rules, whitelist_rules
        )

        # Generate Filter priority variants
        dns_lite, filter_full = self._make_filter_priority(
            filter_rules, dns_rules, whitelist_rules
        )

        return {
            'dns_full': dns_full,
            'filter_lite': filter_lite,
            'dns_lite': dns_lite,
            'filter_full': filter_full
        }

    def _make_dns_priority(
        self,
        filter_rules: List[str],
        dns_rules: List[str],
        whitelist_rules: List[str]
    ) -> tuple[List[str], List[str]]:
        """
        Create DNS priority variants.

        When DNS and Filter have duplicates, keep DNS version.
        Remove duplicates from Filter.
        Apply whitelist to both and resolve conflicts.

        Args:
            filter_rules: List of filter rule strings
            dns_rules: List of DNS rule strings
            whitelist_rules: List of whitelist rule strings

        Returns:
            Tuple of (dns_full, filter_lite) rule lists
        """
        # Parse all rules
        parsed_dns = self._parse_rules(dns_rules)
        parsed_filter = self._parse_rules(filter_rules)
        parsed_whitelist = self._parse_rules(whitelist_rules)

        # Remove duplicates from filter (keep DNS priority)
        filter_lite_parsed = self._remove_duplicates(parsed_filter, parsed_dns)

        # Apply whitelist and resolve conflicts for DNS rules
        dns_full_parsed = self._apply_whitelist(parsed_dns, parsed_whitelist)

        # Apply whitelist and resolve conflicts for filter rules
        filter_lite_parsed = self._apply_whitelist(filter_lite_parsed, parsed_whitelist)

        # Convert back to strings
        dns_full = [r.raw for r in dns_full_parsed]
        filter_lite = [r.raw for r in filter_lite_parsed]

        return dns_full, filter_lite

    def _make_filter_priority(
        self,
        filter_rules: List[str],
        dns_rules: List[str],
        whitelist_rules: List[str]
    ) -> tuple[List[str], List[str]]:
        """
        Create Filter priority variants.

        When DNS and Filter have duplicates, keep Filter version.
        Remove duplicates from DNS.
        Apply whitelist to both and resolve conflicts.

        Args:
            filter_rules: List of filter rule strings
            dns_rules: List of DNS rule strings
            whitelist_rules: List of whitelist rule strings

        Returns:
            Tuple of (dns_lite, filter_full) rule lists
        """
        # Parse all rules
        parsed_dns = self._parse_rules(dns_rules)
        parsed_filter = self._parse_rules(filter_rules)
        parsed_whitelist = self._parse_rules(whitelist_rules)

        # Remove duplicates from DNS (keep Filter priority)
        dns_lite_parsed = self._remove_duplicates(parsed_dns, parsed_filter)

        # Apply whitelist and resolve conflicts for DNS rules
        dns_lite_parsed = self._apply_whitelist(dns_lite_parsed, parsed_whitelist)

        # Apply whitelist and resolve conflicts for filter rules
        filter_full_parsed = self._apply_whitelist(parsed_filter, parsed_whitelist)

        # Convert back to strings
        dns_lite = [r.raw for r in dns_lite_parsed]
        filter_full = [r.raw for r in filter_full_parsed]

        return dns_lite, filter_full

    def _remove_duplicates(
        self,
        primary: List[ParsedRule],
        reference: List[ParsedRule]
    ) -> List[ParsedRule]:
        """
        Remove semantic duplicates from primary based on reference rules.

        Args:
            primary: List of parsed rules to deduplicate
            reference: List of parsed reference rules (higher priority)

        Returns:
            List of primary rules with duplicates removed
        """
        # Build set of canonical keys from reference rules
        reference_keys: Set[str] = set()
        for rule in reference:
            canonical_key = self._get_canonical_key(rule)
            if canonical_key:
                reference_keys.add(canonical_key)

        # Filter primary rules, removing duplicates
        result: List[ParsedRule] = []
        for rule in primary:
            canonical_key = self._get_canonical_key(rule)
            if canonical_key and canonical_key in reference_keys:
                # This rule is a duplicate, skip it
                continue
            result.append(rule)

        return result

    def _dedup_list(self, rules: List[str]) -> List[str]:
        """
        Deduplicate a list of rules using semantic deduplication.

        Args:
            rules: List of rule strings

        Returns:
            Deduplicated list of rule strings
        """
        return self.deduplicator.process_batch(rules)

    def _apply_whitelist(
        self,
        rules: List[ParsedRule],
        whitelist: List[ParsedRule]
    ) -> List[ParsedRule]:
        """
        Apply whitelist rules and resolve conflicts.

        Args:
            rules: List of parsed rules to process (treated as blacklist)
            whitelist: List of parsed whitelist rules

        Returns:
            List of rules after applying whitelist and resolving conflicts
        """
        kept_blacklist, _ = self.conflict.resolve(whitelist, rules)
        return kept_blacklist

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

    def _get_canonical_key(self, rule: ParsedRule) -> Optional[str]:
        """
        Generate a canonical key for a rule for duplicate detection.

        Args:
            rule: ParsedRule to generate key for

        Returns:
            Canonical key string or None if cannot be generated
        """
        # Use normalized domain as primary key if available
        if rule.normalized_domain:
            # Include rule type to distinguish between different types
            return f"{rule.rule_type.value}:{rule.normalized_domain}"

        # Fall back to pattern
        if rule.pattern:
            return f"{rule.rule_type.value}:{rule.pattern}"

        return None
