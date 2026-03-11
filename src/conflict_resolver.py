"""
冲突解决模块 - 处理白名单与黑名单之间的冲突

根据 AdGuard 规则的高级变体特性设计，实现白名单优先的冲突解决逻辑。
"""

from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

from .semantic.types import ParsedRule, RuleType
from .semantic.parser import RuleParser
from .semantic.strength import StrengthEvaluator
from .semantic.canonical import CanonicalFormBuilder


class ConflictResolver:
    """
    冲突解决器 - 处理白名单与黑名单之间的冲突

    核心逻辑：
    1. 按域名对黑名单规则分组
    2. 对每个白名单规则，找出相关的黑名单规则
    3. 检测是否为"注册模式"（大范围黑名单 + 小范围白名单）
    4. 检查覆盖关系：如果白名单完全覆盖所有相关黑名单，则全部消除
    5. 如果是部分覆盖，只消除被覆盖的规则
    6. 返回 (保留的黑名单, 保留的白名单)
    """

    def __init__(self):
        """初始化冲突解决器"""
        self.parser = RuleParser()
        self.canonical = CanonicalFormBuilder()
        self.strength = StrengthEvaluator()

    def resolve(
        self,
        whitelist: List[ParsedRule],
        blacklist: List[ParsedRule]
    ) -> Tuple[List[ParsedRule], List[ParsedRule]]:
        """
        主冲突解决方法

        Args:
            whitelist: 白名单规则列表（例外规则）
            blacklist: 黑名单规则列表（阻断规则）

        Returns:
            Tuple[kept_blacklist, kept_whitelist]: 保留的黑名单和白名单规则
        """
        if not whitelist:
            # 没有白名单，全部保留
            return blacklist, whitelist

        if not blacklist:
            # 没有黑名单，白名单也不需要了
            return [], []

        # 按域名对黑名单分组
        domain_groups = self._group_by_domain(blacklist)

        # 跟踪要消除的规则
        eliminated_blacklist: Set[ParsedRule] = set()
        eliminated_whitelist: Set[ParsedRule] = set()

        # 处理每个白名单规则
        for white_rule in whitelist:
            # 找到与此白名单相关的黑名单规则
            related_blacklists = self._find_related_blacklists(white_rule, domain_groups)

            if not related_blacklists:
                # 没有相关的黑名单，这个白名单规则没有用处，消除
                eliminated_whitelist.add(white_rule)
                continue

            # 检查是否为"注册模式"
            is_registration = False
            for black_rule in related_blacklists:
                if self._is_registration_pattern(white_rule, black_rule):
                    is_registration = True
                    break

            if is_registration:
                # 注册模式：保留白名单和黑名单（白名单只豁免特定子域）
                continue

            # 找出被此白名单覆盖的所有黑名单规则
            covered_blacklists = self._find_covered_batch(white_rule, related_blacklists)

            # 将被覆盖的规则加入消除集合
            eliminated_blacklist.update(covered_blacklists)

            # 完全覆盖：白名单也消除（原始需求：完全冲突的就完全消除掉两者）
            if len(covered_blacklists) == len(related_blacklists) and covered_blacklists:
                eliminated_whitelist.add(white_rule)

        # 计算保留的规则（未被消除的）
        kept_blacklist = [rule for rule in blacklist if rule not in eliminated_blacklist]
        kept_whitelist = [rule for rule in whitelist if rule not in eliminated_whitelist]

        return kept_blacklist, kept_whitelist

    def _is_registration_pattern(
        self,
        white: ParsedRule,
        black: ParsedRule
    ) -> bool:
        """
        检测是否为"注册模式"（大范围黑名单 + 小范围白名单）

        例如：
        - 黑名单: ||example.com^ （大范围，阻断整个域名）
        - 白名单: @@||api.example.com^ （小范围，只豁免API子域）

        这种情况下，应该保留两个规则，因为白名单只是对黑名单的局部豁免。

        Args:
            white: 白名单规则
            black: 黑名单规则

        Returns:
            True 如果是注册模式，False 否则
        """
        # 白名单必须是例外规则
        if not white.is_exception:
            return False

        # 获取域名
        white_domain = white.normalized_domain
        black_domain = black.normalized_domain

        if not white_domain or not black_domain:
            return False

        # 检查黑名单是否有通配符前缀（大范围）
        black_has_wildcard = black.pattern.startswith('||')

        # 检查白名单是否有通配符前缀
        white_has_wildcard = white.pattern.startswith('||') or white.pattern.startswith('@@||')

        # 注册模式特征：
        # 1. 黑名单有大范围通配（||example.com^）
        # 2. 白名单是小范围（子域，如 @@||api.example.com^）
        # 3. 白名单的域名是黑名单域名的子域

        if not black_has_wildcard:
            # 黑名单本身已经是精确的，不是大范围
            return False

        # 检查白名单域名是否是黑名单域名的子域
        is_subdomain = white_domain.endswith('.' + black_domain)

        if is_subdomain and white_has_wildcard:
            # 典型的注册模式：
            # black: ||example.com^ (覆盖 *.example.com)
            # white: @@||api.example.com^ (只豁免 api.example.com)
            return True

        return False

    def _find_covered_batch(
        self,
        white: ParsedRule,
        blacks: List[ParsedRule]
    ) -> Set[ParsedRule]:
        """
        找出被白名单规则覆盖的所有黑名单规则

        Args:
            white: 白名单规则
            blacks: 候选黑名单规则列表

        Returns:
            被覆盖的黑名单规则集合
        """
        covered: Set[ParsedRule] = set()

        for black in blacks:
            # 使用 StrengthEvaluator.covers() 检查覆盖关系
            # 注意：covers 检查的是 rule1 是否覆盖 rule2
            # 这里我们要检查白名单是否覆盖黑名单
            if self.strength.covers(white, black):
                covered.add(black)

        return covered

    def _group_by_domain(
        self,
        rules: List[ParsedRule]
    ) -> Dict[str, List[ParsedRule]]:
        """
        按域名对规则分组

        Args:
            rules: 规则列表

        Returns:
            域名到规则列表的映射字典
        """
        groups: Dict[str, List[ParsedRule]] = defaultdict(list)

        for rule in rules:
            domain = rule.normalized_domain

            if domain:
                # 使用主域名作为键
                groups[domain].append(rule)

                # 同时添加到父域名的组中（用于通配匹配）
                # 例如：sub.example.com 也应该被 example.com 的查询找到
                parts = domain.split('.')
                if len(parts) > 2:
                    # 添加所有父域名
                    for i in range(1, len(parts) - 1):
                        parent_domain = '.'.join(parts[i:])
                        groups[parent_domain].append(rule)
            else:
                # 没有规范化域名的规则，使用模式作为键
                pattern = rule.pattern.lstrip('|').rstrip('^$')
                if pattern:
                    groups[pattern].append(rule)

        return dict(groups)

    def _find_related_blacklists(
        self,
        white: ParsedRule,
        domain_groups: Dict[str, List[ParsedRule]]
    ) -> List[ParsedRule]:
        """
        查找与白名单规则相关的黑名单规则

        相关规则是指：
        1. 域名相同或白名单域名是黑名单域名的子域
        2. 规则类型兼容（都是DNS相关类型）

        Args:
            white: 白名单规则
            domain_groups: 按域名分组的黑名单规则

        Returns:
            相关的黑名单规则列表
        """
        related: List[ParsedRule] = []
        white_domain = white.normalized_domain

        if not white_domain:
            # 没有域名的白名单规则，尝试从模式匹配
            pattern = white.pattern.lstrip('@').lstrip('|').rstrip('^$')
            if pattern in domain_groups:
                related.extend(domain_groups[pattern])
            return related

        # DNS 相关的规则类型（包含 EXCEPTION 以支持 @@ 白名单规则）
        dns_types = {RuleType.HOSTS, RuleType.DOMAIN_ONLY, RuleType.DNS_FILTER, RuleType.AD_BLOCK, RuleType.EXCEPTION}

        # 直接查找相同域名的规则
        if white_domain in domain_groups:
            for rule in domain_groups[white_domain]:
                if rule.rule_type in dns_types and not rule.is_exception:
                    related.append(rule)

        # 查找父域名的规则（白名单可能是子域，需要检查父域的黑名单）
        parts = white_domain.split('.')
        if len(parts) > 2:
            for i in range(1, len(parts)):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in domain_groups:
                    for rule in domain_groups[parent_domain]:
                        # 检查黑名单是否有通配符（能覆盖子域）
                        if (rule.rule_type in dns_types and
                            not rule.is_exception and
                            rule.pattern.startswith('||')):
                            # 避免重复添加
                            if rule not in related:
                                related.append(rule)

        return related
