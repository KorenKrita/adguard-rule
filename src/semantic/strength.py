from typing import Dict, Any, List

from .types import ParsedRule, RuleType


class StrengthEvaluator:
    """
    评估规则的强度，用于在包含关系时决定保留哪个
    """

    # 强度权重
    WEIGHTS = {
        'subdomain_match': 10,      # || 前缀，匹配子域
        'exact_domain': 5,          # 精确域名匹配
        'important': 20,            # $important 修饰符
        'modifier_per_item': 2,     # 每个修饰符加分
        'path_specificity': 3,      # 路径精确度
        'regex_complexity': -5,     # 正则表达式（性能差，略降权）
    }

    def evaluate(self, rule: ParsedRule) -> int:
        """
        计算规则强度评分

        评分逻辑：
        1. 基础分数根据规则类型
        2. 加上各种修饰符和模式特征的权重
        """
        if rule.rule_type == RuleType.HOSTS:
            return self._evaluate_hosts(rule)

        if rule.rule_type == RuleType.DOMAIN_ONLY:
            return self._evaluate_domain_only(rule)

        if rule.rule_type == RuleType.DNS_FILTER:
            return self._evaluate_dns_filter(rule)

        if rule.rule_type == RuleType.AD_BLOCK:
            return self._evaluate_ad_block(rule)

        if rule.rule_type == RuleType.EXCEPTION:
            return self._evaluate_exception(rule)

        if rule.rule_type == RuleType.COSMETIC:
            return self._evaluate_cosmetic(rule)

        return 0

    def _evaluate_hosts(self, rule: ParsedRule) -> int:
        """评估 hosts 规则强度"""
        score = 5  # 基础分：仅精确匹配

        ip = rule.modifiers.get('ip', '')

        # 0.0.0.0 和 127.0.0.1 等价，但 0.0.0.0 更标准
        if ip == '0.0.0.0':
            score += 1

        return score

    def _evaluate_domain_only(self, rule: ParsedRule) -> int:
        """评估纯域名规则强度"""
        return 5  # 仅精确匹配

    def _evaluate_dns_filter(self, rule: ParsedRule) -> int:
        """评估 DNS 过滤规则强度"""
        score = 0
        pattern = rule.pattern

        # || 前缀匹配子域（+10）
        if pattern.startswith('||'):
            score += self.WEIGHTS['subdomain_match']

        # $important 修饰符（+20）
        if rule.modifiers.get('important') is True:
            score += self.WEIGHTS['important']

        # 其他修饰符（+2/个）
        score += len(rule.modifiers) * self.WEIGHTS['modifier_per_item']

        return score

    def _evaluate_ad_block(self, rule: ParsedRule) -> int:
        """评估广告过滤规则强度"""
        score = 0
        pattern = rule.pattern

        # || 前缀
        if pattern.startswith('||'):
            score += self.WEIGHTS['subdomain_match']

        # 路径精确度
        if '/' in pattern:
            path_depth = pattern.count('/')
            score += path_depth * self.WEIGHTS['path_specificity']

        # $important
        if rule.modifiers.get('important') is True:
            score += self.WEIGHTS['important']

        # 其他修饰符
        score += len(rule.modifiers) * self.WEIGHTS['modifier_per_item']

        # 正则表达式（略微降权，因为性能差）
        if pattern.startswith('/') and pattern.endswith('/'):
            score += self.WEIGHTS['regex_complexity']

        return score

    def _evaluate_exception(self, rule: ParsedRule) -> int:
        """评估例外规则强度"""
        # 例外规则的基础强度与普通规则相同
        # 但增加 $important 的额外权重
        base_score = self._evaluate_dns_filter(rule)

        # 例外规则的 $important 更重要
        if rule.modifiers.get('important') is True:
            base_score += 10

        return base_score

    def _evaluate_cosmetic(self, rule: ParsedRule) -> int:
        """评估元素隐藏规则强度"""
        score = 3  # 基础分

        # 指定域名的规则比全局规则更精确
        domains = rule.modifiers.get('domains', '')
        if domains and domains != '*':
            domain_count = len(domains.split(','))
            score += domain_count  # 每指定一个域名+1

        return score

    def compare(self, rule1: ParsedRule, rule2: ParsedRule) -> int:
        """
        比较两条规则的强度

        Returns:
            > 0: rule1 更强
            < 0: rule2 更强
            = 0: 强度相等
        """
        return rule1.strength_score - rule2.strength_score

    def is_stronger(self, rule1: ParsedRule, rule2: ParsedRule) -> bool:
        """判断 rule1 是否比 rule2 更强"""
        return self.compare(rule1, rule2) > 0

    def covers(self, rule1: ParsedRule, rule2: ParsedRule) -> bool:
        """
        判断 rule1 是否完全覆盖 rule2

        例如：
        - ||example.com^ 覆盖 example.com
        - ||example.com^ 覆盖 ||sub.example.com^
        """
        # 类型必须相同或是父子关系
        if rule1.rule_type != rule2.rule_type:
            # DNS 规则类型之间可以比较
            dns_types = {RuleType.HOSTS, RuleType.DOMAIN_ONLY, RuleType.DNS_FILTER}
            if rule1.rule_type not in dns_types or rule2.rule_type not in dns_types:
                return False

        # 获取域名
        domain1 = rule1.normalized_domain
        domain2 = rule2.normalized_domain

        if not domain1 or not domain2:
            return False

        # rule1 必须有 || 前缀（匹配子域）
        has_wildcard1 = rule1.pattern.startswith('||')
        has_wildcard2 = rule2.pattern.startswith('||')

        # 如果 rule1 没有通配但 rule2 有，不可能覆盖
        if not has_wildcard1 and has_wildcard2:
            return False

        # 检查域名包含关系
        if has_wildcard1 and not has_wildcard2:
            # ||example.com^ 覆盖 example.com
            return domain2.endswith('.' + domain1) or domain2 == domain1

        if has_wildcard1 and has_wildcard2:
            # ||example.com^ 覆盖 ||sub.example.com^
            return domain2.endswith('.' + domain1) or domain2 == domain1

        # 都没有通配，检查是否完全相同
        return domain1 == domain2
