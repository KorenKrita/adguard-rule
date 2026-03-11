from typing import Dict, List, Optional, Set, Tuple

from .types import ParsedRule, RuleType
from .parser import RuleParser
from .canonical import CanonicalFormBuilder
from .strength import StrengthEvaluator


class SemanticDeduplicator:
    """
    语义去重引擎

    核心逻辑：
    1. 解析每条规则
    2. 生成规范化键
    3. 检查等价性
    4. 处理包含关系，保留更强规则
    5. 输出保留的规则（原始形式）
    """

    def __init__(self):
        self.parser = RuleParser()
        self.canonical_builder = CanonicalFormBuilder()
        self.strength_evaluator = StrengthEvaluator()

        # 已保留的规则索引
        # canonical_key -> ParsedRule
        self.canonical_index: Dict[str, ParsedRule] = {}

        # 域名索引，用于快速查找覆盖关系
        # domain -> List[ParsedRule]
        self.domain_index: Dict[str, List[ParsedRule]] = {}

        # 统计信息
        self.stats = {
            'total': 0,
            'kept': 0,
            'deduped': 0,
            'replaced': 0,  # 被更强规则替换的数量
        }

    def process(self, rule_text: str) -> Optional[str]:
        """
        处理单条规则

        Args:
            rule_text: 原始规则文本

        Returns:
            保留的规则文本（原始形式），或 None（如果被去重）
        """
        self.stats['total'] += 1

        # 解析规则
        parsed = self.parser.parse(rule_text)

        if parsed is None:
            # 注释或空行，直接返回 None（不参与去重）
            return None

        # 计算强度
        parsed.strength_score = self.strength_evaluator.evaluate(parsed)

        # 生成规范化键
        canonical_key = self.canonical_builder.build_canonical_key(parsed)

        # 检查是否已存在等价的规则
        if canonical_key in self.canonical_index:
            existing = self.canonical_index[canonical_key]

            # 完全等价，丢弃当前
            self.stats['deduped'] += 1
            return None

        # 检查是否存在覆盖关系
        should_keep, replaced_rule = self._check_coverage(parsed)

        if not should_keep:
            # 被现有规则覆盖，丢弃
            self.stats['deduped'] += 1
            return None

        if replaced_rule:
            # 替换现有规则
            self._remove_rule(replaced_rule)
            self.stats['replaced'] += 1

        # 保留当前规则
        self._add_rule(canonical_key, parsed)
        self.stats['kept'] += 1

        return parsed.raw

    def process_batch(self, rules: List[str]) -> List[str]:
        """
        批量处理规则列表

        Args:
            rules: 原始规则文本列表

        Returns:
            去重后的规则文本列表
        """
        # 使用字典来跟踪结果，键为规范化键，值为规则文本
        # 这样当发生替换时，可以自动覆盖较弱的规则
        result_map: Dict[str, str] = {}

        for rule_text in rules:
            parsed = self.parser.parse(rule_text)
            if parsed is None:
                continue

            # 计算强度和规范化键
            parsed.strength_score = self.strength_evaluator.evaluate(parsed)
            canonical_key = self.canonical_builder.build_canonical_key(parsed)

            # 检查是否已存在等价规则
            if canonical_key in self.canonical_index:
                self.stats['total'] += 1
                self.stats['deduped'] += 1
                continue

            # 检查覆盖关系
            should_keep, replaced_rule = self._check_coverage(parsed)

            if not should_keep:
                self.stats['total'] += 1
                self.stats['deduped'] += 1
                continue

            self.stats['total'] += 1

            if replaced_rule:
                # 移除被替换的规则
                replaced_key = self.canonical_builder.build_canonical_key(replaced_rule)
                if replaced_key in result_map:
                    del result_map[replaced_key]
                self._remove_rule(replaced_rule)
                self.stats['replaced'] += 1
                # 被替换的规则已经从 kept 中移除，新规则加入，kept 数量不变
            else:
                # 没有替换，新增规则
                self.stats['kept'] += 1

            # 添加新规则
            self._add_rule(canonical_key, parsed)
            result_map[canonical_key] = parsed.raw

        return list(result_map.values())

    def _check_coverage(self, rule: ParsedRule) -> Tuple[bool, Optional[ParsedRule]]:
        """
        检查规则是否被现有规则覆盖，或需要替换现有规则

        Returns:
            (should_keep, replaced_rule)
            - should_keep: 是否保留当前规则
            - replaced_rule: 被替换的现有规则（如果有）
        """
        domain = rule.normalized_domain

        if not domain:
            # 没有域名信息，无法检查覆盖关系
            return True, None

        # 查找同域名的现有规则
        existing_rules = self.domain_index.get(domain, [])

        # 也检查父域名
        parent_domains = self._get_parent_domains(domain)
        for parent in parent_domains:
            existing_rules.extend(self.domain_index.get(parent, []))

        replaced_rule = None

        for existing in existing_rules:
            # 检查是否类型兼容
            if not self._is_compatible(rule, existing):
                continue

            # 检查覆盖关系
            if self.strength_evaluator.covers(existing, rule):
                # 现有规则覆盖当前规则，丢弃当前
                return False, None

            if self.strength_evaluator.covers(rule, existing):
                # 当前规则覆盖现有规则
                if rule.strength_score > existing.strength_score:
                    replaced_rule = existing

        return True, replaced_rule

    def _is_compatible(self, rule1: ParsedRule, rule2: ParsedRule) -> bool:
        """检查两条规则是否类型兼容（可以比较覆盖关系）"""
        # 例外规则和普通规则不比较覆盖
        if rule1.is_exception != rule2.is_exception:
            return False

        # DNS 相关类型之间兼容
        dns_types = {RuleType.HOSTS, RuleType.DOMAIN_ONLY, RuleType.DNS_FILTER}
        if rule1.rule_type in dns_types and rule2.rule_type in dns_types:
            return True

        return rule1.rule_type == rule2.rule_type

    def _get_parent_domains(self, domain: str) -> List[str]:
        """获取域名的所有父域名"""
        parts = domain.split('.')
        parents = []

        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            parents.append(parent)

        return parents

    def _add_rule(self, canonical_key: str, rule: ParsedRule):
        """添加规则到索引"""
        self.canonical_index[canonical_key] = rule

        # 添加到域名索引
        domain = rule.normalized_domain
        if domain:
            if domain not in self.domain_index:
                self.domain_index[domain] = []
            self.domain_index[domain].append(rule)

    def _remove_rule(self, rule: ParsedRule):
        """从索引中移除规则"""
        # 从规范化索引中移除
        canonical_key = self.canonical_builder.build_canonical_key(rule)
        if canonical_key in self.canonical_index:
            del self.canonical_index[canonical_key]

        # 从域名索引中移除
        domain = rule.normalized_domain
        if domain and domain in self.domain_index:
            self.domain_index[domain] = [
                r for r in self.domain_index[domain] if r.raw != rule.raw
            ]

    def get_stats(self) -> Dict[str, int]:
        """获取统计信息"""
        return self.stats.copy()

    def reset(self):
        """重置去重器状态"""
        self.canonical_index.clear()
        self.domain_index.clear()
        self.stats = {
            'total': 0,
            'kept': 0,
            'deduped': 0,
            'replaced': 0,
        }
