from typing import Dict, Set, List, Any, Optional

from .types import ParsedRule, RuleType


class CanonicalFormBuilder:
    """
    构建规则的规范化形式，用于等价比较
    注意：只用于比较，不改变原始输出
    """

    def __init__(self):
        """初始化规范化构建器"""
        # 使用简单 dict 缓存，key 为规则原始文本，value 为规范化键
        # 规则总量在 10 万级别，内存占用很小，无需 LRU 策略
        self._cache: Dict[str, str] = {}

    def _get_from_cache(self, rule: ParsedRule) -> Optional[str]:
        """从缓存获取结果"""
        return self._cache.get(rule.raw)

    def _add_to_cache(self, rule: ParsedRule, canonical_key: str) -> None:
        """添加结果到缓存"""
        self._cache[rule.raw] = canonical_key

    # 修饰符别名映射（简写 -> 标准名）
    MODIFIER_ALIASES = {
        'doc': 'document',
        'css': 'stylesheet',
        'frame': 'subdocument',
        'xhr': 'xmlhttprequest',
        'ehide': 'elemhide',
        'ghide': 'generichide',
        'shide': 'specifichide',
        '3p': 'third-party',
        '1p': 'first-party',
        'strict3p': 'strict-third-party',
        'strict1p': 'strict-first-party',
        'from': 'domain',  # CoreLibs v1.12+ 中 $from 等价于 $domain
        'queryprune': 'removeparam',  # 已废弃但兼容
    }

    # $all 修饰符展开的内容
    ALL_MODIFIER_EXPANDED = frozenset([
        'document', 'subdocument', 'font', 'image', 'media',
        'object', 'other', 'ping', 'script', 'stylesheet',
        'websocket', 'xmlhttprequest', 'popup'
    ])

    # 内容类型组展开
    CONTENT_TYPE_GROUPS = {
        'media': ['mp4', 'webm', 'avi', 'mov', 'mkv'],
        'image': ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg'],
        'font': ['woff', 'woff2', 'ttf', 'otf', 'eot'],
        'script': ['js', 'javascript'],
    }

    def build_canonical_key(self, rule: ParsedRule) -> str:
        """
        构建规范化键，用于等价比较

        返回的字符串格式：
        - DNS规则: "dns:block:example.com" 或 "dns:allow:example.com"
        - 过滤规则: "filter:block:example.com:modifier1,modifier2"

        注意：使用缓存机制优化重复计算
        """
        # 首先检查缓存
        cached = self._get_from_cache(rule)
        if cached is not None:
            return cached

        # 计算规范化键
        if rule.rule_type in (RuleType.HOSTS, RuleType.DOMAIN_ONLY):
            result = self._canonical_dns_exact(rule)
        elif rule.rule_type == RuleType.DNS_FILTER:
            result = self._canonical_dns_wildcard(rule)
        elif rule.rule_type == RuleType.AD_BLOCK:
            result = self._canonical_adblock(rule)
        elif rule.rule_type == RuleType.EXCEPTION:
            result = self._canonical_exception(rule)
        elif rule.rule_type == RuleType.COSMETIC:
            result = self._canonical_cosmetic(rule)
        else:
            # 未知类型返回原始文本
            result = f"unknown:{rule.raw}"

        # 存入缓存
        self._add_to_cache(rule, result)
        return result

    def _canonical_dns_exact(self, rule: ParsedRule) -> str:
        """
        精确域名阻断的规范化

        127.0.0.1 example.com
        0.0.0.0 example.com
        example.com

        都规范化为: "dns:block:exact:example.com"
        """
        action = "allow" if rule.is_exception else "block"
        domain = rule.normalized_domain or rule.pattern.lower()
        return f"dns:{action}:exact:{domain}"

    def _canonical_dns_wildcard(self, rule: ParsedRule) -> str:
        """
        通配域名阻断的规范化

        ||example.com^
        ||example.com^$important

        都规范化为: "dns:block:wildcard:example.com"
        """
        action = "allow" if rule.is_exception else "block"
        domain = rule.normalized_domain or self._extract_domain_from_pattern(rule.pattern)

        # 检查是否有特殊修饰符改变行为
        dnsrewrite = rule.modifiers.get('dnsrewrite')
        if dnsrewrite:
            return f"dns:rewrite:{domain}:{self._normalize_dnsrewrite(dnsrewrite)}"

        return f"dns:{action}:wildcard:{domain}"

    def _canonical_adblock(self, rule: ParsedRule) -> str:
        """
        广告过滤规则的规范化
        """
        action = "allow" if rule.is_exception else "block"
        pattern = self._normalize_pattern(rule.pattern)
        modifiers = self._normalize_modifiers(rule.modifiers)

        # 排序修饰符以确保一致性
        modifier_str = ','.join(sorted(modifiers)) if modifiers else ""

        return f"filter:{action}:{pattern}:{modifier_str}"

    def _canonical_exception(self, rule: ParsedRule) -> str:
        """
        例外规则的规范化

        @@||example.com^ 规范化为 "dns:allow:wildcard:example.com"
        """
        # 重新解析内部规则并标记为例外
        return self._canonical_dns_wildcard(rule)

    def _canonical_cosmetic(self, rule: ParsedRule) -> str:
        """
        元素隐藏规则的规范化
        """
        action = "allow" if rule.is_exception else "block"
        domains = rule.modifiers.get('domains', '*')
        selector = rule.pattern

        # 规范化域名列表
        if domains != '*':
            domain_list = sorted([d.strip().lower() for d in domains.split(',')])
            domain_key = '|'.join(domain_list)
        else:
            domain_key = '*'

        return f"cosmetic:{action}:{domain_key}:{selector}"

    def _normalize_pattern(self, pattern: str) -> str:
        """规范化模式字符串"""
        # 移除前后空白
        pattern = pattern.strip()

        # 统一前缀标记
        if pattern.startswith('||'):
            # 域名通配: ||example.com -> [DOMAIN]example.com
            return f"[DOMAIN]{pattern[2:].lower()}"
        elif pattern.startswith('|'):
            # 开头匹配: |http:// -> [START]http://
            return f"[START]{pattern[1:].lower()}"
        elif pattern.endswith('|'):
            # 结尾匹配: .swf| -> [END].swf
            return f"[END]{pattern[:-1].lower()}"
        else:
            return pattern.lower()

    def _normalize_modifiers(self, modifiers: Dict[str, Any]) -> Set[str]:
        """规范化修饰符集合"""
        normalized = set()

        for key, value in modifiers.items():
            # 处理别名
            canonical_key = self.MODIFIER_ALIASES.get(key, key)

            # 处理 $all 展开
            if canonical_key == 'all':
                normalized.update(self.ALL_MODIFIER_EXPANDED)
                continue

            # 处理内容类型组展开
            if canonical_key in self.CONTENT_TYPE_GROUPS:
                normalized.update(self.CONTENT_TYPE_GROUPS[canonical_key])
                continue

            # 处理布尔修饰符
            if value is True:
                normalized.add(canonical_key)
            else:
                # 带值的修饰符需要排序值部分
                values = sorted(str(value).lower().split('|'))
                normalized.add(f"{canonical_key}={'|'.join(values)}")

        return normalized

    def _extract_domain_from_pattern(self, pattern: str) -> str:
        """从模式中提取域名"""
        clean = pattern.lstrip('|').rstrip('^$')
        if '/' in clean:
            clean = clean.split('/')[0]
        return clean.lower()

    def _normalize_dnsrewrite(self, value: str) -> str:
        """
        规范化 dnsrewrite 值

        $dnsrewrite=1.2.3.4 -> NOERROR;A;1.2.3.4
        $dnsrewrite=REFUSED -> REFUSED;;
        """
        value = value.upper()

        # 已经是完整格式
        if ';' in value:
            return value

        # 简写格式转换
        if value in ('REFUSED', 'NXDOMAIN', 'NOERROR'):
            return f"{value};;"

        # IP 地址 -> A 记录
        if '.' in value and ':' not in value:
            return f"NOERROR;A;{value.lower()}"

        # IPv6 地址 -> AAAA 记录
        if ':' in value:
            return f"NOERROR;AAAA;{value.lower()}"

        # 域名 -> CNAME 记录
        return f"NOERROR;CNAME;{value.lower()}"
