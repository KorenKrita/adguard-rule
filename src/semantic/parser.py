import re
from typing import Optional, Tuple, Dict, Any

from .types import ParsedRule, RuleType


# 最大规则长度（与 AdGuard 一致）
MAX_RULE_LENGTH = 4096

# 本地/阻止 IP 集合（用于识别 hosts 风格阻断规则）
BLOCK_IPS = {
    '0.0.0.0', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1',
    '127.0.1.1', '255.255.255.255'
}

# 修饰符分隔符
MODIFIER_SEPARATORS = {',', '|'}

# 注释标记
COMMENT_MARKERS = {'!', '#'}


class RuleParser:
    """AdGuard 规则专用解析器"""

    # 正则表达式模式
    HOSTS_PATTERN = re.compile(
        r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # IPv4
        r'\[?([0-9a-fA-F:]+)\]?)\s+'              # IPv6
        r'(\S+)'                                    # 域名
    )

    DOMAIN_ONLY_PATTERN = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'[a-zA-Z]{2,}$'
    )

    ADBLOCK_PATTERN = re.compile(
        r'^(?:@@)?'           # 例外标记
        r'(?:\|\|)?'         # 域名开始标记
        r'([^$^|]+)'          # 模式部分
        r'(?:\^)?'            # 分隔符
        r'(?:\$(.+))?$'       # 修饰符部分
    )

    COSMETIC_PATTERN = re.compile(
        r'^([a-zA-Z0-9.*,]+)?#'  # 域名部分（可选）
        r'([@?%])?'              # 标记 @ ? %
        r'#'                     # 第二个 #
        r'(.+)$'                 # CSS 选择器
    )

    def parse(self, rule: str) -> Optional[ParsedRule]:
        """
        解析单条规则

        Args:
            rule: 原始规则字符串

        Returns:
            ParsedRule 对象，或 None（如果是注释/空行）
        """
        # 长度检查
        if len(rule) > MAX_RULE_LENGTH:
            # 超长规则保持原样，不做语义解析
            return ParsedRule(
                raw=rule,
                rule_type=RuleType.UNKNOWN,
                pattern=rule,
                modifiers={},
                is_exception=False,
                strength_score=0
            )

        # 去除首尾空白
        line = rule.strip()

        # 空行检查
        if not line:
            return None

        # 注释检查（但不拦截 cosmetic 规则 ##）
        if line[0] in COMMENT_MARKERS and not self._is_cosmetic(line):
            return None

        # 判断规则类型并解析
        if self._is_hosts_style(line):
            return self._parse_hosts(line)

        if self._is_domain_only(line):
            return self._parse_domain_only(line)

        if self._is_exception(line):
            return self._parse_exception(line)

        if self._is_adblock_style(line):
            return self._parse_adblock(line)

        if self._is_cosmetic(line):
            return self._parse_cosmetic(line)

        # 无法识别的规则类型
        return ParsedRule(
            raw=rule,
            rule_type=RuleType.UNKNOWN,
            pattern=rule,
            modifiers={},
            is_exception=False,
            strength_score=0
        )

    def _is_hosts_style(self, line: str) -> bool:
        """检查是否为 /etc/hosts 风格"""
        return bool(self.HOSTS_PATTERN.match(line))

    def _is_domain_only(self, line: str) -> bool:
        """检查是否为纯域名"""
        return bool(self.DOMAIN_ONLY_PATTERN.match(line))

    def _is_exception(self, line: str) -> bool:
        """检查是否为例外规则"""
        return line.startswith('@@')

    def _is_adblock_style(self, line: str) -> bool:
        """检查是否为 Adblock 风格"""
        return '||' in line or '$' in line or '^' in line

    def _is_cosmetic(self, line: str) -> bool:
        """检查是否为元素隐藏规则"""
        return '##' in line or '#@#' in line or '#?#' in line

    def _parse_hosts(self, line: str) -> ParsedRule:
        """解析 /etc/hosts 风格规则"""
        match = self.HOSTS_PATTERN.match(line)
        if not match:
            raise ValueError(f"Invalid hosts rule: {line}")

        ip = match.group(1)
        domain = match.group(3)

        return ParsedRule(
            raw=line,
            rule_type=RuleType.HOSTS,
            pattern=domain,
            modifiers={'ip': ip},
            is_exception=False,
            strength_score=5,  # hosts 风格只匹配精确域名
            normalized_domain=domain.lower()
        )

    def _parse_domain_only(self, line: str) -> ParsedRule:
        """解析纯域名规则"""
        domain = line.lower()
        return ParsedRule(
            raw=line,
            rule_type=RuleType.DOMAIN_ONLY,
            pattern=domain,
            modifiers={},
            is_exception=False,
            strength_score=5,
            normalized_domain=domain
        )

    def _parse_exception(self, line: str) -> ParsedRule:
        """解析例外规则"""
        # 去掉 @@ 前缀后按普通规则解析
        inner_rule = line[2:]
        base_rule = self.parse(inner_rule)

        if base_rule:
            base_rule.raw = line
            base_rule.is_exception = True
            base_rule.rule_type = RuleType.EXCEPTION

        return base_rule

    def _parse_adblock(self, line: str) -> ParsedRule:
        """解析 Adblock 风格规则"""
        # 提取修饰符部分
        if '$' in line:
            pattern_part, modifier_part = line.split('$', 1)
            modifiers = self._parse_modifiers(modifier_part)
        else:
            pattern_part = line
            modifiers = {}

        # 判断是否为 DNS 规则（只有域名，没有路径）
        is_dns = self._is_dns_pattern(pattern_part)

        # 提取域名
        domain = self._extract_domain(pattern_part)

        # 计算强度
        strength = self._calculate_adblock_strength(pattern_part, modifiers)

        return ParsedRule(
            raw=line,
            rule_type=RuleType.DNS_FILTER if is_dns else RuleType.AD_BLOCK,
            pattern=pattern_part,
            modifiers=modifiers,
            is_exception=False,
            strength_score=strength,
            normalized_domain=domain.lower() if domain else None
        )

    def _parse_cosmetic(self, line: str) -> ParsedRule:
        """解析元素隐藏规则"""
        match = self.COSMETIC_PATTERN.match(line)
        if not match:
            return ParsedRule(
                raw=line,
                rule_type=RuleType.COSMETIC,
                pattern=line,
                modifiers={},
                is_exception=False,
                strength_score=0
            )

        domains = match.group(1) or '*'
        selector = match.group(3)

        return ParsedRule(
            raw=line,
            rule_type=RuleType.COSMETIC,
            pattern=selector,
            modifiers={'domains': domains},
            is_exception='@' in (match.group(2) or ''),
            strength_score=3
        )

    def _parse_modifiers(self, modifier_str: str) -> Dict[str, Any]:
        """解析修饰符字符串"""
        modifiers = {}

        # 按逗号或管道符分割
        parts = re.split(r'[,|]', modifier_str)

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # 处理 key=value 形式
            if '=' in part:
                key, value = part.split('=', 1)
                modifiers[key] = value
            else:
                # 布尔修饰符
                modifiers[part] = True

        return modifiers

    def _is_dns_pattern(self, pattern: str) -> bool:
        """判断是否为 DNS 规则模式（无路径）"""
        # 移除 || 和 ^ 后检查是否像纯域名
        clean = pattern.lstrip('|').rstrip('^')
        return '/' not in clean and '?' not in clean

    def _extract_domain(self, pattern: str) -> Optional[str]:
        """从模式中提取域名"""
        # 移除 || 前缀和 ^ 后缀
        clean = pattern.lstrip('|').rstrip('^')
        # 提取域名部分（去掉路径）
        if '/' in clean:
            clean = clean.split('/')[0]
        return clean if clean else None

    def _calculate_adblock_strength(self, pattern: str, modifiers: Dict) -> int:
        """计算 Adblock 规则的强度评分"""
        score = 0

        # || 前缀（匹配子域）
        if pattern.startswith('||'):
            score += 10

        # 精确域名匹配（无通配符）
        if '*' not in pattern and '?' not in pattern:
            score += 3

        # $important 修饰符
        if 'important' in modifiers or modifiers.get('important') == True:
            score += 20

        # 修饰符数量（每增加一个修饰符，精确度+2）
        score += len(modifiers) * 2

        return score
