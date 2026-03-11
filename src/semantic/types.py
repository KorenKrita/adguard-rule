from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Any
from enum import Enum, auto


class RuleType(Enum):
    """规则类型枚举"""
    DNS_FILTER = auto()      # ||example.com^ 风格的 DNS 规则
    AD_BLOCK = auto()        # 广告过滤规则（带修饰符）
    HOSTS = auto()           # /etc/hosts 风格
    DOMAIN_ONLY = auto()     # 纯域名列表
    EXCEPTION = auto()       # 例外规则 @@
    COSMETIC = auto()        # 元素隐藏规则 ##
    HTML_FILTER = auto()     # HTML 过滤规则 $$#
    SCRIPTLET = auto()       # Scriptlet 规则 #%#
    COMMENT = auto()         # 注释
    UNKNOWN = auto()         # 未知类型


@dataclass
class ParsedRule:
    """解析后的规则对象"""
    raw: str                            # 原始规则文本（输出时使用）
    rule_type: RuleType                 # 规则类型
    pattern: str                        # 匹配模式（域名/URL模式）
    modifiers: Dict[str, Any]           # 修饰符字典
    is_exception: bool                  # 是否例外规则
    strength_score: int = 0             # 强度评分
    normalized_domain: Optional[str] = None  # 规范化后的域名

    def __hash__(self):
        return hash(self.raw)

    def __eq__(self, other):
        if not isinstance(other, ParsedRule):
            return False
        return self.raw == other.raw
