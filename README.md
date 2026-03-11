# AdGuard 规则合并工具

自动合并多个 AdGuard 订阅源和手动规则，去除重复规则，生成优化的过滤规则集。

## 主要特性

### 智能去重
- **两阶段去重流程**
  1. **文本去重**：去除完全相同的规则行
  2. **语义去重**：识别语法不同但功能相同的规则

- **语义去重能力**
  - 识别等价形式：`127.0.0.1 example.com` = `0.0.0.0 example.com` = `example.com` = `||example.com^`
  - 识别修饰符别名：`$doc` = `$document`
  - 强度评估：保留更强的规则（如通配符规则覆盖精确域名）
  - 例外规则正确处理：`@@||example.com^` 与普通规则共存

- **非屏蔽 hosts 过滤**
  - 自动过滤指向真实 IP 的 hosts 条目（如 `108.177.125.188 mtalk.google.com`）
  - 只保留阻断类型的 hosts：`127.0.0.1`、`0.0.0.0`、`::1` 等

### 自适应排序
根据每次运行的有效规则数，自动调整订阅源顺序：
- 有效规则多的订阅源排在前面（优先处理，提高去重效率）
- 有效规则少的订阅源排在后面（减少重复下载和处理）

### 详细统计
- 每个订阅源的原始规则数、有效数、使用率
- 去重统计：总输入、最终保留、去重数量
- GitHub Actions commit 消息显示去重详情

## 配置

编辑 `config.yaml`：

```yaml
# 广告过滤规则
filters:
  # 手动配置的规则（优先级高于订阅源）
  manual_rules:
    - "||example.com^"
    - "127.0.0.1 ad.example.com"
  # 订阅源（会自动按有效率排序）
  urls:
    - name: "AdGuard Base"
      url: "https://filters.adtidy.org/extension/chromium/filters/2.txt"

# 白名单规则
whitelist:
  urls:
    - name: "Example Allowlist"
      url: "https://example.com/allow.txt"
  manual_rules:
    - "@@||baidu.com^"

# DNS 过滤规则
dns:
  urls:
    - name: "AdGuard DNS"
      url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  manual_rules:
    - "||dns.example.com^"
```

## 输出

合并后的规则文件：

- `output/filter.txt` - 广告过滤规则
- `output/whitelist.txt` - 白名单规则
- `output/dns.txt` - DNS 过滤规则

文件头部包含：
```
! Title: Merged Filter
! Updated: 2026-03-11 08:30:00 UTC
! Total: 682428 rules
! Sources:
!   - HyperADRules: 442424 total, 442424 used (100.0%) - https://...
!   - all.txt: 489714 total, 271587 used (55.5%) - https://...
```

## 手动运行

```bash
pip install -r requirements.txt
python -m src.main
```

输出示例：
```
Loading configuration...

[1/3] Processing filter rules...
    Filtered 44 non-blocking hosts
  -> 682428 rules written to output/filter.txt (filtered 1703086 duplicates
      including 311527 semantic duplicates)

[Dedup Stats]
FILTER_TOTAL=2385514
FILTER_COUNT=682428
...
```

## 自动更新

GitHub Actions 每天 02:00 UTC（北京时间 10:00）自动运行，也可手动触发。

Commit 消息格式：
```
Update rules: filter=682428(-1703086), whitelist=6638(-5404), dns=604664(-1404484) [2026-03-11 08:30:00 UTC]
```

## 项目结构

```
.
├── config.yaml              # 配置文件
├── src/
│   ├── main.py             # 主程序入口
│   ├── config.py           # 配置加载与管理
│   ├── downloader.py       # 规则下载（并行+重试）
│   ├── merger.py           # 规则合并与去重
│   └── semantic/           # 语义去重引擎
│       ├── __init__.py
│       ├── parser.py       # 规则解析器
│       ├── canonical.py    # 规范化形式构建
│       ├── strength.py     # 规则强度评估
│       ├── deduplicator.py # 去重引擎
│       └── types.py        # 类型定义
├── tests/                  # 测试文件（89个测试）
├── output/                 # 输出目录
└── .github/workflows/
    └── merge.yml           # GitHub Actions 工作流
```

## 性能

- 60万规则处理时间：约 8 秒
- 处理速度：约 7.5万规则/秒
- 内存占用：主要规则集约 200-300MB

## 测试

```bash
python -m pytest tests/ -v
```

## License

MIT
