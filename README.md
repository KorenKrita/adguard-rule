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

### 高级变体生成

针对 DNS 过滤和 Filter 过滤有大量重复规则的场景（约 47% 重复），自动生成两组优化变体：

| 变体组 | 文件 | 适用场景 |
|--------|------|----------|
| **DNS 优先** | `dns-full.txt` + `filter-lite.txt` | 开启 DNS 过滤的环境（DNS 过滤性能更好） |
| **Filter 优先** | `dns-lite.txt` + `filter-full.txt` | 仅使用 Filter 的环境（部分环境无法使用 DNS 过滤） |

**处理流程**：
1. **内部去重**：分别对 filter、dns、whitelist 进行语义去重
2. **优先级去重**：根据变体类型保留优先级方的重复规则
3. **白名单合并**：将 whitelist 合并到各变体，进行冲突消解
4. **最终去重**：再次内部去重，输出优化后的规则集

**冲突消解逻辑**：
- **注册用法保留**：`||example.com^` + `@@||api.example.com^`（大黑小白）保留两者
- **完全覆盖消除**：白名单完全覆盖所有相关黑名单时，两者都消除
- **部分覆盖处理**：只消除被覆盖的具体规则

### 自适应排序
根据每次运行的有效规则数，自动调整订阅源顺序：
- 有效规则多的订阅源排在前面（优先处理，提高去重效率）
- 有效规则少的订阅源排在后面（减少重复下载和处理）

### 详细统计
- 每个订阅源的原始规则数、有效数、使用率
- 去重统计：总输入、最终保留、去重数量
- 变体生成统计：各变体文件规则数
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

### 基础输出文件

- `output/filter.txt` - 广告过滤规则（~68万条）
- `output/whitelist.txt` - 白名单规则
- `output/dns.txt` - DNS 过滤规则（~60万条）

### 高级变体文件

- `output/dns-full.txt` - DNS 优先完整版（重复规则保留 DNS 版本）
- `output/filter-lite.txt` - DNS 优先精简版（移除与 DNS 重复的规则）
- `output/dns-lite.txt` - Filter 优先精简版（移除与 Filter 重复的规则）
- `output/filter-full.txt` - Filter 优先完整版（重复规则保留 Filter 版本）

### 文件格式

所有输出文件头部包含：
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

[1/5] Processing filter rules...
    Filtered 44 non-blocking hosts
  -> 682428 rules written to output/filter.txt (filtered 1703086 duplicates
      including 311527 semantic duplicates)

[2/5] Processing whitelist rules...
  -> 6638 rules written to output/whitelist.txt

[3/5] Processing DNS filter rules...
  -> 604664 rules written to output/dns.txt

[4/5] Optimizing config order...
  -> Config order updated

[5/5] Generating variant files...
  -> 315401 rules written to output/dns-full.txt
  -> 367027 rules written to output/filter-lite.txt
  -> 290227 rules written to output/dns-lite.txt
  -> 392201 rules written to output/filter-full.txt

[Dedup Stats]
FILTER_TOTAL=2385514
FILTER_COUNT=682428
WHITELIST_TOTAL=12042
WHITELIST_COUNT=6638
DNS_TOTAL=2009148
DNS_COUNT=604664
```

## 自动更新

GitHub Actions 每天 02:00 UTC（北京时间 10:00）自动运行，也可手动触发。

Commit 消息格式：
```
Update rules: filter=682428(-1703086), whitelist=6638(-5404), dns=604664(-1404484) [2026-03-11 08:30:00 UTC]

📊 规则统计:
- Filter: 682428 条 (去重 1703086)
- DNS: 604664 条 (去重 1404484)
- Whitelist: 6638 条 (去重 5404)

🔗 含变体: dns-full / filter-lite / dns-lite / filter-full
```

## 项目结构

```
.
├── config.yaml                 # 配置文件
├── src/
│   ├── main.py                # 主程序入口
│   ├── config.py              # 配置加载与管理
│   ├── downloader.py          # 规则下载（并行+重试）
│   ├── merger.py              # 规则合并与去重
│   ├── conflict_resolver.py   # 白名单冲突消解
│   ├── variant_generator.py   # 高级变体生成
│   └── semantic/              # 语义去重引擎
│       ├── __init__.py
│       ├── parser.py          # 规则解析器
│       ├── canonical.py       # 规范化形式构建
│       ├── strength.py        # 规则强度评估
│       ├── deduplicator.py    # 去重引擎
│       └── types.py           # 类型定义
├── tests/                     # 测试文件（146个测试）
├── output/                    # 输出目录
├── docs/                      # 设计文档
│   ├── advanced-variants-design.md
│   └── semantic-deduplication-design.md
└── .github/workflows/
    └── merge.yml              # GitHub Actions 工作流
```

## 性能

- 基础规则处理（60万条）：约 8 秒
- 变体生成（含冲突消解）：约 15-20 秒
- 处理速度：约 7.5万规则/秒
- 内存占用：主要规则集约 200-300MB

## 测试

```bash
python -m pytest tests/ -v
```

测试覆盖：
- 基础模块：配置、下载、合并
- 语义去重：解析器、规范化、强度评估
- 冲突消解：注册用法、覆盖检测
- 变体生成：DNS/Filter 优先级、重复检测

## License

MIT
