# AdGuard 规则合并工具

自动合并多个 AdGuard 订阅源和手动规则，去除重复规则。

## 功能

- 合并广告过滤规则（支持订阅源 + 手动规则）
- 合并白名单规则（支持订阅源 + 手动规则）
- 合并 DNS 过滤规则（支持订阅源 + 手动规则）
- 精确去重，保留首次出现的规则
- 显示每个订阅源的规则总数、有效数、使用率
- **自适应排序**：根据每次运行结果自动调整订阅源顺序（使用率高的优先）
- GitHub Actions 自动定时更新

## 配置

编辑 `config.yaml`（订阅源会自动按有效率排序，无需手动调整）：

```yaml
# 广告过滤规则
filters:
  # 手动配置的规则（优先级高于订阅源）
  manual_rules:
    - "||example.com^"
    - "127.0.0.1 ad.example.com"
  # 订阅源
  urls:
    - name: "AdGuard Base"
      url: "https://filters.adtidy.org/extension/chromium/filters/2.txt"

# 白名单规则
whitelist:
  # 订阅源
  urls:
    - name: "Example Allowlist"
      url: "https://example.com/allow.txt"
  # 手动配置的规则
  rules:
    - "@@||baidu.com^"

# DNS 过滤规则
dns:
  # 订阅源
  urls:
    - name: "AdGuard DNS"
      url: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
  # 手动配置的规则
  manual_rules:
    - "||dns.example.com^"
```

## 输出

合并后的规则文件：

- `output/filter.txt` - 广告过滤规则
- `output/whitelist.txt` - 白名单规则
- `output/dns.txt` - DNS 过滤规则

每个文件包含：
- 更新时间和总规则数
- 所有来源及其统计信息：
  - `规则总数` - 该来源的原始规则数
  - `有效数` - 去重后实际生效的规则数
  - `使用率` - 有效数 ÷ 总数（百分比）

示例：
```
! Title: Merged Filter
! Updated: 2026-03-10 10:00:00 UTC
! Total: 834496 rules
! Sources:
!   - AdGuard Base: 150000 total, 138384 used (92.3%) - https://filters.adtidy.org/...
!   - AdGuard Chinese: 22000 total, 21742 used (98.8%) - https://filters.adtidy.org/...
```

## 手动运行

```bash
pip install pyyaml requests
python -m src.main
```

## 自动更新

GitHub Actions 每天 02:00 UTC（北京时间 10:00）自动运行，也可手动触发。

每次运行后，工具会根据各订阅源的**有效规则数**自动调整 `config.yaml` 中的顺序：
- 有效规则多的订阅源排在前面（优先处理，提高去重效率）
- 有效规则少的订阅源排在后面（重复内容较多，后置减少浪费）

## 项目结构

```
.
├── config.yaml           # 配置文件
├── src/
│   ├── main.py          # 主程序入口
│   ├── config.py        # 配置加载
│   ├── downloader.py    # 规则下载
│   └── merger.py        # 规则合并与去重
├── output/              # 输出目录
│   ├── filter.txt       # 广告过滤规则
│   ├── whitelist.txt    # 白名单规则
│   └── dns.txt          # DNS 过滤规则
└── .github/workflows/
    └── merge.yml        # GitHub Actions 工作流
```
