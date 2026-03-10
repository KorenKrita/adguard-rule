# AdGuard 规则合并工具

自动合并多个 AdGuard 订阅源，去除重复规则。

## 功能

- 合并广告过滤规则
- 合并白名单规则（支持订阅 + 独立规则）
- 合并 DNS 过滤规则
- 精确去重，保留首次出现的规则
- GitHub Actions 自动定时更新

## 配置

编辑 `config.yaml`：

```yaml
filters:
  - name: "AdGuard Base"
    url: "https://filters.adtidy.org/extension/chromium/filters/2.txt"

whitelist:
  urls:
    - name: "Example Allowlist"
      url: "https://example.com/allow.txt"
  rules:
    - "@@||baidu.com^"

dns:
  - name: "AdGuard DNS Filter"
    url: "https://filters.adtidy.org/extension/chromium/filters/15.txt"
```

## 输出

合并后的规则文件：

- `output/filter.txt` - 广告过滤规则
- `output/whitelist.txt` - 白名单规则
- `output/dns.txt` - DNS 过滤规则

每个文件包含：
- 更新时间和总规则数
- 所有来源 URL 及其规则数

## 手动运行

```bash
pip install pyyaml requests
python -m src.main
```

## 自动更新

GitHub Actions 每天 02:00 UTC 自动运行，也可手动触发。
