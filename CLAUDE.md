# CLAUDE.md

## 项目概览

AdGuard 规则合并工具 — 自动合并多个 AdGuard 订阅源，执行文本+语义两阶段去重，生成优化的过滤规则集和变体文件。

- 语言：Python 3.13+
- 依赖：`requests`, `PyYAML`（见 `requirements.txt`）
- CI：GitHub Actions 每天 02:00 UTC 自动运行（`.github/workflows/merge.yml`）

## 常用命令

```bash
# 安装依赖
pip install -r requirements.txt

# 运行主程序（会下载远程规则列表，需要网络）
python -m src.main

# 运行全部测试
python -m pytest tests/ -v

# 运行特定测试文件
python -m pytest tests/test_semantic_parser.py -v

# 分析 DNS 与 Filter 规则重合度
python tools/analyze_overlap.py
python tools/analyze_overlap.py --detail
```

## 代码结构

```
src/
├── main.py                 # 入口，5 阶段处理管道
├── config.py               # YAML 配置加载、验证、自适应排序
├── downloader.py           # 并行下载 + 重试 + 非屏蔽 hosts 过滤
├── merger.py               # 文本去重、规则合并、文件头生成
├── conflict_resolver.py    # 白名单与黑名单冲突消解
├── variant_generator.py    # 4 种变体生成（DNS/Filter 优先 × Full/Lite）
├── constants.py            # 全局常量（屏蔽 IP、最大规则长度等）
└── semantic/               # 语义去重引擎
    ├── types.py            # RuleType 枚举（11 种）、ParsedRule 数据类
    ├── parser.py           # 规则解析器（识别 11+ 规则格式）
    ├── canonical.py        # 规范化形式构建、修饰符别名展开
    ├── strength.py         # 规则强度/特异性评估
    └── deduplicator.py     # 语义去重引擎（索引、覆盖关系检测）

tests/                      # 146 个测试，与 src/ 模块一一对应
docs/                       # 设计文档（语义去重、变体生成等）
tools/                      # 辅助脚本（重合度分析等）
output/                     # 生成的规则文件（已提交到 git）
config.yaml                 # 用户配置（订阅源 URL、手动规则）
```

## 处理管道

1. 加载 `config.yaml`
2. 下载 + 文本去重 + 语义去重 → `output/filter.txt`
3. 下载 + 文本去重 + 语义去重 → `output/whitelist.txt`
4. 下载 + 文本去重 + 语义去重 → `output/dns.txt`
5. 按有效规则数自适应排序 config
6. 生成 4 种变体（含冲突消解）→ `output/{dns,filter}-{full,lite}.txt`
7. 输出统计信息供 GitHub Actions 使用

## 开发规范

- 保持函数短小、逻辑清晰，不做过度抽象
- 保留并扩展 type hints
- 遵循 `src/` 和 `tests/` 中已有的命名模式
- 中文注释/docstring 可以，保持与周围代码一致
- 不要手动编辑 `output/` 目录下的生成文件
- `config.yaml` 是用户配置，除非明确要求否则不要修改
- 不要引入不必要的新依赖
- 变更如影响输出规则数或格式，需在总结中说明

## 测试策略

- 修改语义去重逻辑 → 优先运行 `tests/test_semantic_*.py`
- 修改合并/输出行为 → 优先运行 `tests/test_merger.py`、`tests/test_conflict_resolver.py`、`tests/test_variant_generator.py`
- 避免依赖网络的测试，用 mock 替代远程下载
- 先运行最相关的测试，再根据需要扩大范围

## 注意事项

- 完整运行 `python -m src.main` 会下载远程规则列表，在离线或受限环境中谨慎使用
- `output/*.txt` 虽已提交 git，但应视为构建产物
- `tools/` 中有辅助分析脚本，优先复用而非重写
- `docs/` 包含设计文档，架构或行为变更时应同步更新
