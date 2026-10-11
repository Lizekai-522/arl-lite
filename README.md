# arl-lite

> 灯塔 ARL 资产侦察系统的**降级增强版** — 2G 内存机器友好,CLI + TUI,单用户长期资产侦察

[![Phase](https://img.shields.io/badge/phase-7-blue)](docs/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Zero Deps](https://img.shields.io/badge/pip_dependencies-0-green)](pyproject.toml)

## 这是什么

> 目标平台:**Linux**(2G 内存 VPS 场景)。TUI 需要 Unix 终端;CLI 各子命令在标准 Python 3.10+ 环境均可运行。外部工具(nmap/subfinder/nuclei)为可选依赖,按需安装。

ARL(灯塔 Asset Reconnaissance Lighthouse)是国内流行的红队资产侦察平台,功能强但资源消耗大(Web UI + MongoDB + 多 worker)。`arl-lite` 把它**重写**为:

- **2 GB 内存机器** 跑得动
- **CLI + TUI**(不要 Web UI)
- **单用户长期资产侦察**(像 sysadmin 自己的工具)
- **零外部 pip 依赖**(PyPI 不可达环境也能跑)
- **全功能保留**:13 个 ARL 核心能力 + 1 个新增(关联分析)+ 4 个扩展

## 特性

| 类别 | 能力 | 状态 |
|---|---|---|
| **数据源 (9)** | subfinder / crtsh / rapiddns / hackertarget / otx / dnsdumpster / virustotal / quake / fofa | ✓ |
| **侦察模块 (8)** | portscan (nmap+Python) / httpx_probe / fingerprint (2015 规则:内置 119 + ARL 库) / dns (自写) / whois / dirscan / nuclei / github | ✓ |
| **关联分析 (37 YAML 规则)** | 数据库暴露/管理面板/WordPress/Jenkins/Nacos/Redis/Elasticsearch/SNMP/VNC... | ✓ |
| **AI 集成 (5 边界 + 4 provider)** | ask / report / explain / suggest / fix × OpenAI/Anthropic/Google/Ollama | ✓ |
| **交互** | 12 菜单 TUI / MCP stdio JSON-RPC 2.0 (4 工具) / 6 报告格式 + AI report | ✓ |
| **告警** | webhook (ntfy/Slack/通用) + 监控变更事件 + watch 持续模式 | ✓ |
| **性能** | 入库复用连接(5000 行 58s→10s)+ bulk_insert 批量 API / 并发执行 / FTS5 全文搜索 | ✓ |
| **3 态纪律** | `{ok, data, error}` — 失败源如实记录 | ✓ |
| **SIGTERM 优雅停止** | 1s 信号 → 1.26s 任务退出 | ✓ |
| **零假数据** | 失败 = `ok=False, error_type=network/rate_limit/auth` | ✓ |
| **零外部 pip 依赖** | 纯 stdlib,内存 35 MB,2G 机器直接跑 | ✓ |

## 架构 (v0.7.8)

```
arl-lite
├── arl_lite/
│   ├── core/
│   │   ├── base_module.py            # BaseModule + 3 态 SourceResult/ModuleResult
│   │   ├── signal_handler.py         # SIGTERM 优雅停止
│   │   ├── task_runner.py            # TaskRunner(asyncio.gather 并发)
│   │   ├── fingerprint_engine.py     # AST 安全求值指纹匹配
│   │   ├── correlation_engine.py     # YAML 规则执行器(37 规则)
│   │   ├── monitor.py                # 监控 CRUD + 变更事件
│   │   ├── risk_score.py             # 风险画像(score + level)
│   │   └── watcher.py                # Watch 模式(持续监控 + 告警)        ★ v0.7
│   ├── db/
│   │   ├── schema.sql                # 14 表 + 4 视图 + 36 索引 + 9 触发器
│   │   └── storage.py                # upsert/diff/query/FTS5 + bulk_insert ★ v0.7
│   ├── integrations/                 # 9 数据源 + portscan + httpx_probe + dns_lookup + whois_lookup
│   ├── modules/
│   │   ├── recon/
│   │   │   ├── domains_hosts/        # 9 个数据源 module
│   │   │   ├── ports/                # portscan
│   │   │   ├── sites/                # httpx_probe
│   │   │   ├── fingerprints/         # fingerprint
│   │   │   ├── dns/                  # dns / whois
│   │   │   ├── dirs/                 # dirscan / nuclei
│   │   │   └── github.py             # github 代码泄漏
│   │   └── analysis/
│   │       └── rules/                # 37 条 YAML 关联分析规则
│   ├── ai/                           # AI 集成(5 边界 + 4 provider)
│   ├── notify/                       # Webhook 通知(ntfy/Slack/通用)        ★ v0.7
│   ├── mcp/                          # MCP stdio JSON-RPC 2.0
│   ├── fingerprints/                 # 2015 条指纹(内置 119 + ARL 库 1896,MIT)
│   ├── tui/                          # 12 菜单 ANSI TUI
│   ├── cli.py                        # 15+ 子命令
│   └── cli_report_html.py            # HTML 报告
├── tests/
│   ├── test_phase1.py                # 基础
│   ├── test_phase2.py                # 集成
│   ├── test_phase3.py                # 关联/监控/调度/TUI/风险
│   ├── test_phase4.py                # AI 集成
│   ├── test_phase5.py                # dirscan/nuclei/github/MCP
│   ├── test_phase6.py                # DNS/WHOIS/HTML
│   ├── test_phase7.py                # bulk_insert/notify/watcher          ★ v0.7
│   ├── test_edge.py                  # 13 类边界
│   └── test_concurrency.py           # 并发 + 隔离
└── docs/
    ├── PROJECT_PLAN.md               # 1454 行完整设计
    ├── COMPETITOR_ANALYSIS.md        # 184 行竞品分析
    └── COMPETITOR_ANALYSIS.md        # 竞品分析(ARL/SpiderFoot 源码直读)
```

## 快速开始

### 安装

```bash
# 零依赖,直接拷走用
tar -xzf arl-lite-v0.7.1.tar.gz
cd arl-lite

# 或者 pip install -e . (但其实不需要,stdlib 就够)
```

### 跑一个任务

```bash
# 跑全部默认模块
arl-lite run -t example.com

# 选特定模块
arl-lite run -t example.com -m dns,whois,subfinder,crtsh,portscan
```

输出:
```
[+] workspace: default
[+] target: example.com
[+] modules: ['dns', 'whois', 'subfinder', 'crtsh', 'portscan']

[+] done in 6.6s
[+] found: 109

[i] source status:
    ✓ dns: 8 found in 1.5s
    ✓ whois: 12 found in 0.5s
    ✓ rapiddns: 3 found in 4.0s
    ✓ portscan: 92 found in 0.5s
    ✗ subfinder: not installed
    ✗ crtsh: 502 Bad Gateway
```

### 查询 / 搜索 / 关联分析

```bash
# 查所有 hosts
arl-lite query hosts

# FTS5 全文搜索(需要 table 位置参数)
arl-lite search sites "mysql"
arl-lite search findings "redis"

# 跑关联分析
arl-lite correlate -w default
  23 correlations, max risk 9
  - dev_port_public: 104.20.23.154:8080
  - snmp_public: 104.20.23.154:161
  - vnc_exposed: 104.20.23.154:5900

# 风险画像
arl-lite risk summary -w default
  total correlations: 23
  by level: medium=9, high=12, critical=2
```

### 导出报告 (5 格式)

```bash
# JSON / CSV / TSV / Markdown / HTML
arl-lite export -w default --format json -o report.json
arl-lite export -w default --format html -o report.html   # ★ 单文件 HTML
arl-lite export -w default --format markdown -o report.md
```

### 持续监控 + 告警 (v0.7)

```bash
# Webhook 配置(本地 dry-run)
arl-lite notify test --provider local --min-severity high

# 实际 webhook(ntfy / Slack / 自建)
arl-lite notify test \
    --provider ntfy \
    --url https://ntfy.sh/your-secret-topic \
    --min-severity critical

# Watch 持续监控
arl-lite watch add example.com --interval 3600 --modules dns,whois
arl-lite watch add foo.com --interval 7200
arl-lite watch list
arl-lite watch start
# 前台运行,Ctrl+C 停止;变更写入 asset_changes,`arl-lite monitor changes` 可查
```

### MCP (Model Context Protocol) 集成

```bash
# 启动 MCP server (stdio JSON-RPC 2.0)
arl-lite mcp -w default
```

4 个 tools:
- `query_assets` — 查 domains/hosts/ports/sites/findings/correlations/monitors
- `search_findings` — FTS5 全文搜索
- `get_risk` — top N 风险资产
- `run_correlate` — 跑关联分析(参数 min_risk/limit)

### AI 集成 (5 边界点)

```bash
# 配置 provider
arl-lite ai config set openai --api-key sk-... --model gpt-4o
arl-lite ai config set ollama --base-url http://localhost:11434

# 5 个 boundary commands
arl-lite ai ask "解释这个关联分析"
arl-lite ai report -w default
arl-lite ai explain --finding-id 123
arl-lite ai suggest --target example.com
arl-lite ai fix --rule-id dev_port_public
```

## 17 modules

```
$ arl-lite tools list
[i] 17 modules available:
  [recon/dirs]
    - dirscan      v0.5.0  目录/文件扫描(80+ 内置路径,启发式过滤)
    - nuclei       v0.5.0  PoC 联动(nuclei binary + 20+ 内建模板 fallback)
  [recon/dns]
    - dns          v0.6.0  DNS 详细记录枚举(A/AAAA/NS/MX/TXT/SOA/CNAME)
    - whois        v0.6.0  WHOIS 域名注册信息(注册商/到期/状态/NS)
  [recon/domains-hosts]
    - crtsh        v0.1.0  通过 crt.sh 证书透明度日志查询子域
    - dnsdumpster  v0.2.0  通过 DNSDumpster 被动查询子域
    - fofa         v0.2.0  通过 FOFA 网络空间测绘被动查询子域
    - hackertarget v0.2.0  通过 HackerTarget 被动查询子域
    - otx          v0.2.0  通过 AlienVault OTX 被动 DNS 查询子域
    - quake        v0.2.0  通过 360 Quake 被动查询子域
    - rapiddns     v0.2.0  通过 RapidDNS 被动查询子域
    - subfinder    v0.1.0  通过 subfinder 枚举子域名
    - virustotal   v0.2.0  通过 VirusTotal 被动查询子域
  [recon/external]
    - github       v0.5.0  GitHub 代码泄漏监控
  [recon/fingerprints]
    - fingerprint  v0.2.0  对 HTTP 响应跑内置指纹库(115 条)
  [recon/ports]
    - portscan     v0.2.0  端口扫描(nmap 优先,纯 Python fallback)
  [recon/sites]
    - httpx_probe  v0.2.0  HTTP 站点探活(标题/状态码/Server/技术栈)
```

## 性能

### 入库性能 (自 v0.7.1)

```
5000 行 add_domain(逐行 upsert,真实扫描路径):
  v0.7.0(每行新建连接): 58174 ms
  v0.7.1(线程内复用连接 + WAL synchronous=NORMAL): 9890 ms  ← 5.9x
另提供 bulk_insert 批量 API(同数据集 ~300 ms,供脚本导入用)
```

### 内存 (单任务)

```
RSS:  35 MB (跑全部 9 源 + 端口 + 站点)
适合: 2 GB 内存 VPS
```

### 并发

```
17 module 端到端: ~10-15s (受外部 API 限制)
单 module 单独跑: 0.5-4s
```

## 17 子命令

| Command | 功能 |
|---|---|
| `run` | 跑扫描任务(选 module / workspace) |
| `query` | 查资产(7 表) |
| `search` | FTS5 全文搜索 |
| `correlate` | 跑关联分析 |
| `monitor` | 监控 CRUD + 变更事件 |
| `risk` | 风险画像(summary / top) |
| `diff` | 真 diff(资产对比) |
| `export` | 导出(5 格式) |
| `workspace` | workspace 管理 |
| `stats` | 统计 |
| `tui` | 12 菜单交互终端 |
| `ai` | AI 集成(5 边界) |
| `notify` | Webhook 测试 / 配置 ★ v0.7 |
| `watch` | 持续监控 / watch 模式 ★ v0.7 |
| `tools` | 工具管理(check / list) |
| `mcp` | MCP stdio JSON-RPC 2.0 server |
| `version` | 版本 |

## 关联结果与当前风险

关联规则可声明 `identity: auto|port|site|host|domain|workspace`（默认 `auto`）。
端口身份包含协议、地址和端口（例如 `tcp://192.0.2.1:6379`），站点使用完整 URL。
显式 `host` 按 IP（无 IP 则主机名）聚合；`workspace` 按工作空间聚合。
聚合保存完整 `matched_assets`，不会只留下最后一个端口的证据。

`correlations.status` 为 `active` 或 `resolved`，`risk` 只计算 active 命中。
只有某规则完整执行成功才关闭该规则在当前工作空间的旧未命中结果；SQL 错误、
规则解析失败、collect 超出 1000 行限制都会保留旧风险。`evaluated_run` 与
`resolved_run` 记录评估 UUID，`correlation_history` 保存命中和关闭时的完整快照。
历史可通过 `Storage.query("correlation_history")` 查询；当前结果可使用
`arl-lite query correlations --filter "status='active'"`。
Python 的普通 hit 列表仍可保存，但没有完整评估元数据的列表不会关闭旧结果。

升级保留旧库尚存证据；升级前已经相互覆盖的端口证据无法恢复。
这里的“当前”指最近成功规则评估的已存资产状态；规则不会主动重扫，也不会把
缺少扫描结果解释为资产消失。多次评估应顺序执行、保存；历史尚无自动清理策略。

## 任务状态与退出码

`run` 的任务状态(可 `arl-lite query tasks` 查看)与进程退出码口径对齐:

| 场景 | task status | exit code |
|---|---|---|
| 全部源成功 | `DONE` | 0 |
| 部分源成功(脚本按 0 处理,details 看 `sources_failed` / `source_status` 表) | `DONE_PARTIAL` | 0 |
| 0 个源成功(全失败 / 模块全部未找到) | `FAILED` | 1 |
| 参数错误(空 modules / 拼错模块名 / workspace 不存在) | — | 2 |
| Ctrl+C / SIGTERM | `STOPPED` | 130 |

## 6 报告格式

| Format | 文件 | 用途 |
|---|---|---|
| `json` | `report.json` | 程序处理 / API |
| `table` | stdout | 终端查看 |
| `csv` | `report.csv` | Excel / 脚本 |
| `tsv` | `report.tsv` | 脚本处理 |
| `markdown` | `report.md` | 文档 / 报告 |
| `html` | `report.html` | 单文件 HTML(内嵌 CSS,无 JS)★ |

(另有 `arl-lite ai report` 命令独立生成 AI 分析报告)

## 5 关键纪律

1. **3 态返回**: `ok=True/False`, `data` / `error`, `error_type` 5 类分类
2. **真 diff**: UNIQUE 索引 + 实际查询对比,不用 `len()` 估计
3. **SIGTERM 优雅**: 信号 → task runner `request_stop()` → 1.26s 退出
4. **死源可见**: 失败的源明确标记 `ok=False + error_type`,不假装数据
5. **scope 授权**: 提示用户输入授权目标,log 记录

## 设计决策

### 为什么不 fork ARL / SpiderFoot?

- **License 风险**: 商业工具 / 协议限制
- **2G 内存不友好**: ARL MongoDB + 6 worker 起步 4 GB
- **过度工程**: Web UI / 多用户 / 队列对我们没用

### 为什么 SQLite + FTS5?

- 零外部依赖
- 足够小数据量(几千-几万资产)
- FTS5 全文搜索比 LIKE 快
- 单一文件备份简单

### 为什么自己写 DNS packet 解析?

- dnspython 装了也不能用(PyPI 不可达)
- DNS 协议不复杂,200 行 stdlib 搞定
- 含压缩指针支持

### 为什么 hand-rolled YAML parser?

- PyYAML 不能用
- 37 条规则都简单,支持 scalar/list/literal block 够用
- 不引 C 依赖

### 为什么 hand-rolled mini LLM client?

- LiteLLM 不能用
- 4 个 provider 协议不复杂,各 30 行 stdlib
- 完全控制 timeout / retry / error mapping

## 已知限制

- **YAML 解析器**是手写的(支持 scalar/list/literal-block),复杂 YAML 可能解析失败
- **Nuclei fallback** 模板 22 个,不如社区 5000+ 模板,但纯 stdlib 跑得动
- **GitHub 搜索**无 token 时 60 req/h,有 token 5000 req/h
- **AI 集成**不持久化对话历史(每次 stateless)
- **批量入库**目前 6 表,其他表仍需逐行

## 测试覆盖

```
test_phase1.py          6/6  基础
test_phase2.py          8/8  集成 + 端到端
test_phase3.py          8/8  关联/监控/调度/TUI/风险
test_phase4.py          8/8  AI 集成 + 24 bug regression
test_phase5.py          7/7  dirscan/nuclei/github/MCP
test_phase6.py          6/6  DNS/WHOIS/HTML 报告
test_phase7.py          8/8  bulk/notify/watcher     ★
test_edge.py           13/13 边界
test_concurrency.py     7/7  并发 + 隔离

bug audit history: 12 + 12 + 7 + 8 = 39 真 bug,全部修
```

## Roadmap (2026-09 调研结论)

结论:**继续投入本项目**。ARL 停更后的活跃后继(ARL-Next、nemo_go v3)全是 Web+MongoDB 重平台路线,"2GB 单机 / 零依赖 / CLI"生态位没有直接竞品。

值得借鉴的能力(按性价比排序):

1. **指纹库扩容**:从 ARL webapp.json(MIT,1917 条)导入,适配现有指纹引擎
2. **子域接管检测**:can-i-take-over-xyz 指纹表 + CNAME 链校验,纯 stdlib 约 150 行
3. **ksubdomain 接入**:主动子域枚举(无状态 UDP,低内存),沿用现有 subprocess 架构
4. **ASN/CDN 归属字段**:Team Cymru whois / ipinfo 免费接口,约 50-80 行
5. **preset 分层**(参考 reconftw):慢速/正常/全面三档工作流,纯配置层

不做:Web UI / 多用户平台化 / Mongo+Celery / Amass v4 / 嵌入 GPL 规则(Wappalyzer、OneForAll)。

## License

MIT

## 致谢

- [灯塔 ARL](https://github.com/AttackAllForks/ARL) — 设计参考
- [SpiderFoot](https://github.com/smicallef/spiderfoot) — 关联分析规则参考
- [ProjectDiscovery](https://github.com/projectdiscovery) — subfinder/nuclei
- [crt.sh](https://crt.sh/) — 证书透明度数据源
