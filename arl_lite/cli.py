"""arl_lite CLI

Phase 1 命令(纯 argparse,零外部依赖):
    arl-lite run -t example.com --modules subfinder,crtsh
    arl-lite query domains
    arl-lite query sites --filter "title like '%admin%'"
    arl-lite search sites "admin"
    arl-lite export json --workspace example.com
    arl-lite workspace list
    arl-lite workspace create foo
    arl-lite stats
    arl-lite tools check
    arl-lite diff --since 7d
    arl-lite version
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

# 让 from arl_lite import ... 能用
from . import __version__
from .db.storage import Storage, get_default_workspace_root
from .core.task_runner import TaskRunner
from .core.signal_handler import GracefulShutdown
from .modules.registry import discover_modules

log = logging.getLogger("arl_lite.cli")


# ============================================
# 输出辅助
# ============================================

def _use_color() -> bool:
    """只在交互终端上用 ANSI 颜色,重定向/管道不污染输出"""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _ensure_workspace_exists(name: str) -> int:
    """只读类命令的 workspace 存在性检查,不自动创建。

    Storage() 会静默自动创建 workspace——拼错 -w 的结果是"全 0 统计"
    加一个垃圾目录,用户会误判数据丢失。

    判定顺序(轻→重,避免检查本身产生副作用):
    1. 目录下有 data.db(覆盖 `run -w` 直建的库,零副作用)
    2. default 库注册表(覆盖 `workspace create` 只写表不建目录;
       仅在 default 库已存在时查——否则这个"检查"会自己创建 default)
    """
    ws_root = get_default_workspace_root()
    if (ws_root / name / "data.db").exists():
        return 0
    ref = None
    if (ws_root / "default" / "data.db").exists():
        try:
            ref = Storage(workspace="default")
            if any(w.get("name") == name for w in ref.list_workspaces()):
                return 0
        except Exception as e:
            log.debug(f"workspace existence check degraded: {e}")
            return 0  # 检查本身失败时不阻塞(降级为旧行为)
    available = set()
    if ref is not None:
        try:
            available |= {w.get("name", "") for w in ref.list_workspaces()}
        except Exception:
            pass
    if ws_root.exists():
        available |= {d.name for d in ws_root.iterdir() if d.is_dir()}
    available.discard("")
    print(f"[!] workspace not found: {name!r}", file=sys.stderr)
    if available:
        print(f"    available: {sorted(available)}", file=sys.stderr)
    return 1


def _print_table(rows: list[dict], cols: list[str] | None = None) -> None:
    """简单表格输出(无 rich 降级)"""
    if not rows:
        print("(empty)")
        return
    if cols is None:
        cols = list(rows[0].keys())
    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    sep = "  "
    print(sep.join(c.ljust(widths[c]) for c in cols))
    print(sep.join("-" * widths[c] for c in cols))
    for r in rows:
        print(sep.join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def _print_json(obj: Any, file=None) -> None:
    out = file or sys.stdout
    out.write(json.dumps(obj, ensure_ascii=False, indent=2, default=str))
    if file is None:
        out.write("\n")


def _print_csv(rows: list[dict], file=None) -> None:
    """CSV 输出(所有表所有列)"""
    import csv as csv_mod
    if not rows:
        return
    cols = list(rows[0].keys())
    writer = csv_mod.writer(file or sys.stdout)
    writer.writerow(cols)
    for r in rows:
        writer.writerow(["" if r.get(c) is None else str(r.get(c)) for c in cols])


def _print_tsv(rows: list[dict], file=None) -> None:
    """TSV 输出"""
    if not rows:
        return
    cols = list(rows[0].keys())
    out = file or sys.stdout
    out.write("\t".join(cols) + "\n")
    for r in rows:
        out.write("\t".join(
            ("" if r.get(c) is None else str(r.get(c))).replace("\t", " ").replace("\n", " ")
            for c in cols
        ) + "\n")


def _print_markdown(data: dict, file=None) -> None:
    """Markdown 输出(每个表一个 section)"""
    out = file or sys.stdout
    for table, rows in data.items():
        out.write(f"\n## {table} ({len(rows)} rows)\n\n")
        if not rows:
            out.write("_(empty)_\n")
            continue
        cols = list(rows[0].keys())
        out.write("| " + " | ".join(cols) + " |\n")
        out.write("|" + "|".join(["---"] * len(cols)) + "|\n")
        for r in rows:
            out.write("| " + " | ".join(_md_cell(r.get(c, "")) for c in cols) + " |\n")


def _md_cell(v) -> str:
    """单元格值:None→空串,竖线/链接语法转义。

    数据(站点 title 等)来自外部,markdown 导出若保留 `[x](url)`
    语法,贴进任何 markdown 渲染器就会触发外联请求/钓鱼链接。
    """
    s = str(v if v is not None else "")
    s = s.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
    return s.replace("|", "\\|").replace("\n", " ")


# ============================================
# 子命令
# ============================================

def cmd_run(args) -> int:
    """跑一个扫描任务"""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # 防御:target 边界
    if not args.target or not args.target.strip():
        print("[!] target must not be empty", file=sys.stderr)
        return 2
    if len(args.target) > 1000:
        print(f"[!] target too long: {len(args.target)} > 1000", file=sys.stderr)
        return 2
    if "\x00" in args.target:
        print("[!] target contains null byte", file=sys.stderr)
        return 2

    storage = Storage(workspace=args.workspace)
    runner = TaskRunner(storage=storage, workspace_id=storage.workspace_id)

    # SIGTERM 优雅停止
    shutdown = GracefulShutdown(runner)
    shutdown.install()

    # 解析 modules
    if args.modules is not None:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        # 空串/全逗号和拼错的模块名都提前拒绝:旧逻辑空串会静默跑默认模块
        # (意外发动 3 分钟扫描),拼错的名字只在执行期报错还可能 exit 0
        if not modules:
            print("[!] --modules parsed to empty list (check for stray commas)", file=sys.stderr)
            return 2
        available = discover_modules()
        unknown = [m for m in modules if m not in available]
        if unknown:
            print(f"[!] unknown module(s): {unknown}", file=sys.stderr)
            print(f"    available: {sorted(available.keys())}", file=sys.stderr)
            return 2
    else:
        modules = ["subfinder", "crtsh"]  # 默认

    print(f"[+] workspace: {args.workspace}")
    print(f"[+] target: {args.target}")
    print(f"[+] modules: {modules}")
    print()

    async def _go():
        return await runner.run(
            target=args.target,
            modules=modules,
            preset=args.preset,
        )

    result = asyncio.run(_go())

    print()
    print(f"[+] done in {result.duration_seconds:.1f}s")
    print(f"[+] found: {result.found}")
    if result.errors:
        print(f"[!] errors: {len(result.errors)}")
        for e in result.errors[:5]:
            print(f"    - {e}")
    # 显示每源状态(零假数据纪律)— source_status 由 TaskRunner 自动入库
    if result.sources:
        print()
        print("[i] source status:")
        for src in result.sources:
            mark = "✓" if src.ok else "✗"
            extra = f" ({src.error})" if src.error else ""
            print(f"    {mark} {src.source}: {len(src.data)} found in {src.duration:.1f}s{extra}")

    # 退出码:任一源成功即 0(部分降级 ≠ 全盘失败,cron/脚本才好判断);
    # 全部失败(或没跑成任何源)才非零
    ok_sources = sum(1 for s in result.sources if s.ok)
    return 0 if ok_sources > 0 else 1


def cmd_query(args) -> int:
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    rows = storage.query(args.table, filter_sql=args.filter, limit=args.limit)
    if args.format == "json":
        _print_json(rows)
    else:
        _print_table(rows)
    return 0


def cmd_search(args) -> int:
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    rows = storage.search(args.table, args.keyword, limit=args.limit)
    if args.format == "json":
        _print_json(rows)
    else:
        _print_table(rows)
    return 0


def cmd_export(args) -> int:
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    data: dict = {}
    for table in ["domains", "hosts", "ports", "sites", "findings", "tasks", "source_status", "correlations"]:
        data[table] = storage.query(table, limit=10000)
    fmt = getattr(args, "format", "json")
    output = getattr(args, "output", None)
    if output:
        # 用户直觉里 ~/x.html 是家目录;不展开会在 CWD 建出字面量 "~" 目录
        output = str(Path(output).expanduser())

    if fmt == "html":
        from .cli_report_html import write_html_report
        target = output or f"{args.workspace}_report.html"
        try:
            out_path = write_html_report(storage, args.workspace, target)
        except (IOError, OSError) as e:
            print(f"[!] HTML export failed: {e}", file=sys.stderr)
            return 1
        print(f"[+] HTML report written: {out_path}")
        print(f"    size: {out_path.stat().st_size} bytes")
        return 0

    # 其他格式:支持 -o 写文件(没 -o 输出到 stdout)
    if output:
        try:
            file = open(output, "w", encoding="utf-8")
        except (IOError, OSError) as e:
            print(f"[!] cannot open output file {output}: {e}", file=sys.stderr)
            return 1
    else:
        file = None  # 用 stdout

    try:
        if fmt == "json":
            _print_json(data, file=file)
        elif fmt == "csv":
            for table, rows in data.items():
                if file is None:
                    # 分隔行走 stderr:stdout 是机读数据流,混入垃圾行会污染表头
                    print(f"=== {table} ({len(rows)} rows) ===", file=sys.stderr)
                _print_csv(rows, file=file)
        elif fmt == "tsv":
            for table, rows in data.items():
                if file is None:
                    print(f"=== {table} ({len(rows)} rows) ===", file=sys.stderr)
                _print_tsv(rows, file=file)
        elif fmt == "markdown":
            _print_markdown(data, file=file)
        elif fmt == "table":
            for table, rows in data.items():
                print(f"\n=== {table} ({len(rows)} rows) ===")
                _print_table(rows)
        else:
            print(f"[!] unknown format: {fmt}", file=sys.stderr)
            return 2
    finally:
        if file is not None:
            file.close()

    if output:
        print(f"[+] {fmt} exported to {output}")
    return 0


def cmd_workspace_list(args) -> int:
    # workspace list 不依赖某个具体 workspace,显示所有
    # 但仍需要一个 Storage 实例来读 workspaces 表,用 "default" 即可
    ws = getattr(args, "workspace", None) or "default"
    storage = Storage(workspace=ws)
    rows = storage.list_workspaces()
    _print_table(rows, cols=["id", "name", "description", "ticket", "task_count", "last_active_at"])
    return 0


def cmd_workspace_delete(args) -> int:
    if not args.name or not args.name.strip():
        print("[!] workspace name must not be empty", file=sys.stderr)
        return 2
    if args.name in ("default",):
        print("[!] cannot delete built-in 'default' workspace", file=sys.stderr)
        return 2
    # 与 create/Storage 同款校验:名字会参与拼 workspace 目录路径
    if "/" in args.name or "\\" in args.name or args.name in (".", ".."):
        print(f"[!] invalid workspace name: {args.name!r}", file=sys.stderr)
        return 2
    # 用合并后的列表确认存在(list_workspaces 会并集目录扫描,
    # run 直接建的 workspace 也能被看到)
    temp_storage = Storage(workspace="default")
    exists = any(w.get("name") == args.name for w in temp_storage.list_workspaces())
    if not exists:
        print(f"[!] workspace {args.name!r} not found", file=sys.stderr)
        return 1
    if not args.yes:
        print(f"[!] deleting workspace {args.name!r} will remove its data. use -y to confirm", file=sys.stderr)
        return 2
    # 注册表每库独立:default 库(`workspace create` 写的)和该库自己
    # (`run -w` 写的)两处登记都要清,按名字删,别用别的库的 id
    try:
        temp_storage.delete_workspace_by_name(args.name)
    except Exception as e:
        print(f"[!] delete failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    try:
        Storage(workspace=args.name).delete_workspace_by_name(args.name)
    except Exception as e:
        log.debug(f"own-registry cleanup skipped: {e}")
    # 删目录
    import shutil
    ws_dir = temp_storage.workspace_root / args.name
    if ws_dir.exists():
        try:
            shutil.rmtree(ws_dir)
        except OSError as e:
            print(f"[!] warning: data dir not removed: {e}", file=sys.stderr)
    print(f"[+] workspace {args.name!r} deleted")
    return 0


def cmd_workspace_create(args) -> int:
    if not args.name or not args.name.strip():
        print("[!] workspace name must not be empty", file=sys.stderr)
        return 2
    if "/" in args.name or "\\" in args.name:
        print(f"[!] workspace name must not contain path separator: {args.name!r}", file=sys.stderr)
        return 2
    if args.name in (".", ".."):
        print(f"[!] workspace name must not be . or ..: {args.name!r}", file=sys.stderr)
        return 2
    # 用 default 临时 storage 来检查
    storage = Storage(workspace="default")
    for w in storage.list_workspaces():
        if w.get("name") == args.name:
            print(f"[!] workspace {args.name!r} already exists (id={w.get('id')})", file=sys.stderr)
            return 1
    try:
        wid = storage.create_workspace(
            name=args.name,
            description=args.description or "",
            ticket=args.ticket,
            valid_from=args.valid_from,
            valid_until=args.valid_until,
        )
    except Exception as e:
        print(f"[!] failed to create workspace: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(f"[+] workspace '{args.name}' created (id={wid})")
    return 0


def cmd_stats(args) -> int:
    ws = getattr(args, "workspace", None) or "default"
    if _ensure_workspace_exists(ws):
        return 1
    storage = Storage(workspace=ws)
    stats = storage.get_stats()
    _print_json(stats)
    return 0


def cmd_diff(args) -> int:
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    # 解析 since:7d / 24h / ISO 时间
    since_raw = args.since
    try:
        if since_raw.endswith("d"):
            days = int(since_raw[:-1])
            if days < 0:
                raise ValueError(f"days must be >= 0, got {days}")
            since = (datetime.utcnow() - timedelta(days=days)).isoformat()
        elif since_raw.endswith("h"):
            hours = int(since_raw[:-1])
            if hours < 0:
                raise ValueError(f"hours must be >= 0, got {hours}")
            since = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        else:
            since = since_raw
    except ValueError as e:
        print(f"[!] invalid --since '{since_raw}': {e}", file=sys.stderr)
        print(f"    valid: '7d' / '24h' / '2026-09-01'", file=sys.stderr)
        return 2

    table = args.table or "domains"
    rows = storage.diff_new_since(since, table=table)
    print(f"[+] new {table} since {since}: {len(rows)}")
    _print_table(rows)
    return 0


def cmd_correlate(args) -> int:
    """跑关联分析"""
    # 边界校验(Phase 3 审计发现)
    if args.min_risk is not None and not (0 <= args.min_risk <= 10):
        print(f"[!] --min-risk must be 0..10 (got {args.min_risk})", file=sys.stderr)
        return 2
    if args.limit is not None and args.limit <= 0:
        print(f"[!] --limit must be > 0 (got {args.limit})", file=sys.stderr)
        return 2
    from .core.correlation_engine import run_all_rules, save_correlations, load_all_rules
    from pathlib import Path
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    rules_dir = Path(__file__).parent / "modules" / "analysis" / "rules"
    rules = load_all_rules(rules_dir)
    print(f"[i] {len(rules)} rules loaded from {rules_dir.name}/")
    import time as _time
    start = _time.time()
    hits = run_all_rules(storage, rules_dir)
    elapsed = _time.time() - start
    n = save_correlations(storage, hits)
    print(f"[+] {len(hits)} hits, saved/refreshed {n} in {elapsed:.2f}s")

    # 按 risk 降序
    hits.sort(key=lambda h: -h.risk)
    # 过滤 min_risk
    hits = [h for h in hits if h.risk >= args.min_risk]
    hits = hits[:args.limit]

    if not hits:
        print("[i] no correlations found (target too clean? run 'arl-lite run' first)")
        return 0

    print()
    use_color = _use_color()
    for h in hits:
        line = f"  [{h.risk}] {h.rule_name}: {h.headline[:80]}"
        if use_color:
            color = "\033[31m" if h.risk >= 8 else ("\033[33m" if h.risk >= 5 else "\033[36m")
            print(f"{color}{line}\033[0m")
        else:
            print(line)
    return 0


def cmd_monitor_add(args) -> int:
    from .core.monitor import Monitor
    # 边界校验
    if not args.target or not args.target.strip():
        print("[!] target must not be empty", file=sys.stderr)
        return 2
    if args.interval is not None and args.interval <= 0:
        print(f"[!] --interval must be > 0 (got {args.interval})", file=sys.stderr)
        return 2
    storage = Storage(workspace=args.workspace)
    m = Monitor(storage)
    try:
        mid = m.add(args.target, args.type, args.interval)
    except ValueError as e:
        print(f"[!] {e}", file=sys.stderr)
        return 1
    print(f"[+] monitor #{mid} added: {args.target} (type={args.type}, interval={args.interval}s)")
    return 0


def cmd_monitor_list(args) -> int:
    from .core.monitor import Monitor
    storage = Storage(workspace=args.workspace)
    monitors = Monitor(storage).list()
    if not monitors:
        print("[i] no monitors. use 'arl-lite monitor add <target>' to add one")
        return 0
    print(f"[i] {len(monitors)} monitor(s):")
    for m in monitors:
        status = "✓" if m.get("enabled") else "✗"
        print(f"  [{status}] #{m['id']} {m['target']:30} type={m['monitor_type']:10} interval={m['interval_seconds']}s last_run={m.get('last_run_at') or 'never'}")
    return 0


def cmd_monitor_remove(args) -> int:
    from .core.monitor import Monitor
    storage = Storage(workspace=args.workspace)
    m = Monitor(storage)
    arg = str(args.id_or_target).strip()
    # 数字 → 按 id 删
    if arg.isdigit():
        mid = int(arg)
        if m.remove(mid):
            print(f"[+] monitor #{mid} removed")
            return 0
        print(f"[!] monitor #{mid} not found", file=sys.stderr)
        return 1
    # 字符串 → 按 target 删(全部匹配)
    n = m.remove_by_target(arg)
    if n > 0:
        print(f"[+] {n} monitor(s) for {arg!r} removed")
        return 0
    print(f"[!] no monitor for target {arg!r}", file=sys.stderr)
    return 1


def cmd_monitor_enable(args) -> int:
    from .core.monitor import Monitor
    storage = Storage(workspace=args.workspace)
    enabled = not args.disable
    ok = Monitor(storage).enable(args.id, enabled)
    if ok:
        print(f"[+] monitor #{args.id} {'enabled' if enabled else 'disabled'}")
        return 0
    print(f"[!] monitor #{args.id} not found", file=sys.stderr)
    return 2


def cmd_monitor_changes(args) -> int:
    from .core.monitor import list_changes
    if args.limit is not None and args.limit <= 0:
        print(f"[!] --limit must be > 0 (got {args.limit})", file=sys.stderr)
        return 2
    storage = Storage(workspace=args.workspace)
    rows = list_changes(storage, asset_type=args.type, change_type=args.change_type, limit=args.limit)
    if not rows:
        print("[i] no changes")
        return 0
    print(f"[i] {len(rows)} change(s):")
    for r in rows:
        print(f"  [{r['change_type']:18}] {r['asset_type']:10} {r['asset_hash'][:16]} {r.get('detected_at', '')}")
    return 0


def cmd_tui(args) -> int:
    from .tui.app import run_tui
    run_tui(workspace=args.workspace)
    return 0


def cmd_risk_summary(args) -> int:
    from .core.risk_score import risk_summary
    storage = Storage(workspace=args.workspace)
    s = risk_summary(storage)
    print(f"[+] workspace '{args.workspace}' 风险概览")
    print(f"  total correlations: {s['total_correlations']}")
    print(f"  unique targets:     {s['unique_targets']}")
    print(f"  max risk:           {s['max_risk']}")
    print()
    print("  by level:")
    use_color = _use_color()
    for level, n in s["by_level"].items():
        if n > 0:
            line = f"    {level:10}{n}"
            if use_color:
                color = {
                    "critical": "\033[31m", "high": "\033[33m",
                    "medium": "\033[36m", "low": "\033[37m"
                }.get(level, "")
                line = f"    {color}{level:10}{n}\033[0m"
            print(line)
    return 0


def cmd_risk_top(args) -> int:
    from .core.risk_score import compute_asset_risks
    limit = args.limit_short if args.limit_short is not None else args.limit
    if limit is not None and limit <= 0:
        print(f"[!] -n/--limit must be > 0 (got {limit})", file=sys.stderr)
        return 2
    if _ensure_workspace_exists(args.workspace):
        return 1
    storage = Storage(workspace=args.workspace)
    risks = compute_asset_risks(storage)[:limit]
    if not risks:
        print("[i] no risks (run 'arl-lite run' + 'arl-lite correlate' first)")
        return 0
    print(f"[+] top {len(risks)} high-risk assets:")
    use_color = _use_color()
    for r in risks:
        line = f"  [{r.risk_score:2}/{r.risk_level:8}] {r.target:30} (rules={r.rule_count}, type={r.target_type})"
        if use_color:
            color = {
                "critical": "\033[31m", "high": "\033[33m",
                "medium": "\033[36m", "low": "\033[37m"
            }.get(r.risk_level, "")
            print(f"{color}{line}\033[0m")
        else:
            print(line)
    return 0


def cmd_tools_list(args) -> int:
    """列出所有已注册的 recon module"""
    from .modules.registry import discover_modules
    registry = discover_modules()
    by_category: dict[str, list] = {}
    for name, cls in registry.items():
        cat = getattr(cls, "category", "uncategorized")
        by_category.setdefault(cat, []).append((name, cls))
    print(f"[i] {len(registry)} modules available:")
    for cat in sorted(by_category):
        print(f"  [{cat}]")
        for name, cls in sorted(by_category[cat]):
            tools = ",".join(getattr(cls, "required_tools", []) or []) or "-"
            ver = getattr(cls, "version", "?")
            desc = (getattr(cls, "description", "") or "")[:50]
            print(f"    - {name:12} v{ver}  tools=[{tools}]  {desc}")
    return 0


def cmd_notify_test(args) -> int:
    """发测试通知"""
    from .notify import WebhookConfig, notify

    provider = args.provider
    if provider == "local" or (not args.url and provider != "local"):
        # 默认 local,如果没 url
        if not args.url and provider != "local":
            provider = "local"

    try:
        config = WebhookConfig(
            url=args.url or "",
            provider=provider,
            min_severity=args.min_severity,
            timeout=args.timeout,
        )
    except ValueError as e:
        print(f"[!] config error: {e}", file=sys.stderr)
        return 2

    print(f"[i] provider={config.provider} min_severity={config.min_severity}")
    if config.provider != "local":
        print(f"    url: {config.url}")

    ok = notify(
        config,
        title="[ARL] Test notification",
        message="This is a test message from arl-lite.",
        severity="high",
        tags=["test_tube"],
    )
    if ok:
        print("[+] sent OK")
        return 0
    print("[!] send failed (network / provider error)")
    return 1


def cmd_watch_add(args) -> int:
    """添加 watch target"""

    # 空目标不校验的话,坏 entry 会让之后的 watch start 永久瘫痪
    if not args.target or not args.target.strip():
        print("[!] watch target must not be empty", file=sys.stderr)
        return 2
    if len(args.target) > 1000:
        print(f"[!] watch target too long: {len(args.target)} > 1000", file=sys.stderr)
        return 2

    storage, state_file = _watch_state(args)
    if args.interval < 60:
        print("[!] interval must be >= 60 seconds", file=sys.stderr)
        return 2

    targets = []
    if state_file.exists():
        try:
            targets = json.loads(state_file.read_text())
        except Exception as e:
            print(f"[!] invalid watch configuration: {e}", file=sys.stderr)
            return 2

    modules = None
    if args.modules:
        modules = [m.strip() for m in args.modules.split(",") if m.strip()]
        if not modules or any(m not in discover_modules() for m in modules):
            print("[!] invalid watch modules", file=sys.stderr)
            return 2

    entry = {
        "target": args.target,
        "modules": modules or ["dns", "whois", "subfinder", "crtsh"],
        "interval_seconds": args.interval,
    }
    targets = [t for t in targets if t["target"] != args.target]
    targets.append(entry)
    _save_config(state_file, targets)
    print(f"[+] watch: added {args.target} (interval={args.interval}s)")
    print(f"    state: {state_file}")
    return 0


def cmd_watch_remove(args) -> int:
    """移除 watch target"""
    _, state_file = _watch_state(args)
    if not state_file.exists():
        print("[!] no watch state")
        return 1
    targets = json.loads(state_file.read_text())
    before = len(targets)
    targets = [t for t in targets if t["target"] != args.target]
    _save_config(state_file, targets)
    if len(targets) < before:
        print(f"[+] removed {args.target}")
        return 0
    print(f"[!] {args.target} not in watch list")
    return 1


def cmd_watch_list(args) -> int:
    """列出 watch targets"""
    _, state_file = _watch_state(args)
    if not state_file.exists():
        print("[i] no watch targets (use `arl-lite watch add` first)")
        return 0
    targets = json.loads(state_file.read_text())
    if not targets:
        print("[i] watch list empty")
        return 0
    print(f"[i] {len(targets)} watch targets:")
    for t in targets:
        modules = ",".join(t.get("modules", []) or []) or "(default)"
        interval = t.get("interval_seconds", 86400)
        print(f"  - {t['target']:30} modules={modules} interval={interval}s")
    return 0


def cmd_watch_start(args) -> int:
    """启动 watch 调度器(同步跑,Ctrl+C 退出)"""
    from .core.watcher import Watcher

    storage, state_file = _watch_state(args)
    if not state_file.exists():
        print("[!] no watch state")
        return 1
    targets_data = json.loads(state_file.read_text())
    if not targets_data:
        print("[!] no watch targets")
        return 1

    w = Watcher(storage, webhook_config=_load_webhook(storage))
    skipped = 0
    for t in targets_data:
        # 历史坏 entry(如空 target)跳过并告警,不中断整个 watch
        target = t.get("target") if isinstance(t, dict) else None
        if not target or not str(target).strip():
            log.warning(f"watch: skipping invalid state entry: {t!r}")
            skipped += 1
            continue
        try:
            w.add(target, modules=t.get("modules"), interval_seconds=t.get("interval_seconds", 86400))
        except (ValueError, TypeError) as e:
            log.warning(f"watch: skipping invalid entry {target!r}: {e}")
            skipped += 1
    if skipped:
        print(f"[!] skipped {skipped} invalid watch entry(ies) — fix with 'arl-lite watch remove <target>'", file=sys.stderr)
    if not w.list():
        print("[!] no valid watch targets", file=sys.stderr)
        return 1

    print(f"[+] watch starting with {len(w.list())} targets (Ctrl+C to stop)")
    w.start()
    try:
        # 主线程等 stop
        import threading
        stop_event = threading.Event()
        try:
            from .core.signal_handler import GracefulShutdown
            gs = GracefulShutdown(w)
            gs.install()
        except Exception:
            pass
        while w.is_running():
            stop_event.wait(timeout=1.0)
    except KeyboardInterrupt:
        print("\n[!] Ctrl+C, stopping")
    finally:
        w.stop(timeout=5.0)
        print("[+] watch stopped")
    return 0


def cmd_watch_stop(args) -> int:
    """watch stop(同 start 一样立刻返回,因为是同步)"""
    print("[i] watch 是同步模式,直接 Ctrl+C 退出 start 即可")
    return 0


def _save_config(path: Path, value) -> None:
    """Replace a complete config file instead of exposing a partial write."""
    import os
    import tempfile
    fd, name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _watch_state(args):
    storage = Storage(workspace=getattr(args, "workspace", "default"))
    path = storage.workspace_dir / "watch.json"
    # The historical global list belongs only to default. Do not copy it
    # into every named workspace, or overwrite the historical file.
    legacy = Path.home() / ".arl-lite" / "watch" / "watch.json"
    if storage.workspace == "default" and not path.exists() and legacy.exists():
        _save_config(path, json.loads(legacy.read_text(encoding="utf-8")))
    return storage, path


def _load_webhook(storage):
    from .notify import WebhookConfig
    path = storage.workspace_dir / "notify.json"
    if not path.exists():
        return None
    return WebhookConfig(**json.loads(path.read_text(encoding="utf-8")))


def cmd_notify_set(args) -> int:
    """Persist configuration for future watch starts; never send a message."""
    from dataclasses import asdict
    from .notify import WebhookConfig
    try:
        config = WebhookConfig(url=args.url or "", provider=args.provider,
                               min_severity=args.min_severity, timeout=args.timeout)
    except ValueError as exc:
        print(f"[!] config error: {exc}", file=sys.stderr)
        return 2
    storage = Storage(workspace=args.workspace)
    _save_config(storage.workspace_dir / "notify.json", asdict(config))
    print(f"[+] notification configuration saved for {storage.workspace}")
    return 0


def cmd_tools_check(args) -> int:
    """检查外部工具是否安装"""
    from .integrations.subfinder import is_available, get_version
    from .integrations.crtsh import CRTSH_URL

    print("[i] external tools:")
    print(f"    subfinder: {'✓' if is_available() else '✗'} ({get_version()})")
    print(f"    crt.sh: ✓ (HTTP, no install needed, endpoint={CRTSH_URL})")

    mods = discover_modules()
    print()
    print(f"[i] discovered modules ({len(mods)}):")
    for name, cls in mods.items():
        required = ",".join(cls.required_tools or []) or "(none)"
        print(f"    - {name} [{cls.category}] requires: {required}")
    return 0


def cmd_version(args) -> int:
    print(f"arl-lite {__version__}")
    print(f"Python {sys.version.split()[0]}")
    return 0


def cmd_mcp(args) -> int:
    """启动 MCP server(stdio JSON-RPC 2.0)"""
    from .mcp.server import MCPServer
    server = MCPServer(workspace=args.workspace)
    return server.serve_forever()


# ============================================
# 入口
# ============================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="arl-lite",
        description="灯塔 ARL 降级增强版:2G 内存友好的资产侦察工具",
    )
    p.add_argument("--log-level", default="INFO", help="日志级别(默认: INFO)")
    # 注:--workspace 不放全局,放每个子命令里,避免 argparse 冲突
    # 习惯上:`arl-lite run -t xxx -w foo` 这种写法要支持

    sub = p.add_subparsers(dest="command", required=True)

    # run
    pr = sub.add_parser("run", help="跑一个扫描任务")
    pr.add_argument("-t", "--target", required=True, help="目标(域名/IP/URL)")
    pr.add_argument("-m", "--modules", help="模块列表(逗号分隔,默认: subfinder,crtsh)")
    pr.add_argument("-p", "--preset", help="preset 名(Phase 2 实现)")
    pr.add_argument("-w", "--workspace", help="工作空间名(可放在 run 后面,等同于全局 --workspace)", default="default")
    pr.set_defaults(func=cmd_run)

    # query
    pq = sub.add_parser("query", help="查询资产")
    pq.add_argument("table", choices=["domains", "hosts", "ports", "sites", "findings",
                                        "tasks", "source_status", "correlations", "asset_changes"])
    pq.add_argument("-f", "--filter", help="SQL WHERE 子句(不含 WHERE 关键字)")
    pq.add_argument("-l", "--limit", type=int, default=50)
    pq.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pq.add_argument("--format", choices=["table", "json"], default="table")
    pq.set_defaults(func=cmd_query)

    # search
    ps = sub.add_parser("search", help="FTS5 全文搜索")
    ps.add_argument("table", choices=["sites", "domains", "findings"])
    ps.add_argument("keyword", help="搜索关键词")
    ps.add_argument("-l", "--limit", type=int, default=50)
    ps.add_argument("-w", "--workspace", help="工作空间名", default="default")
    ps.add_argument("--format", choices=["table", "json"], default="table")
    ps.set_defaults(func=cmd_search)

    # export
    pe = sub.add_parser("export", help="导出所有数据(json/csv/tsv/markdown/table/html)")
    pe.add_argument("--format", choices=["json", "csv", "tsv", "markdown", "table", "html"], default="json")
    pe.add_argument("-o", "--output", help="输出文件(不指定时 html 写入 CWD,其余打到 stdout)")
    pe.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pe.set_defaults(func=cmd_export)

    # workspace
    pw = sub.add_parser("workspace", help="工作空间管理")
    pw_sub = pw.add_subparsers(dest="workspace_cmd", required=True)
    pwl = pw_sub.add_parser("list", help="列出所有 workspace")
    pwl.add_argument("-w", "--workspace", help="(忽略)当前 workspace 名", default="default")
    pwl.set_defaults(func=cmd_workspace_list)

    pwc = pw_sub.add_parser("create", help="创建 workspace")
    pwc.add_argument("name", help="workspace 名")
    pwc.add_argument("-d", "--description", default="")
    pwc.add_argument("--ticket", help="授权凭证号")
    pwc.add_argument("--valid-from", help="授权开始时间(ISO)")
    pwc.add_argument("--valid-until", help="授权结束时间(ISO)")
    pwc.set_defaults(func=cmd_workspace_create)

    pwd = pw_sub.add_parser("delete", help="删除 workspace")
    pwd.add_argument("name", help="workspace 名")
    pwd.add_argument("-y", "--yes", action="store_true", help="跳过确认")
    pwd.set_defaults(func=cmd_workspace_delete)

    # stats
    pst = sub.add_parser("stats", help="资产统计")
    pst.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pst.set_defaults(func=cmd_stats)

    # diff
    pd = sub.add_parser("diff", help="看新增资产(真 diff,基于 first_seen)")
    pd.add_argument("--since", default="7d", help="时间窗口,如 7d / 24h / 2026-09-01")
    pd.add_argument("-t", "--table", choices=["domains", "hosts", "ports", "sites", "findings"])
    pd.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pd.set_defaults(func=cmd_diff)

    # correlate(关联分析)
    pc = sub.add_parser("correlate", help="跑关联分析(37 条规则)")
    pc.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pc.add_argument("-l", "--limit", type=int, default=50, help="最多显示多少条(>0)")
    pc.add_argument("--min-risk", type=int, default=0, help="最小风险等级(0-10)")
    pc.set_defaults(func=cmd_correlate)

    # monitor(资产监控)
    pm = sub.add_parser("monitor", help="资产监控管理")
    pm_sub = pm.add_subparsers(dest="monitor_cmd", required=True)

    pma = pm_sub.add_parser("add", help="添加监控")
    pma.add_argument("target", help="目标域名/IP")
    pma.add_argument("-t", "--type", default="full", choices=["full", "subdomain", "port", "site"])
    pma.add_argument("-i", "--interval", type=int, default=86400, help="间隔秒数(默认 24h)")
    pma.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pma.set_defaults(func=cmd_monitor_add)

    pml = pm_sub.add_parser("list", help="列出监控")
    pml.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pml.set_defaults(func=cmd_monitor_list)

    pmr = pm_sub.add_parser("remove", help="删除监控")
    pmr.add_argument("id_or_target", help="监控 ID(数字)或 target 域名")
    pmr.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pmr.set_defaults(func=cmd_monitor_remove)

    pme = pm_sub.add_parser("enable", help="启用/禁用监控")
    pme.add_argument("id", type=int, help="监控 ID")
    pme.add_argument("--disable", action="store_true", help="禁用(默认启用)")
    pme.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pme.set_defaults(func=cmd_monitor_enable)

    pmc = pm_sub.add_parser("changes", help="看变更事件")
    pmc.add_argument("-t", "--type", choices=["domain", "host", "port", "site", "finding"],
                    help="资产类型")
    pmc.add_argument("-c", "--change-type", choices=["NEW_ASSET", "DISAPPEARED", "TITLE_CHANGED",
                                                     "TECH_CHANGED", "FINGERPRINT_CHANGED", "STATUS_CHANGED"],
                    help="变更类型")
    pmc.add_argument("-l", "--limit", type=int, default=50, help="最多显示多少条")
    pmc.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pmc.set_defaults(func=cmd_monitor_changes)

    # tui(交互式终端)
    pt = sub.add_parser("tui", help="启动交互式 TUI 终端")
    pt.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pt.set_defaults(func=cmd_tui)

    # risk(风险画像)
    prk = sub.add_parser("risk", help="风险画像(基于关联分析)")
    prk_sub = prk.add_subparsers(dest="risk_cmd", required=True)

    prks = prk_sub.add_parser("summary", help="workspace 风险概览")
    prks.add_argument("-w", "--workspace", help="工作空间名", default="default")
    prks.set_defaults(func=cmd_risk_summary)

    prkt = prk_sub.add_parser("top", help="top N 高风险资产")
    prkt.add_argument("-n", "--limit", type=int, default=10, help="最多显示 N 条")
    prkt.add_argument("-l", "--limit-short", type=int, default=None, help=argparse.SUPPRESS)  # 别名兼容
    prkt.add_argument("-w", "--workspace", help="工作空间名", default="default")
    prkt.set_defaults(func=cmd_risk_top)

    # ai(AI 集成:5 边界点 + 配置)
    from .ai.commands import (
        cmd_ai_ask, cmd_ai_config_get, cmd_ai_config_list, cmd_ai_config_reset,
        cmd_ai_config_set, cmd_ai_config_test, cmd_ai_explain, cmd_ai_fix,
        cmd_ai_report, cmd_ai_suggest,
    )
    pa = sub.add_parser("ai", help="AI 集成(自然语言/报告/解释/建议/修复)")
    pa_sub = pa.add_subparsers(dest="ai_cmd", required=True)

    # ai ask
    paa = pa_sub.add_parser("ask", help="自然语言查询资产/风险")
    paa.add_argument("question", help="要问的问题(中文)")
    paa.add_argument("-w", "--workspace", help="工作空间名", default="default")
    paa.add_argument("--provider", help="强制 provider (openai/anthropic/google/ollama)")
    paa.set_defaults(func=cmd_ai_ask)

    # ai report
    par = pa_sub.add_parser("report", help="生成 workspace 报告")
    par.add_argument("-w", "--workspace", help="工作空间名", default="default")
    par.add_argument("--provider", help="强制 provider")
    par.set_defaults(func=cmd_ai_report)

    # ai explain
    pae = pa_sub.add_parser("explain", help="解释一条关联分析")
    pae.add_argument("corr_id", help="关联 ID(数字)")
    pae.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pae.add_argument("--provider", help="强制 provider")
    pae.set_defaults(func=cmd_ai_explain)

    # ai suggest
    pasg = pa_sub.add_parser("suggest", help="基于当前数据,建议下一步扫描")
    pasg.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pasg.add_argument("--provider", help="强制 provider")
    pasg.set_defaults(func=cmd_ai_suggest)

    # ai fix
    paf = pa_sub.add_parser("fix", help="给一条 finding 修复建议")
    paf.add_argument("finding_id", help="finding ID(数字)")
    paf.add_argument("-w", "--workspace", help="工作空间名", default="default")
    paf.add_argument("--provider", help="强制 provider")
    paf.set_defaults(func=cmd_ai_fix)

    # ai config
    pac = pa_sub.add_parser("config", help="AI 配置管理")
    pac_sub = pac.add_subparsers(dest="ai_config_cmd", required=True)

    pacs = pac_sub.add_parser("set", help="设置 provider 配置")
    pacs.add_argument("provider", help="provider 名 (openai/anthropic/google/ollama)")
    pacs.add_argument("--api-key", help="API key")
    pacs.add_argument("--base-url", help="API base URL")
    pacs.add_argument("--model", help="模型名")
    pacs.add_argument("--temperature", type=float, help="temperature (0-2)")
    pacs.add_argument("--max-tokens", type=int, help="max tokens")
    pacs.set_defaults(func=cmd_ai_config_set)

    pacg = pac_sub.add_parser("get", help="查看 provider 配置(api key 掩码)")
    pacg.add_argument("provider", nargs="?", help="provider 名(留空看全部)")
    pacg.set_defaults(func=cmd_ai_config_get)

    pacl = pac_sub.add_parser("list", help="列出所有 provider + 当前活动")
    pacl.set_defaults(func=cmd_ai_config_list)

    pacr = pac_sub.add_parser("reset", help="重置 provider 配置")
    pacr.add_argument("provider", nargs="?", help="provider 名(留空重置全部)")
    pacr.set_defaults(func=cmd_ai_config_reset)

    pact = pac_sub.add_parser("test", help="测试当前 provider 是否可用")
    pact.add_argument("--provider", help="强制 provider")
    pact.set_defaults(func=cmd_ai_config_test)

    # tools
    ptk = sub.add_parser("tools", help="工具管理")
    ptk_sub = ptk.add_subparsers(dest="tools_cmd", required=True)
    ptkc = ptk_sub.add_parser("check", help="检查工具可用性")
    ptkc.set_defaults(func=cmd_tools_check)
    ptkl = ptk_sub.add_parser("list", help="列出所有可用 module")
    ptkl.set_defaults(func=cmd_tools_list)

    # notify (v0.7)
    pnf = sub.add_parser("notify", help="Webhook 通知测试 / 配置")
    pnf_sub = pnf.add_subparsers(dest="notify_cmd", required=True)
    pnft = pnf_sub.add_parser("test", help="发测试通知")
    pnft.add_argument("--url", help="webhook URL")
    pnft.add_argument("--provider", default="generic", choices=["generic", "ntfy", "slack", "local"])
    pnft.add_argument("--min-severity", default="info", choices=["info", "low", "medium", "high", "critical"])
    pnft.add_argument("--timeout", type=int, default=10)
    pnft.set_defaults(func=cmd_notify_test)
    pnfs = pnf_sub.add_parser("set", help="保存当前 workspace 的 watch 通知配置（不发送）")
    pnfs.add_argument("-w", "--workspace", default="default")
    pnfs.add_argument("--url")
    pnfs.add_argument("--provider", default="generic", choices=["generic", "ntfy", "slack", "local"])
    pnfs.add_argument("--min-severity", default="high", choices=["info", "low", "medium", "high", "critical"])
    pnfs.add_argument("--timeout", type=int, default=10)
    pnfs.set_defaults(func=cmd_notify_set)

    # watch (v0.7)
    pwa = sub.add_parser("watch", help="持续监控 / Watch 模式")
    pwa_sub = pwa.add_subparsers(dest="watch_cmd", required=True)
    pwaa = pwa_sub.add_parser("add", help="添加 watch target")
    pwaa.add_argument("target", help="目标域名/IP")
    pwaa.add_argument("-w", "--workspace", default="default")
    pwaa.add_argument("-m", "--modules", help="逗号分隔 module 列表")
    pwaa.add_argument("--interval", type=int, default=86400, help="重跑间隔秒(默认 86400=24h)")
    pwaa.set_defaults(func=cmd_watch_add)
    pwar = pwa_sub.add_parser("remove", help="移除 watch target")
    pwar.add_argument("target", help="目标")
    pwar.add_argument("-w", "--workspace", default="default")
    pwar.set_defaults(func=cmd_watch_remove)
    pwal = pwa_sub.add_parser("list", help="列出 watch targets")
    pwal.add_argument("-w", "--workspace", default="default")
    pwal.set_defaults(func=cmd_watch_list)
    pwas = pwa_sub.add_parser("start", help="启动 watch 调度器(前台运行,Ctrl+C 停止)")
    pwas.add_argument("-w", "--workspace", default="default")
    pwas.set_defaults(func=cmd_watch_start)
    pwap = pwa_sub.add_parser("stop", help="停止 watch 调度器")
    pwap.set_defaults(func=cmd_watch_stop)

    # version
    pv = sub.add_parser("version", help="版本")
    pv.set_defaults(func=cmd_version)

    # mcp(启动 MCP server)
    pm = sub.add_parser("mcp", help="启动 MCP server(stdio JSON-RPC 2.0)")
    pm.add_argument("-w", "--workspace", help="工作空间名", default="default")
    pm.set_defaults(func=cmd_mcp)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # 日志级别
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130  # 标准的 SIGINT exit code
    except ValueError as e:
        # 用户输入错误(白名单/SQL 注入等)— 干净报错
        print(f"[!] error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # 未预期错误 — log + 非零退出
        log = logging.getLogger("arl_lite.cli")
        log.exception(f"unexpected error: {e}")
        print(f"[!] unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
