"""arl_lite.core.correlation_engine

关联分析执行器:跑 YAML 规则对资产做高危组合检测。

设计:
- 规则格式参考 modules/analysis/rules/ 下的 37 条现成规则
- 不用 PyYAML,自己解析(4 个核心字段够用)
- 3 个动作:collect / cross_ref / exclusion
- collect 命中 → cross_ref 必须存在 → exclusion 必须不存在 → headline 输出

纪律:
- SQL 注入防护:所有 SQL 通过 storage.query() 的白名单
- 规则失败不 crash,记录 skipped 原因
- 输出写入 correlations 表(已有 schema)
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

log = logging.getLogger("arl_lite.core.correlation_engine")


# =========================
# 数据结构
# =========================

@dataclass
class RuleAction:
    """规则中的一条 SQL 片段"""
    table: str           # 目标表
    where: str           # WHERE 子句(不含 WHERE 关键字)
    description: str = ""


@dataclass
class Rule:
    """一条关联分析规则"""
    name: str
    description: str
    risk: int  # 0-10
    tags: list[str] = field(default_factory=list)
    collect: list[RuleAction] = field(default_factory=list)
    cross_ref: list[RuleAction] = field(default_factory=list)
    exclusion: list[RuleAction] = field(default_factory=list)
    headline: str = ""
    advice: str = ""
    # 聚合型规则:collect 命中总数 >= count_min 时,整个 workspace 报一条
    # (而不是每个目标各报一条)。None = 普通逐目标规则
    count_min: int | None = None


@dataclass
class CorrelationHit:
    """规则一次命中"""
    rule_name: str
    risk: int
    target: dict  # 命中目标的字段(用于 headline 格式化)
    headline: str  # 格式化后的输出
    advice: str = ""
    tags: list[str] = field(default_factory=list)
    description: str = ""  # 规则描述(save_correlations 用,免去重复加载规则)
    matched_count: int = 1  # 该 hit 覆盖的资产数(聚合规则 = 全部命中数)
    evidence_preview: str | None = None  # 聚合规则的证据摘要 JSON(可选)


# =========================
# 极简 YAML 解析(只支持本规则格式)
# =========================

# 缩进深度
LIST_KEYS = {"collect", "cross_ref", "exclusion", "tags"}
SCALAR_KEYS = {"name", "description", "risk", "headline", "advice", "count_min"}


def _unquote(s: str) -> str:
    """去掉字符串两端的引号(单/双)"""
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _parse_flow_list(value: str) -> list[str]:
    """解析 YAML 行内列表 '[a, b, c]' → ['a', 'b', 'c'](不支持嵌套)"""
    inner = value[1:-1].strip()
    if not inner:
        return []
    return [_unquote(x) for x in inner.split(",") if _unquote(x)]


def _parse_yaml(text: str) -> Rule:
    lines = text.split("\n")
    rule = Rule(name="", description="", risk=0)
    current_list: list | None = None
    current_list_key: str | None = None  # current_list 属于哪个字段(tags 需特殊处理)
    current_action: dict | None = None
    pending_key: str | None = None  # 收集多行 scalar
    pending_value: list[str] = []

    def flush_scalar():
        nonlocal pending_key, pending_value
        if pending_key is not None:
            v = "\n".join(pending_value).rstrip()
            if pending_key == "risk":
                # 风险值兜底:失败用 0 + 警告(不让 parse 抛)
                try:
                    parsed = int(v.strip())
                except (ValueError, TypeError):
                    log.warning(f"rule risk value {v!r} not int, default 0")
                    parsed = 0
                # 截到合法范围 0-10
                rule.risk = max(0, min(10, parsed))
            elif pending_key == "name":
                rule.name = v.strip()
            elif pending_key == "description":
                rule.description = v.strip()
            elif pending_key == "headline":
                rule.headline = v.strip()
            elif pending_key == "advice":
                rule.advice = v
            pending_key = None
            pending_value = []

    def flush_action():
        nonlocal current_action
        if current_action is not None and current_list is not None:
            if "table" in current_action and "where" in current_action:
                current_list.append(RuleAction(**current_action))
            else:
                # 缺 table/where 的项直接丢会静默损规则,必须留痕
                log.warning(f"rule '{rule.name}' list item missing table/where, skipped: {current_action}")
            current_action = None

    i = 0
    while i < len(lines):
        line = lines[i]
        # 跳过空行和注释
        if not line.strip() or line.strip().startswith("#"):
            i += 1
            continue
        # 计算缩进
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        if indent == 0 and ":" in stripped:
            # 顶层 key
            flush_scalar()
            flush_action()
            current_list = None
            current_list_key = None
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if key in SCALAR_KEYS:
                if value and value not in ("|", ">"):
                    # 单行值(去引号)
                    unquoted = _unquote(value)
                    if key == "risk":
                        # 风险值兜底
                        try:
                            parsed = int(unquoted)
                        except (ValueError, TypeError):
                            log.warning(f"rule risk value {unquoted!r} not int, default 0")
                            parsed = 0
                        rule.risk = max(0, min(10, parsed))
                    elif key == "count_min":
                        try:
                            rule.count_min = int(unquoted)
                        except (ValueError, TypeError):
                            log.warning(f"rule count_min value {unquoted!r} not int, ignored")
                    else:
                        setattr(rule, key, unquoted)
                else:
                    # 多行 scalar(literal | 或 folded >)
                    pending_key = key
                    pending_value = []
            elif key in LIST_KEYS:
                if value.startswith("[") and value.endswith("]"):
                    # 行内列表(现有 37 条规则的 tags 全是这个形式)
                    if key == "tags":
                        rule.tags.extend(_parse_flow_list(value))
                    else:
                        log.warning(f"flow-style list not supported for '{key}', ignored")
                else:
                    current_list = getattr(rule, key)
                    current_list_key = key
            else:
                log.warning(f"unknown top-level key: {key}")
                pending_key = None
                pending_value = []
        elif pending_key is not None and indent >= 2:
            # 收集多行 scalar 的内容
            pending_value.append(line.lstrip())
        elif indent >= 2 and current_list is not None and stripped.startswith("- "):
            # 列表项
            flush_action()
            item = stripped[2:].strip()
            if current_list_key == "tags":
                # tags 是标量列表,不是 RuleAction 列表
                rule.tags.append(_unquote(item))
            else:
                current_action = {}
                if ":" in item:
                    k, _, v = item.partition(":")
                    current_action[k.strip()] = _unquote(v.strip())
        elif indent >= 4 and current_action is not None and ":" in stripped:
            # 列表项的子字段
            k, _, v = stripped.partition(":")
            current_action[k.strip()] = _unquote(v.strip())
        i += 1
    flush_scalar()
    flush_action()
    return rule


def load_rule(path: Path) -> Rule:
    """从 .yml 文件加载单条规则

    utf-8-sig 兼容 Windows 编辑器留下的 BOM(BOM 会让首行 key 变 '\\ufeffname',
    规则静默死亡)。解析后强校验 name/collect:规则文件写错必须显式报错,
    静默 0 命中对检测工具是最危险的失败模式。
    """
    text = path.read_text(encoding="utf-8-sig")
    rule = _parse_yaml(text)
    if not rule.name:
        raise ValueError(f"rule {path.name}: missing 'name'")
    if not rule.collect:
        raise ValueError(f"rule {path.name}: missing/empty 'collect' (bad indent? tabs? '-table:' without space?)")
    return rule


def load_all_rules(rules_dir: str | Path) -> list[Rule]:
    """加载目录下所有 .yml 规则"""
    p = Path(rules_dir)
    if not p.exists():
        log.warning(f"rules dir not found: {p}")
        return []
    rules = []
    for f in sorted(p.glob("*.yml")):
        try:
            rules.append(load_rule(f))
        except Exception as e:
            log.error(f"failed to load rule {f.name}: {e}")
    log.info(f"loaded {len(rules)} correlation rules from {p}")
    return rules


# =========================
# 执行器
# =========================

ALLOWED_TABLES = {"domains", "hosts", "ports", "sites", "findings"}

# 规则 where 片段的执行预算。check_filter_sql 只拦写操作,拦不住
# `WITH RECURSIVE` 无限递归这类只读查询——那条 SQL 会在 C 层死循环,
# 连 SIGALRM 都打不断,进程只能 SIGKILL。连接本身有常驻 120s 兜底预算,
# 这里把规则 SQL 收紧到 5s。
_RULE_SQL_BUDGET_SECONDS = 5.0


def _guarded_query(storage, sql: str, params: list, budget: float = _RULE_SQL_BUDGET_SECONDS) -> list:
    """在 storage 的当前连接上执行带预算的查询

    预算作用在 storage 的线程本地 deadline 上(连接的常驻 progress handler
    读它),用完恢复原值——不能 set_progress_handler(None) 一清了之,
    那会把连接的兜底预算一起拆掉。
    """
    if budget <= 0:
        raise ValueError("query budget must be positive")
    # _conn refreshes the connection's default deadline on entry. Apply the
    # narrower rule deadline afterwards, and restore it before commit/rollback.
    with storage._conn() as conn:
        prev = storage._local.deadline
        storage._local.deadline = min(prev, time.monotonic() + budget)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            storage._local.deadline = prev


def _exec_action(action: RuleAction, storage) -> list[dict]:
    """执行一条 SQL 片段(只读,带白名单 + 执行预算)"""
    if action.table not in ALLOWED_TABLES:
        log.warning(f"rule action table '{action.table}' not in whitelist")
        return []
    ws = storage.workspace_id
    sql = f"SELECT * FROM {action.table} WHERE workspace_id = ?"
    params: list = [ws]
    if action.where and action.where.strip():
        try:
            from ..db.storage import check_filter_sql
            check_filter_sql(action.where)
        except ValueError as e:
            log.warning(f"rule {action.table} where clause rejected: {e}")
            return []
        sql += f" AND ({action.where})"
    sql += " ORDER BY id DESC LIMIT 1000"
    try:
        rows = _guarded_query(storage, sql, params)
        return [dict(r) for r in rows]
    except Exception as e:
        log.warning(f"rule action exec failed ({action.table}): {e}")
        return []


def _cross_ref_match(action: RuleAction, target: dict, storage) -> bool:
    """交叉引用:对于 target,执行 action 查 SQL,如果有任何命中返回 True

    SQL 中的 ports.ip / sites.ip 等会自动替换成 target 的实际值
    """
    if action.table not in ALLOWED_TABLES:
        return False
    ws = storage.workspace_id
    sql = f"SELECT 1 FROM {action.table} WHERE workspace_id = ?"
    params: list = [ws]
    if action.where and action.where.strip():
        # 占位符替换:把 SQL 中的 `ports.ip` 替换为实际 IP。
        # 用 lambda 返回替换串,避免值里的反斜杠被当成 re 模板转义
        # (re.PatternError 会让整条规则静默 0 命中);re.sub 本身也可能被
        # 畸形值炸掉,一并纳入 try。
        where = action.where
        try:
            for key, val in target.items():
                val_str = str(val).replace("'", "''")
                where = re.sub(
                    rf"\b\w+\.{re.escape(key)}\b",
                    lambda m, v=val_str: f"'{v}'",
                    where,
                )
        except Exception as e:
            log.warning(f"cross_ref placeholder substitution failed: {e}")
            return False
        try:
            from ..db.storage import check_filter_sql
            check_filter_sql(where)
        except ValueError:
            return False
        sql += f" AND ({where})"
    sql += " LIMIT 1"
    try:
        rows = _guarded_query(storage, sql, params)
        return len(rows) > 0
    except Exception as e:
        log.debug(f"cross_ref failed: {e}")
        return False


def _exclusion_match(action: RuleAction, target: dict, storage) -> bool:
    """排除:和 cross_ref 一样,但返回 True 表示"应该排除" """
    return _cross_ref_match(action, target, storage)


def run_rule(rule: Rule, storage) -> list[CorrelationHit]:
    """跑单条规则,返回命中列表"""
    if not rule.name:
        return []
    hits: list[CorrelationHit] = []

    # 1. 收集所有 collect 命中
    collect_targets: list[dict] = []
    for action in rule.collect:
        collect_targets.extend(_exec_action(action, storage))

    # 去重(按 hash)
    seen_hashes: set[str] = set()
    unique_targets: list[dict] = []
    for t in collect_targets:
        h = t.get("hash") or str(sorted(t.items()))
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_targets.append(t)
    collect_targets = unique_targets

    if not collect_targets:
        return []

    # 1b. 聚合型规则(count_min):workspace 级判断,命中只报一条,
    # 覆盖全部资产。旧的逐目标模式对"总数 ≥ N"这类规则会每个目标
    # 误报一条且完全没有阈值判断。
    if rule.count_min is not None:
        if len(collect_targets) < rule.count_min:
            return []
        sample = collect_targets[:50]
        target = {"aggregate": "workspace", "count": len(collect_targets)}
        try:
            headline = rule.headline.format(count=len(collect_targets))
        except Exception:
            headline = rule.headline
        hits.append(CorrelationHit(
            rule_name=rule.name,
            risk=rule.risk,
            target=target,
            headline=headline,
            advice=rule.advice,
            tags=list(rule.tags),
            description=rule.description,
            matched_count=len(collect_targets),
            evidence_preview=json.dumps(
                [{k: t.get(k) for k in ("id", "domain", "host", "ip", "url") if k in t}
                 for t in sample],
                ensure_ascii=False),
        ))
        return hits

    # 2. 对每个 target,检查 cross_ref 和 exclusion
    for target in collect_targets:
        # cross_ref 必须全部命中
        all_cross_ok = all(
            _cross_ref_match(act, target, storage)
            for act in rule.cross_ref
        )
        if rule.cross_ref and not all_cross_ok:
            continue
        # exclusion 不能有命中
        any_excl = any(
            _exclusion_match(act, target, storage)
            for act in rule.exclusion
        )
        if any_excl:
            continue

        # 格式化 headline
        try:
            headline = rule.headline.format(**{k: v for k, v in target.items() if isinstance(v, (str, int, float))})
        except KeyError:
            headline = rule.headline
        except Exception:
            headline = rule.headline

        hits.append(CorrelationHit(
            rule_name=rule.name,
            risk=rule.risk,
            target=target,
            headline=headline,
            advice=rule.advice,
            tags=list(rule.tags),
            description=rule.description,
        ))

    return hits


def run_all_rules(storage, rules_dir: str | Path | None = None,
                  rules_override: list[Rule] | None = None) -> list[CorrelationHit]:
    """跑所有规则,返回所有命中

    Args:
        storage: Storage 实例
        rules_dir: 规则目录(可省,默认)
        rules_override: 自定义规则列表(测试用,优先级高于目录加载)
    """
    if rules_override is not None:
        rules = rules_override
    else:
        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent / "modules" / "analysis" / "rules"
        rules = load_all_rules(rules_dir)
    log.info(f"running {len(rules)} correlation rules")

    all_hits: list[CorrelationHit] = []
    for rule in rules:
        try:
            hits = run_rule(rule, storage)
            log.info(f"  rule '{rule.name}': {len(hits)} hit(s)")
            all_hits.extend(hits)
        except Exception as e:
            log.error(f"rule '{rule.name}' crashed: {e}")

    log.info(f"total correlations: {len(all_hits)}")
    return all_hits


def save_correlations(storage, hits: list[CorrelationHit]) -> int:
    """把命中写进 correlations 表,返回写入条数

    description 随 hit 携带(旧版每条 hit 重新加载全部 37 个规则文件,
    命中多时纯 IO 比规则执行还慢);失败升为 warning 不静默。
    """
    if not hits:
        return 0
    count = 0
    for hit in hits:
        # target 字段取主键(ip / host / domain),聚合规则固定为 workspace
        if "aggregate" in hit.target:
            target, target_type = f"workspace@{hit.target.get('aggregate')}", "aggregate"
        else:
            target = (hit.target.get("ip")
                      or hit.target.get("host")
                      or hit.target.get("domain")
                      or hit.target.get("target")
                      or hit.target.get("url")
                      or hit.target.get("id")
                      or "unknown")
            target_type = "ip" if "ip" in hit.target else (
                "host" if "host" in hit.target else (
                "domain" if "domain" in hit.target else (
                "site" if "url" in hit.target else "other"
            )))
        evidence = hit.evidence_preview or json.dumps(hit.target, ensure_ascii=False, default=str)
        try:
            with storage._conn() as conn:
                cur = conn.execute(
                    """INSERT INTO correlations
                       (workspace_id, rule_name, rule_description, risk,
                        target, target_type, headline, advice, tags,
                        matched_count, evidence, detected_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(workspace_id, rule_name, target) DO UPDATE SET
                         rule_description = excluded.rule_description,
                         risk = excluded.risk,
                         headline = excluded.headline,
                         advice = excluded.advice,
                         tags = excluded.tags,
                         matched_count = excluded.matched_count,
                         evidence = excluded.evidence,
                         detected_at = excluded.detected_at""",
                    (storage.workspace_id, hit.rule_name, hit.description, hit.risk,
                     str(target), target_type, hit.headline, hit.advice,
                     json.dumps(hit.tags, ensure_ascii=False),
                     hit.matched_count, evidence, datetime.utcnow().isoformat())
                )
                # 新行和被刷新的行 rowcount 都是 1,只有内容完全没变的行才是 0
                count += cur.rowcount
        except Exception as e:
            log.warning(f"save correlation failed ({hit.rule_name}@{target}): {e}")
    return count
