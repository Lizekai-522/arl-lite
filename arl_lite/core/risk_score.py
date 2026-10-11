"""arl_lite.core.risk_score

风险画像:基于 correlations 输出每个 asset 的 risk score。

设计:
- 每个 asset(按 target 聚合)汇总所有命中规则
- risk_score = max(命中规则的 risk) + bonus(命中数量)
- risk_level: low(0-3) / medium(4-6) / high(7-8) / critical(9-10)

输出:
- top_risks(workspace 内 top N 高风险资产)
- risk_summary(workspace 整体风险概览)
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field

log = logging.getLogger("arl_lite.core.risk_score")


@dataclass
class AssetRisk:
    target: str
    target_type: str
    risk_score: int  # 0-10 + bonus
    risk_level: str  # low/medium/high/critical
    rule_count: int
    rule_names: list[str] = field(default_factory=list)
    headlines: list[str] = field(default_factory=list)


def _score_to_level(score: int) -> str:
    if score >= 9:
        return "critical"
    elif score >= 7:
        return "high"
    elif score >= 4:
        return "medium"
    return "low"


def compute_asset_risks(storage) -> list[AssetRisk]:
    """从 correlations 表计算每个 asset 的风险评分"""
    rows = storage.query("correlations", filter_sql="status = 'active'", limit=10000)
    if not rows:
        return []

    # 按 target 聚合
    by_target: dict[str, dict] = defaultdict(lambda: {
        "target_type": "",
        "max_risk": 0,
        "rule_count": 0,
        "rule_names": [],
        "headlines": [],
    })
    for r in rows:
        target = r.get("target", "")
        if not target:
            continue
        entry = by_target[target]
        entry["target_type"] = r.get("target_type", "other")
        risk = r.get("risk", 0) or 0
        if risk > entry["max_risk"]:
            entry["max_risk"] = risk
        entry["rule_count"] += 1
        rname = r.get("rule_name", "")
        if rname and rname not in entry["rule_names"]:
            entry["rule_names"].append(rname)
        headline = r.get("headline", "")
        if headline and len(entry["headlines"]) < 5:
            entry["headlines"].append(headline)

    # 计算最终 score
    results: list[AssetRisk] = []
    for target, entry in by_target.items():
        # score = max risk + bonus for multiple rules
        bonus = min(2, (entry["rule_count"] - 1))  # 多规则加 1-2 分
        score = min(10, entry["max_risk"] + bonus)
        results.append(AssetRisk(
            target=target,
            target_type=entry["target_type"],
            risk_score=score,
            risk_level=_score_to_level(score),
            rule_count=entry["rule_count"],
            rule_names=entry["rule_names"][:5],
            headlines=entry["headlines"],
        ))

    # 按 risk_score 降序
    results.sort(key=lambda r: -r.risk_score)
    return results


def risk_summary(storage) -> dict:
    """workspace 整体风险概览"""
    rows = storage.query("correlations", filter_sql="status = 'active'", limit=10000)
    by_level = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for r in rows:
        score = r.get("risk", 0) or 0
        level = _score_to_level(score)
        by_level[level] += 1
    return {
        "total_correlations": len(rows),
        "by_level": by_level,
        "max_risk": max((r.get("risk", 0) or 0) for r in rows) if rows else 0,
        "unique_targets": len(set(r.get("target", "") for r in rows if r.get("target"))),
    }


def top_risks(storage, limit: int = 10, min_level: str | None = None) -> list[AssetRisk]:
    """workspace 内 top N 高风险资产

    按 risk_score 降序,可选按 risk_level 过滤(low/medium/high/critical)
    """
    if limit <= 0:
        return []
    risks = compute_asset_risks(storage)
    if min_level:
        # 等级序:low < medium < high < critical
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        threshold = order.get(min_level, 0)
        risks = [r for r in risks if order.get(r.risk_level, 0) >= threshold]
    return risks[:limit]
