"""arl_lite.modules.recon.github

GitHub 监控 — 探测代码泄漏 / 凭证 / 敏感文件。

设计:
- 用 GitHub Search API(code search)
- 探测类型:API key、token、password、private key、.env
- 无 token 也能跑(限速更严)
- 解析 JSON 响应
- 3 态返回
"""
from __future__ import annotations

import logging
import asyncio
import os
import time

from ...core.base_module import BaseModule, ModuleResult
from ...integrations.github_search import search_github, BUILTIN_QUERIES

log = logging.getLogger("arl_lite.modules.github")


class GithubModule(BaseModule):
    name = "github"
    category = "recon/external"
    description = "GitHub 代码泄漏监控(API key / token / .env / private key)"
    input_type = "domain"
    output_type = "finding"
    required_tools = []  # 不强制需要 token
    author = "arl-lite"
    version = "0.5.0"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        # target 是域名
        target_domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        # token:env > config
        token = os.environ.get("ARL_GITHUB_TOKEN", "") or os.environ.get("GITHUB_TOKEN", "")
        queries = kwargs.get("queries") or BUILTIN_QUERIES
        per_query = int(kwargs.get("per_query", 10))

        all_results = []
        errors: list[str] = []
        for q_template in queries:
            if self.should_stop():
                raise asyncio.CancelledError()
            try:
                query = q_template.format(target=target_domain, domain=target_domain)
                results = await asyncio.to_thread(search_github, query, token=token, per_page=per_query, timeout=15)
            except Exception as e:
                # 每条 query 独立容错,但失败要留痕(不再静默)
                log.warning(f"github search failed for {q_template!r}: {e}")
                errors.append(f"{q_template!r}: {e}")
                continue
            for r in results:
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=r.get("html_url", ""),
                    finding_type="github_leak",
                    title=f"GitHub leak: {r.get('repo', '?')}",
                    description=r.get("content", "")[:300],
                    evidence=json_evidence(r),
                    severity=self._severity_for(r),
                    source="github",
                )
                all_results.append(r)

        # data 只放真实结果(旧版伪造 count:0 假字典,会把 source_status
        # 的 found_count 吹成 query 数);部分失败也要带出(死源可见纪律:
        # 8 条 query 挂 7 条却有结果时,不能伪装成全量健康)
        partial = "; ".join(errors[:3]) if errors else None
        sr = self.make_source_result(
            data=all_results,
            source=self.name, start_time=start,
            error=partial,
            error_type=("rate_limit" if any("403" in e or "rate" in e.lower() for e in errors)
                        else "network") if errors else None,
        )
        return ModuleResult(
            success=sr.ok, target=target, found=len(all_results),
            duration_seconds=time.time() - start,
            sources=[sr], errors=errors[:5],
            metadata={
                "queries_run": len(queries),
                "results": len(all_results),
                "token_used": bool(token),
            },
        )

    def _severity_for(self, r: dict) -> str:
        name = r.get("name", "").lower()
        path = r.get("path", "").lower()
        full = f"{name} {path}"
        if "private" in full or "id_rsa" in full or ".pem" in full or "key" in full:
            return "critical"
        if "password" in full or "secret" in full or "token" in full or "api_key" in full:
            return "high"
        if ".env" in full or "credentials" in full or "config" in full:
            return "high"
        return "medium"


def json_evidence(r: dict) -> str:
    import json
    return json.dumps({
        "repo": r.get("repo"),
        "path": r.get("path"),
        "html_url": r.get("html_url"),
        "score": r.get("score"),
    }, ensure_ascii=False)[:500]
