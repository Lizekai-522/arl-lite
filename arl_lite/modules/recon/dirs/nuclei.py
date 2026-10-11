"""arl_lite.modules.recon.dirs.nuclei

Nuclei 集成 — 调外部 nuclei binary(如果装了),否则 fallback 到模板扫描。

设计:
- 优先用真实 nuclei(快、准确、社区模板)
- 没装 nuclei → 跑内建 20+ 模板(.git 暴露、swagger、admin 面板等)
- 解析 JSON Lines 输出
- 3 态返回
"""
from __future__ import annotations

import json
import asyncio
import logging
import shutil
import time

from ....core.base_module import BaseModule, ModuleResult
from ....integrations.nuclei import run_nuclei, BUILTIN_TEMPLATES, scan_with_templates

log = logging.getLogger("arl_lite.modules.nuclei")


class NucleiModule(BaseModule):
    name = "nuclei"
    category = "recon/dirs"
    description = "PoC 联动(nuclei binary + 20+ 内建模板 fallback)"
    input_type = "url"
    output_type = "finding"
    required_tools = ["nuclei"]  # 提示但不强制
    author = "arl-lite"
    version = "0.5.0"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        if not target.startswith("http://") and not target.startswith("https://"):
            target = f"http://{target}"

        timeout = int(kwargs.get("timeout", 300))
        severity = kwargs.get("severity", "info,low,medium,high,critical")
        tags = kwargs.get("tags", "")
        templates = kwargs.get("templates", "")  # custom templates dir

        # 1. 优先真实 nuclei
        if shutil.which("nuclei"):
            try:
                # fallback 只对 run_nuclei 本身失败触发;一行坏 JSON 不应该
                # 引发对目标的二次扫描(旧版把入库循环也包进 try,
                # matched_at:null 就切换到内建模板重扫,产出混杂结果)
                results = [
                    r for r in await asyncio.to_thread(run_nuclei,
                        target, timeout=timeout, severity=severity,
                        tags=tags, templates=templates, should_stop=self.should_stop,
                    )
                    if isinstance(r, dict) and isinstance(r.get("matched_at"), str)
                ]
            except Exception as e:
                log.warning(f"nuclei binary failed, falling back to builtin: {e}")
            else:
                for r in results:
                    self.storage.add_finding(
                        task_id=self.task_id,
                        target=r.get("matched_at", target),
                        finding_type="nuclei_poc",
                        title=f"[{r.get('severity', 'info')}] {r.get('name', r.get('template-id', '?'))}",
                        description=r.get("description", ""),
                        evidence=json.dumps(r, ensure_ascii=False)[:500],
                        severity=r.get("severity", "info") if isinstance(r.get("severity"), str) and r.get("severity") in ("info", "low", "medium", "high", "critical") else "info",
                        cve=r.get("classification", {}).get("cve-id") if isinstance(r.get("classification"), dict) else None,
                        source="nuclei",
                    )
                sr = self.make_source_result(
                    data=results, source="nuclei", start_time=start,
                )
                return ModuleResult(
                    success=sr.ok, target=target, found=len(results),
                    duration_seconds=time.time() - start,
                    sources=[sr], errors=[],
                    metadata={"engine": "nuclei", "matched": len(results)},
                )

        # 2. fallback:内建模板
        log.info(f"using built-in templates fallback for {target}")
        results = await asyncio.to_thread(scan_with_templates, target, BUILTIN_TEMPLATES, self.should_stop)
        for r in results:
            self.storage.add_finding(
                task_id=self.task_id,
                target=r.get("matched_at", target),
                finding_type="builtin_poc",
                title=f"[{r.get('severity', 'info')}] {r.get('name', '?')}",
                description=r.get("description", ""),
                evidence=json.dumps(r, ensure_ascii=False)[:500],
                severity=r.get("severity", "info"),
                source="builtin",
            )
        sr = self.make_source_result(
            data=results, source="nuclei-fallback", start_time=start,
        )
        return ModuleResult(
            success=sr.ok, target=target, found=len(results),
            duration_seconds=time.time() - start,
            sources=[sr], errors=[],
            metadata={"engine": "builtin", "matched": len(results)},
        )
