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

        # An installed but failing scanner must not silently turn into a
        # completed-empty scan or launch a second, different measurement.
        binary = bool(shutil.which("nuclei"))
        outcome = (run_nuclei(target, timeout=timeout, severity=severity,
                              tags=tags, templates=templates) if binary else
                   scan_with_templates(target, BUILTIN_TEMPLATES))
        source = "nuclei" if binary else "nuclei-fallback"
        for r in outcome.data:
            classification = r.get("classification")
            cve = classification.get("cve-id") if isinstance(classification, dict) else None
            if isinstance(cve, list):
                cve = ",".join(str(v) for v in cve)
            self.storage.add_finding(
                task_id=self.task_id,
                target=r.get("matched_at", target),
                finding_type="nuclei_poc" if binary else "builtin_poc",
                title=f"[{r.get('severity', 'info')}] {r.get('name', '?')}",
                description=r.get("description", ""),
                evidence=json.dumps(r, ensure_ascii=False)[:500],
                severity=r.get("severity", "info"),
                cve=cve,
                source="nuclei" if binary else "builtin",
            )
        sr = self.make_source_result(
            data=outcome.data, source=source, start_time=start,
            error=outcome.error, error_type=outcome.error_type,
        )
        return ModuleResult(
            success=sr.ok, target=target, found=len(outcome.data),
            duration_seconds=time.time() - start,
            sources=[sr], errors=[outcome.error] if outcome.error else [],
            metadata={"engine": "nuclei" if binary else "builtin",
                      "attempted": outcome.attempted, "completed": outcome.completed},
        )
