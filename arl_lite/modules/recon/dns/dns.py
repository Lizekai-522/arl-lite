"""arl_lite.modules.recon.dns.dns

DNS 详细记录枚举 module。

设计:
- 输入:域名
- 输出:finding(DNS 配置 / SPF / DMARC / 异常)
- 用 stdlib 自己解析(零依赖)
"""
from __future__ import annotations

import logging
import asyncio
import time

from ....core.base_module import BaseModule, ModuleResult
from ....integrations.dns_lookup import lookup

log = logging.getLogger("arl_lite.modules.dns")


class DNSModule(BaseModule):
    name = "dns"
    category = "recon/dns"
    description = "DNS 详细记录枚举(A/AAAA/NS/MX/TXT/SOA/CNAME)"
    input_type = "domain"
    output_type = "finding"
    required_tools = []
    author = "arl-lite"
    version = "0.6.0"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        # target 应该是域名
        target_domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        dns_server = kwargs.get("dns_server", "8.8.8.8")
        timeout = int(kwargs.get("timeout", 5))

        try:
            result = await asyncio.to_thread(lookup, target_domain, server=dns_server, timeout=timeout, should_stop=self.should_stop)
        except Exception as e:
            log.exception(f"dns lookup failed: {e}")
            return ModuleResult(
                success=False, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[],
                errors=[f"{type(e).__name__}: {e}"],
            )

        # 汇总
        total_records = sum(len(v) for k, v in result.items() if isinstance(v, list))
        # 入库 — DNS 记录作为 finding 存(便于搜索)
        if result.get("A"):
            for r in result["A"]:
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=f"{target_domain} → {r['value']}",
                    finding_type="dns_a",
                    title=f"A: {r['value']}",
                    description=f"DNS A record",
                    evidence=str(r),
                    severity="info",
                    source=self.name,
                )
        if result.get("AAAA"):
            for r in result["AAAA"]:
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=f"{target_domain} → {r['value']}",
                    finding_type="dns_aaaa",
                    title=f"AAAA: {r['value']}",
                    description=f"DNS AAAA record",
                    evidence=str(r),
                    severity="info",
                    source=self.name,
                )
        if result.get("MX"):
            for r in result["MX"]:
                pref = r.get("preference", "?")
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=f"{target_domain} MX → {r['value']}",
                    finding_type="dns_mx",
                    title=f"MX: {r['value']} (pref={pref})",
                    description=f"Mail server",
                    evidence=str(r),
                    severity="info",
                    source=self.name,
                )
        if result.get("NS"):
            for r in result["NS"]:
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=f"{target_domain} NS → {r['value']}",
                    finding_type="dns_ns",
                    title=f"NS: {r['value']}",
                    description=f"Name server",
                    evidence=str(r),
                    severity="info",
                    source=self.name,
                )
        if result.get("TXT"):
            for r in result["TXT"]:
                # 特殊:SPF / DMARC
                val = r["value"]
                sev = "info"
                title_prefix = "TXT"
                if "v=spf1" in val:
                    title_prefix = "SPF"
                elif "DMARC" in val.upper() or "v=DMARC" in val:
                    title_prefix = "DMARC"
                if "v=DMARC" not in val and "DMARC" not in val.upper() and target_domain.startswith("_dmarc"):
                    title_prefix = "DMARC"
                self.storage.add_finding(
                    task_id=self.task_id,
                    target=f"{target_domain} TXT",
                    finding_type="dns_txt",
                    title=f"{title_prefix}: {val[:80]}",
                    description=f"DNS TXT record",
                    evidence=val[:500],
                    severity=sev,
                    source=self.name,
                )

        sr = self.make_source_result(
            data=result, source=self.name, start_time=start,
        )
        return ModuleResult(
            success=sr.ok, target=target, found=total_records,
            duration_seconds=time.time() - start,
            sources=[sr], errors=[],
            metadata={
                "dns_server": dns_server,
                "record_types": {k: len(v) for k, v in result.items() if isinstance(v, list)},
            }
        )
