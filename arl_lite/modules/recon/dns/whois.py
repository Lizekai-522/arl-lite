"""arl_lite.modules.recon.dns.whois

WHOIS module — 查域名注册信息。
"""
from __future__ import annotations

import json
import asyncio
import logging
import time

from ....core.base_module import BaseModule, ModuleResult
from ....integrations.whois_lookup import whois_query

log = logging.getLogger("arl_lite.modules.whois")


class WhoisModule(BaseModule):
    name = "whois"
    category = "recon/dns"
    description = "WHOIS 域名注册信息(注册商/到期/状态/NS)"
    input_type = "domain"
    output_type = "finding"
    required_tools = []
    author = "arl-lite"
    version = "0.6.0"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        target_domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        timeout = int(kwargs.get("timeout", 10))

        try:
            result = await asyncio.to_thread(whois_query, target_domain, timeout=timeout, should_stop=self.should_stop)
        except Exception as e:
            log.exception(f"whois failed: {e}")
            return ModuleResult(
                success=False, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[],
                errors=[f"{type(e).__name__}: {e}"],
            )

        if "_error" in result:
            sr = self.make_source_result(
                data=[], source=self.name, start_time=start,
            )
            return ModuleResult(
                success=False, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[sr],
                errors=[result["_error"]],
            )

        # 入库:核心字段
        server = result.get("server", "?")
        registrar = result.get("registrar", "?")
        # 限流页/空壳响应:解析结果全是占位符时如实报错,不产出脏 finding
        if (not registrar or registrar == "?") and not result.get("creation_date") and not result.get("expiration_date"):
            sr = self.make_source_result(
                data=[], source=self.name, start_time=start,
                error="no usable whois data (rate limit page or unsupported TLD?)",
                error_type="parse",
            )
            return ModuleResult(
                success=sr.ok, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[sr], errors=[sr.error or ""],
            )
        creation = result.get("creation_date", "?")
        expiration = result.get("expiration_date", "?")
        statuses = result.get("status", [])
        nservers = result.get("name_servers", [])

        # 计算剩余天数(简单)
        evidence = json.dumps({
            "server": server,
            "registrar": registrar,
            "creation_date": creation,
            "expiration_date": expiration,
            "statuses": statuses,
            "name_servers": nservers,
        }, ensure_ascii=False)[:500]

        self.storage.add_finding(
            task_id=self.task_id,
            target=target_domain,
            finding_type="whois",
            title=f"WHOIS: {target_domain} via {server}",
            description=f"registrar={registrar} expires={expiration} status={','.join(statuses[:3])}",
            evidence=evidence,
            severity="info",
            source=self.name,
        )

        # 注册人 / email 如果暴露 → 标高(但是 WHOIS 反查)
        registrant = result.get("registrant", "")
        if registrant and "redacted" not in registrant.lower() and "privacy" not in registrant.lower():
            self.storage.add_finding(
                task_id=self.task_id,
                target=target_domain,
                finding_type="whois_registrant",
                title=f"Registrant: {registrant}",
                description="注册人公开(没 privacy 保护)",
                evidence=f"registrant={registrant}",
                severity="medium",
                source=self.name,
            )

        for email in result.get("emails", [])[:3]:
            self.storage.add_finding(
                task_id=self.task_id,
                target=target_domain,
                finding_type="whois_email",
                title=f"Email: {email}",
                description="WHOIS 文本中发现 email",
                evidence=email,
                severity="low",
                source=self.name,
            )

        sr = self.make_source_result(
            data=result, source=self.name, start_time=start,
        )
        return ModuleResult(
            success=sr.ok, target=target, found=1,  # 实际入库 1 条 whois finding
            duration_seconds=time.time() - start,
            sources=[sr], errors=[],
            metadata={
                "registrar": registrar,
                "expiration_date": expiration,
                "name_servers_count": len(nservers),
                "status_count": len(statuses),
            }
        )
