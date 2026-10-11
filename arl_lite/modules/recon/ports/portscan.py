"""arl_lite.modules.recon.ports.portscan

端口扫描模块(支持 nmap + 纯 Python fallback)。

行为:
1. 解析 target(支持 IP/CIDR/域名)
2. 对每个 host 并发端口扫描
3. 入库 ports 表
"""
from __future__ import annotations

import logging
import time
import ipaddress
import itertools
import socket

from ....core.base_module import BaseModule, ModuleResult
from ....integrations.portscan import scan, parse_ports, check_nmap

log = logging.getLogger("arl_lite.modules.portscan")


def resolve_host(target: str) -> list[str]:
    """解析 target → host 列表(IP 列表)"""
    target = target.strip()
    if not target:
        return []

    # CIDR
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 256:
            log.warning(f"portscan: {target} has {net.num_addresses} hosts, "
                        f"truncating to first 256 (safety)")
            # islice 惰性取前 256;list(net.hosts()) 会先物化全量
            # (/8 = 1600 万对象,"安全截断"本身成了内存炸弹)
            return [str(ip) for ip in itertools.islice(net.hosts(), 256)]
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # 纯 IP
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass

    # 域名 → 解析 A/AAAA 记录
    try:
        infos = socket.getaddrinfo(target, None)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        return ips
    except socket.gaierror:
        log.warning(f"portscan: cannot resolve {target}")
        return []


class PortscanModule(BaseModule):
    name = "portscan"
    category = "recon/ports"
    description = "端口扫描(nmap 优先,纯 Python fallback)"
    input_type = "ip_or_domain"
    output_type = "port"
    required_tools = []  # nmap 可选,没装会自动 fallback
    author = "arl-lite"
    version = "0.2.0"

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        ports = kwargs.get("ports") or self.config.get(
            "ports",
            "21,22,23,25,53,80,110,135,139,143,161,389,443,445,465,587,636,873,"
            "993,995,1080,1433,1521,2049,2181,3306,3389,3690,5432,5601,5900,5984,"
            "6379,7001,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017"
        )
        prefer = kwargs.get("prefer", "auto")
        timeout_per_port = float(kwargs.get("timeout_per_port", 2.0))

        hosts = resolve_host(target)
        if not hosts:
            return ModuleResult(
                success=False, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[self.make_source_result(
                    data=[], source=self.name, start_time=start,
                    error=f"no hosts resolved from {target}", error_type="resolve"
                )],
                errors=[f"no hosts resolved from {target}"],
            )

        all_results: list[dict] = []
        all_errors: list[str] = []
        use_nmap = (prefer == "nmap") or (prefer == "auto" and check_nmap())

        for host in hosts:
            results, err, etype = await scan(
                host, ports=ports, prefer=prefer, timeout_per_port=timeout_per_port, include_closed=True,
            )
            if err:
                all_errors.append(f"{host}: {err}")
            all_results.extend(results)

        # 入库
        for r in all_results:
            if r["state"] == "unknown":
                self.storage.record_port_unknown(self.task_id, r["host"], r["port"], self.name, r.get("reason", "filtered/unknown"))
                all_errors.append(f'{r["host"]}:{r["port"]}: {r.get("reason", "filtered/unknown")}')
                continue
            self.storage.add_port(
                task_id=self.task_id,
                host=r["host"],
                port=r["port"],
                state=r["state"],
                service=r["service"],
                source=self.name,
            )

        sr = self.make_source_result(
            data=all_results, source=self.name, start_time=start,
            error=all_errors[0] if all_errors else None,
            error_type="scan_error" if all_errors else None,
        )

        return ModuleResult(
            success=sr.ok, target=target, found=sum(r["state"] == "open" for r in all_results),
            duration_seconds=time.time() - start,
            sources=[sr], errors=all_errors,
            metadata={
                "ports_expressed": ports,
                "ports_count": len(parse_ports(ports)),
                "hosts_scanned": len(hosts),
                "scanner": "nmap" if use_nmap else "python-fallback",
            }
        )
