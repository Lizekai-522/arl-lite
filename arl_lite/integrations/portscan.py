"""arl_lite.integrations.portscan

端口扫描:有 nmap 用 nmap,没有 fallback 到纯 Python TCP connect 扫描。

设计:
- 优先 nmap(subprocess,扫描精度高)
- 没装 nmap → 用 socket 做 TCP connect 扫描(基础但能用)
- 输出统一格式:list[dict{host, port, state, service, banner?}]

纪律:
- 速率控制:不扫太快,避免被屏蔽
- 超时:每个连接 2s 默认
- 端口解析:支持 80,443 / 1-1000 / 80,443,8000-8100
"""
from __future__ import annotations

import asyncio
import errno
import logging
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import AsyncIterator

log = logging.getLogger("arl_lite.integrations.portscan")

DEFAULT_TIMEOUT = 2.0  # 每个连接 2s
DEFAULT_CONCURRENCY = 100  # 100 并发


def parse_ports(ports: str) -> list[int]:
    """解析端口表达式:'80,443' / '1-1000' / '80,443,8000-8100' → [80, 443, ...]"""
    result: set[int] = set()
    for part in ports.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start, end = int(start_s), int(end_s)
                if start > end:
                    log.warning(f"portscan: bad port range '{part}' (start > end), skipped")
                    continue
                for p in range(start, end + 1):
                    if 1 <= p <= 65535:
                        result.add(p)
            except ValueError:
                log.warning(f"portscan: bad port range '{part}', skipped")
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    result.add(p)
            except ValueError:
                log.warning(f"portscan: bad port '{part}', skipped")
    return sorted(result)


# 常见端口 → 服务名(基础 NMAP services 摘录)
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 587: "smtp-submission", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 2181: "zookeeper", 3306: "mysql", 3389: "rdp",
    3690: "svn", 4444: "metasploit", 5000: "upnp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    7001: "weblogic", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "fpm",
    9090: "prometheus", 9200: "elasticsearch", 9300: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 50070: "hadoop", 61613: "activemq",
}


def _probe_tcp(host: str, port: int, timeout: float, include_closed: bool = False) -> dict | None:
    """同步 TCP connect 探测(单端口)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            err = s.connect_ex((host, port))
            if err == 0:
                return {
                    "host": host,
                    "port": port,
                    "state": "open",
                    "service": COMMON_PORTS.get(port, "unknown"),
                }
        if include_closed:
            return {"host": host, "port": port, "state": "closed" if err in (errno.ECONNREFUSED, 10061) else "unknown",
                    "service": COMMON_PORTS.get(port, "unknown"), "reason": f"connect-error:{err}"}
        return None
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as error:
        if include_closed:
            return {"host": host, "port": port,
                    "state": "closed" if isinstance(error, ConnectionRefusedError) else "unknown",
                    "service": COMMON_PORTS.get(port, "unknown"), "reason": type(error).__name__}
        return None


async def scan_tcp(
    host: str,
    ports: list[int],
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    include_closed: bool = False,
) -> AsyncIterator[dict]:
    """纯 Python TCP connect 扫描

    Yields:
        {host, port, state, service}
    """
    loop = asyncio.get_running_loop()
    # 用 ThreadPoolExecutor 跑阻塞 socket(因为 socket.connect_ex 是阻塞)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {
            pool.submit(_probe_tcp, host, port, timeout, include_closed): port
            for port in ports
        }
        for fut in as_completed(futures):
            # wrap_future:等待期间让事件循环调度其他协程(旧写法冻结 loop)
            r = await asyncio.wrap_future(fut)
            if r is not None:
                yield r


# ---------------- nmap wrapper(可选)----------------

def check_nmap() -> bool:
    """检查 nmap 是否可用"""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


async def scan_nmap(
    host: str,
    ports: str,
    timeout: int = 300,
    include_closed: bool = False,
) -> AsyncIterator[dict]:
    """subprocess 调 nmap,解析输出

    命令:nmap -Pn -p 80,443,1-1000 -oG - <host>
    """
    cmd = ["nmap", "-Pn", "-p", ports, "-oG", "-", "--", host]
    log.info(f"nmap: running {' '.join(cmd)}")

    def _run():
        return subprocess.run(
            cmd, capture_output=True, timeout=timeout, text=True
        )

    loop = asyncio.get_running_loop()
    try:
        result = await loop.run_in_executor(None, _run)
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"nmap timeout after {timeout}s")
    except FileNotFoundError:
        raise FileNotFoundError("nmap not installed")

    if result.returncode != 0:
        raise RuntimeError(f"nmap returned {result.returncode}: {result.stderr[:200]}")

    # 解析 -oG 格式:Host: 1.2.3.4 ()  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    for line in result.stdout.splitlines():
        if not line.startswith("Host:"):
            continue
        # 提取端口(Ports: 后面是本行剩余全部内容,逗号分隔)
        ports_match = re.search(r"Ports:\s*(.*)$", line)
        if not ports_match:
            continue
        ports_str = ports_match.group(1)
        for port_info in ports_str.split(","):
            parts = port_info.strip().split("/")
            if len(parts) < 3:
                continue
            try:
                port = int(parts[0])
            except ValueError:
                # 畸形 token(注释/截断行)跳过,别让整个扫描报 EXC
                continue
            state = parts[1]
            if state != "open" and not include_closed:
                continue
            if state not in ("open", "closed"):
                state = "unknown"
            service = parts[4] if len(parts) > 4 and parts[4] else COMMON_PORTS.get(port, "unknown")
            yield {
                "host": host,
                "port": port,
                "state": state,
                "service": service,
            }


async def scan(
    host: str,
    ports: str = "21,22,23,25,80,110,135,139,143,161,389,443,445,465,587,636,873,993,995,1080,1433,1521,2049,2181,3306,3389,3690,4444,5000,5432,5601,5900,5984,6379,7001,8000,8008,8080,8081,8443,8888,9000,9090,9200,9300,11211,27017,50070,61613",
    prefer: str = "auto",  # "auto" / "nmap" / "python"
    timeout_per_port: float = DEFAULT_TIMEOUT,
    include_closed: bool = False,
) -> tuple[list[dict], str | None, str | None]:
    """端口扫描入口

    Args:
        host: 目标 IP/域名
        ports: 端口表达式
        prefer: 优先 nmap 还是纯 Python
        timeout_per_port: 每个端口超时

    Returns:
        (results, error, error_type) — 三态
    """
    port_list = parse_ports(ports)
    if not port_list:
        return [], f"no valid ports parsed from '{ports}'", "config"

    # 选择扫描器
    use_nmap = False
    if prefer == "nmap":
        use_nmap = True
    elif prefer == "auto":
        use_nmap = check_nmap()

    if use_nmap:
        try:
            results = []
            async for r in scan_nmap(host, ports, timeout=300, include_closed=include_closed):
                results.append(r)
            return results, None, None
        except FileNotFoundError as e:
            # nmap 不可用 → 降级到 Python 扫描
            log.warning(f"nmap unavailable, fallback to Python: {e}")
        except (TimeoutError, RuntimeError) as e:
            return [], str(e), "scan_error"

    # 纯 Python TCP connect 扫描
    try:
        results = []
        async for r in scan_tcp(host, port_list, timeout=timeout_per_port, include_closed=include_closed):
            results.append(r)
        return results, None, None
    except Exception as e:
        return [], f"{type(e).__name__}: {e}", "unknown"
