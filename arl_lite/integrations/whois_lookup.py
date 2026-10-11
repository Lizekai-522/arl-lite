"""arl_lite.integrations.whois_lookup

WHOIS 查询 — 纯 stdlib socket。

协议:port 43,发 "<domain>\r\n",读响应。
"""
from __future__ import annotations

import logging
import re
import socket
from typing import Optional

log = logging.getLogger("arl_lite.integrations.whois_lookup")

# 公共 WHOIS server
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
    "cn": "whois.cnnic.cn",
    "com.cn": "whois.cnnic.cn",
    "net.cn": "whois.cnnic.cn",
    "org.cn": "whois.cnnic.cn",
    "edu.cn": "whois.cnnic.cn",
    "ai": "whois.nic.ai",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "ru": "whois.tcinet.ru",
    "jp": "whois.jprs.jp",
    "fr": "whois.nic.fr",
    "tv": "whois.nic.tv",
    "cc": "whois.nic.cc",
    "xyz": "whois.nic.xyz",
}


def whois_server_for(domain: str) -> str:
    """根据 TLD 选 WHOIS server"""
    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return "whois.iana.org"
    tld = parts[-1]
    # 二级 TLD(如 com.cn)
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in WHOIS_SERVERS:
        return WHOIS_SERVERS[f"{parts[-2]}.{parts[-1]}"]
    return WHOIS_SERVERS.get(tld, "whois.iana.org")


def _parse_whois_response(text) -> dict:
    """解析 WHOIS 文本为结构化字段

    防御性:非 str 输入(None / int / bytes)返回空结果,不抛异常。
    """
    if not isinstance(text, str):
        log.warning(f"_parse_whois_response: non-str input ({type(text).__name__})")
        return {
            "domain": None, "registrar": None, "creation_date": None,
            "expiration_date": None, "updated_date": None, "status": [],
            "name_servers": [], "registrant": None, "emails": [],
            "raw_length": 0,
        }
    result = {
        "domain": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "status": [],
        "name_servers": [],
        "registrant": None,
        "emails": [],
        "raw_length": len(text),
    }
    # 通用 pattern
    patterns = {
        "domain": r"Domain Name:\s*(\S+)",
        "registrar": r"Registrar:\s*(.+)",
        "creation_date": r"Creation Date:\s*(.+)",
        "expiration_date": r"(?:Registry Expiry Date|Expires On|Expiration Date):\s*(.+)",
        "updated_date": r"Updated Date:\s*(.+)",
        "registrant": r"Registrant (?:Name|Organization):\s*(.+)",
    }
    for field_name, pattern in patterns.items():
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            result[field_name] = m.group(1).strip()

    # Status
    for m in re.finditer(r"Domain Status:\s*(\S+)", text, re.IGNORECASE):
        s = m.group(1).rstrip(".")
        if s and s not in result["status"]:
            result["status"].append(s)

    # Name servers
    for m in re.finditer(r"Name Server:\s*(\S+)", text, re.IGNORECASE):
        ns = m.group(1).lower().rstrip(".")
        if ns not in result["name_servers"]:
            result["name_servers"].append(ns)

    # Emails
    for m in re.finditer(r"[\w.+-]+@[\w-]+\.[\w.-]+", text):
        email = m.group(0)
        # 过滤 WHOIS 自身的 abuse/contact
        if "abuse" in email or "contact" in email or "whois" in email:
            continue
        if email not in result["emails"]:
            result["emails"].append(email)

    return result


def whois_query(domain: str, server: Optional[str] = None, timeout: int = 10, should_stop=lambda: False) -> dict:
    """查询域名的 WHOIS 信息

    Args:
        domain: 域名(例 example.com)
        server: 强制 server(默认根据 TLD 自动选)
        timeout: 超时秒

    Returns:
        dict(结构化字段 + raw)
    """
    # 防御:空 / 非 str / 含 null byte 域名直接拒(必须在 whois_server_for
    # 之前——它会调 domain.lower(),检查排在后面就形同虚设)
    if not isinstance(domain, str):
        return {"domain": None, "server": None, "_error": f"domain must be str (got {type(domain).__name__})"}
    domain = domain.strip().lower()
    if not domain:
        return {"domain": domain, "server": None, "_error": "empty domain"}
    if "\x00" in domain:
        return {"domain": domain, "server": None, "_error": "domain contains null byte"}
    if len(domain) > 253:
        return {"domain": domain, "server": None, "_error": f"domain too long ({len(domain)} > 253)"}

    if server is None:
        server = whois_server_for(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, 43))
        sock.sendall(f"{domain}\r\n".encode("utf-8"))
        chunks = []
        while True:
            if should_stop():
                raise InterruptedError("WHOIS stopped")
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            except socket.timeout:
                break
        response = b"".join(chunks).decode("utf-8", errors="replace")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        log.warning(f"whois query failed for {domain}@{server}: {e}")
        return {
            "domain": domain,
            "server": server,
            "_error": f"{type(e).__name__}: {e}",
        }
    finally:
        sock.close()

    if not response.strip():
        return {"domain": domain, "server": server, "_error": "empty response"}

    parsed = _parse_whois_response(response)
    parsed["server"] = server
    parsed["raw"] = response[:2000]  # 截断
    return parsed
