"""arl_lite.integrations.nuclei

Nuclei binary 调用 + 20+ 内建模板 fallback。

外部 nuclei 安装(可选):
- Go:go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
- Mac:brew install nuclei
- 预编译二进制:https://github.com/projectdiscovery/nuclei/releases

nuclei 协议:
- 输出:JSON Lines 到 stdout
- 调用:nuclei -u URL -severity info,low,medium,high,critical -json
"""
from __future__ import annotations

import json
import logging
import shlex
import subprocess

log = logging.getLogger("arl_lite.integrations.nuclei")


def run_nuclei(
    target: str,
    timeout: int = 300,
    severity: str = "info,low,medium,high,critical",
    tags: str = "",
    templates: str = "",
    should_stop=lambda: False,
) -> list[dict]:
    """调用 nuclei binary

    Args:
        target: URL
        timeout: 超时秒
        severity: 严重度过滤
        tags: 标签过滤(逗号分隔)
        templates: 自定义模板目录

    Returns:
        findings list(每条 dict)
    """
    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity,
        "-json",
        "-silent",
        "-no-update-check",
    ]
    if tags:
        cmd += ["-tags", tags]
    if templates:
        cmd += ["-t", templates]

    log.debug(f"running nuclei: {' '.join(shlex.quote(c) for c in cmd)}")
    try:
        from ..core.process import run_process_sync
        proc = run_process_sync(cmd, timeout, should_stop)
    except subprocess.TimeoutExpired as e:
        log.warning(f"nuclei timeout after {timeout}s")
        return []
    except FileNotFoundError:
        log.warning("nuclei binary not found")
        return []

    if proc.returncode != 0 and not proc.stdout:
        log.warning(f"nuclei exit={proc.returncode} stderr={proc.stderr[:200]}")
        return []

    results = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            log.debug(f"nuclei output not JSON: {line[:80]}")
    return results


# =========================
# 20+ 内建模板 fallback
# =========================

BUILTIN_TEMPLATES = [
    {
        "id": "git-config",
        "name": "Git Config Exposed",
        "severity": "high",
        "description": ".git/config file is publicly accessible",
        "path": ".git/config",
        "match_status": 200,
        "match_keywords": ["[core]", "[remote"],
    },
    {
        "id": "git-head",
        "name": "Git HEAD Exposed",
        "severity": "medium",
        "description": ".git/HEAD is publicly accessible",
        "path": ".git/HEAD",
        "match_status": 200,
        "match_keywords": ["ref:"],
    },
    {
        "id": "env-file",
        "name": "Environment File Exposed",
        "severity": "high",
        "description": ".env file is publicly accessible",
        "path": ".env",
        "match_status": 200,
        "match_keywords": ["=", "KEY", "SECRET"],
    },
    {
        "id": "swagger-ui",
        "name": "Swagger UI",
        "severity": "medium",
        "description": "Swagger UI is exposed",
        "path": "swagger-ui.html",
        "match_status": 200,
        "match_keywords": ["swagger"],
    },
    {
        "id": "swagger-json",
        "name": "Swagger JSON",
        "severity": "medium",
        "description": "OpenAPI/Swagger JSON is exposed",
        "path": "swagger.json",
        "match_status": 200,
        "match_keywords": ["swagger", "openapi"],
    },
    {
        "id": "phpinfo",
        "name": "PHPInfo Exposed",
        "severity": "high",
        "description": "phpinfo() page is exposed",
        "path": "phpinfo.php",
        "match_status": 200,
        "match_keywords": ["PHP Version", "phpinfo"],
    },
    {
        "id": "admin-panel",
        "name": "Admin Panel",
        "severity": "high",
        "description": "Common admin panel path found",
        "path": "admin",
        "match_status": [200, 301, 302],
        "match_keywords": ["admin", "login", "dashboard"],
    },
    {
        "id": "wp-admin",
        "name": "WordPress Admin",
        "severity": "medium",
        "description": "WordPress admin panel found",
        "path": "wp-admin",
        "match_status": [200, 301, 302],
        "match_keywords": ["wordpress", "wp-admin"],
    },
    {
        "id": "wp-login",
        "name": "WordPress Login",
        "severity": "low",
        "description": "WordPress login page found",
        "path": "wp-login.php",
        "match_status": 200,
        "match_keywords": ["wordpress", "login"],
    },
    {
        "id": "robots-txt",
        "name": "robots.txt Exposed",
        "severity": "info",
        "description": "robots.txt is exposed(reveals structure)",
        "path": "robots.txt",
        "match_status": 200,
        "match_keywords": ["User-agent", "Disallow"],
    },
    {
        "id": "sitemap",
        "name": "Sitemap Exposed",
        "severity": "info",
        "description": "sitemap.xml is exposed",
        "path": "sitemap.xml",
        "match_status": 200,
        "match_keywords": ["urlset", "sitemap"],
    },
    {
        "id": "backup-zip",
        "name": "Backup File Exposed",
        "severity": "high",
        "description": "Backup .zip/.tar.gz file is exposed",
        "path": "backup.zip",
        "match_status": 200,
        "match_keywords": ["PK", "BZh"],  # zip/gzip magic
    },
    {
        "id": "database-sql",
        "name": "Database Dump",
        "severity": "critical",
        "description": "SQL dump file is exposed",
        "path": "dump.sql",
        "match_status": 200,
        "match_keywords": ["CREATE TABLE", "INSERT INTO"],
    },
    {
        "id": "htpasswd",
        "name": "htpasswd Exposed",
        "severity": "critical",
        "description": ".htpasswd file is exposed(密码 hash)",
        "path": ".htpasswd",
        "match_status": 200,
        "match_keywords": [":"],  # user:hash format
    },
    {
        "id": "dockerfile",
        "name": "Dockerfile Exposed",
        "severity": "medium",
        "description": "Dockerfile is exposed",
        "path": "Dockerfile",
        "match_status": 200,
        "match_keywords": ["FROM", "RUN"],
    },
    {
        "id": "docker-compose",
        "name": "docker-compose.yml Exposed",
        "severity": "medium",
        "description": "docker-compose.yml is exposed",
        "path": "docker-compose.yml",
        "match_status": 200,
        "match_keywords": ["services:", "image:"],
    },
    {
        "id": "actuator",
        "name": "Spring Boot Actuator",
        "severity": "high",
        "description": "Spring Boot Actuator endpoint exposed",
        "path": "actuator",
        "match_status": 200,
        "match_keywords": ["_links", "health", "beans"],
    },
    {
        "id": "graphql",
        "name": "GraphQL Endpoint",
        "severity": "medium",
        "description": "GraphQL endpoint is exposed",
        "path": "graphql",
        "match_status": [200, 400, 405],
        "match_keywords": ["__schema", "GraphQL", "query"],
    },
    {
        "id": "kibana",
        "name": "Kibana",
        "severity": "high",
        "description": "Kibana dashboard exposed",
        "path": "app/kibana",
        "match_status": 200,
        "match_keywords": ["kibana", "elastic"],
    },
    {
        "id": "prometheus",
        "name": "Prometheus Metrics",
        "severity": "medium",
        "description": "Prometheus metrics exposed",
        "path": "metrics",
        "match_status": 200,
        "match_keywords": ["# HELP", "# TYPE"],
    },
    {
        "id": "cgi-bin",
        "name": "CGI-BIN Exposed",
        "severity": "low",
        "description": "cgi-bin directory exposed",
        "path": "cgi-bin/",
        "match_status": 200,
        "match_keywords": [],
    },
    {
        "id": "server-status",
        "name": "Apache Server Status",
        "severity": "low",
        "description": "Apache mod_status exposed",
        "path": "server-status",
        "match_status": 200,
        "match_keywords": ["Apache Server Status"],
    },
]


def scan_with_templates(target: str, templates: list[dict], should_stop=lambda: False) -> list[dict]:
    """用内建模板跑探测(纯 HTTP)

    Args:
        target: URL
        templates: 模板列表

    Returns:
        matches list
    """
    import urllib.request
    import urllib.error
    import ssl

    if not target.endswith("/"):
        target = target + "/"

    ctx = ssl.create_default_context()
    matches = []
    for t in templates:
        if should_stop():
            raise InterruptedError("template scan stopped")
        url = target + t["path"].lstrip("/")
        try:
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "arl-lite/0.5"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                status = resp.status
                body = resp.read(64 * 1024).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            status = e.code
            body = ""
            try:
                body = e.read(64 * 1024).decode("utf-8", errors="replace")
            except Exception:
                pass
        except Exception as e:
            continue

        # 状态码匹配
        match_status = t.get("match_status", 200)
        if isinstance(match_status, int):
            match_status = [match_status]
        if status not in match_status:
            continue

        # 关键词匹配
        keywords = t.get("match_keywords", [])
        if keywords:
            found = sum(1 for kw in keywords if kw in body)
            if found == 0:
                continue

        matches.append({
            "template-id": t["id"],
            "name": t["name"],
            "severity": t.get("severity", "info"),
            "description": t.get("description", ""),
            "matched_at": url,
            "matcher_name": "status+keywords",
        })
    return matches
