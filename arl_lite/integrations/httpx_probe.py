"""arl_lite.integrations.httpx_probe

轻量 HTTP 探活(纯 urllib,无 httpx 依赖):
- 给定 host:port 列表,探测 http/https 响应
- 提取:status / title / server / content_length / content_type / tech hints
- 并发 + 超时控制

纪律:
- 失败 = 三态记录(不吞错)
- 标题提取:正则 <title>(.+?)</title>
- 指纹线索:Server header + X-Powered-By + body 中的关键词
"""
from __future__ import annotations

import asyncio
import logging
import re
import urllib.request
import urllib.error
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import AsyncIterator
from .portscan import COMMON_PORTS

log = logging.getLogger("arl_lite.integrations.httpx_probe")

DEFAULT_TIMEOUT = 10
DEFAULT_CONCURRENCY = 50
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) arl-lite/0.2"

TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE | re.DOTALL)
META_DESC_RE = re.compile(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _ssl_context(verify: bool = True) -> ssl.SSLContext:
    """SSL 上下文:默认校验证书;自签内网场景降级为不校验(调用方需打标)"""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _do_request(url: str, timeout: int) -> dict:
    """同步 HTTP 请求(给 thread pool 跑)"""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        if url.startswith("https://"):
            # 先按正常方式校验证书,失败(自签/过期)再降级重试并打标,
            # 避免 MITM 伪造 title/Server 污染指纹与关联分析。
            # 注意 urllib 对证书错误抛的是 URLError(包裹 reason),不是
            # 裸 SSLCertVerificationError——只接后者会让降级成死代码
            try:
                resp_ctx = _ssl_context(verify=True)
                resp = urllib.request.urlopen(req, timeout=timeout, context=resp_ctx)
                tls_verified: bool | None = True
            except (ssl.SSLCertVerificationError, urllib.error.URLError) as e:
                reason = getattr(e, "reason", e)
                if not isinstance(e, ssl.SSLCertVerificationError) and not isinstance(reason, ssl.SSLCertVerificationError):
                    raise  # 非证书类网络错,交给外层统一处理
                resp = urllib.request.urlopen(req, timeout=timeout, context=_ssl_context(verify=False))
                tls_verified = False
        else:
            resp = urllib.request.urlopen(req, timeout=timeout, context=None)
            tls_verified = None
        with resp:
            body = resp.read(200 * 1024)  # 最多读 200KB(标题和元信息够了)
            return {
                "url": url,
                "tls_verified": tls_verified,
                "status": resp.status,
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "content_length": len(body),
                "x_powered_by": resp.headers.get("X-Powered-By", ""),
                "body": body.decode("utf-8", errors="ignore"),
            }
    except urllib.error.HTTPError as e:
        # 4xx/5xx 也算响应(401/403 也能拿到 server header)
        try:
            body = e.read(200 * 1024)
        except Exception:
            body = b""
        # HTTPError 也需要 close
        try:
            e.close()
        except Exception:
            pass
        return {
            "url": url,
            "tls_verified": None,  # HTTPError 无法确定,不声称为已验证
            "status": e.code,
            "server": e.headers.get("Server", "") if e.headers else "",
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "content_length": len(body),
            "x_powered_by": e.headers.get("X-Powered-By", "") if e.headers else "",
            "body": body.decode("utf-8", errors="ignore"),
            "error": None,  # HTTP 错误不算网络错(状态码也算探活)
        }
    except urllib.error.URLError as e:
        return {"url": url, "status": 0, "server": "", "error": f"URLError: {e}"}
    except Exception as e:
        return {"url": url, "status": 0, "server": "", "error": f"{type(e).__name__}: {e}"}


def _extract_title(html: str) -> str:
    m = TITLE_RE.search(html)
    if m:
        title = m.group(1).strip()
        if len(title) > 200:
            title = title[:200] + "..."
        return title
    return ""


def _extract_tech(hint: dict) -> str:
    """从 server/x-powered-by/body 提取技术栈 hints"""
    techs = []
    server = hint.get("server", "").lower()
    if server:
        # nginx/apache/iis/tomcat 等
        for kw in ["nginx", "apache", "iis", "tomcat", "weblogic", "jboss",
                   "caddy", "cloudflare", "openresty", "tengine", "lighttpd"]:
            if kw in server:
                techs.append(kw)

    xpb = hint.get("x_powered_by", "").lower()
    if xpb:
        for kw in ["php", "asp.net", "express", "django", "flask", "spring", "rails"]:
            if kw in xpb:
                techs.append(kw)

    body = hint.get("body", "").lower()
    body_hints = {
        "wordpress": ["wp-content", "wp-includes"],
        "joomla": ["joomla"],
        "drupal": ["drupal", "sites/default"],
        "phpbb": ["phpbb"],
        "discuz": ["discuz"],
        "typecho": ["typecho"],
        "vue.js": ["vue.js", "vue.min.js"],
        "react": ["react", "reactdom"],
        "jquery": ["jquery"],
        "vue": ["vue.js"],
        "bootstrap": ["bootstrap.min.css"],
        "tomcat": ["apache tomcat"],
        "weblogic": ["weblogic"],
        "jboss": ["jboss"],
        "nexus": ["nexus repository"],
        "jenkins": ["jenkins"],
        "grafana": ["grafana"],
        "kibana": ["kibana"],
        "elasticsearch": ["elasticsearch"],
        "solr": ["apache solr"],
        "spring boot": ["whitelabel error page"],
    }
    for tech, patterns in body_hints.items():
        for pat in patterns:
            if pat in body:
                techs.append(tech)
                break

    return ",".join(sorted(set(techs))) if techs else ""


def _build_targets(host: str, ports: list[int], schemes: list[str]) -> list[tuple[str, str, int]]:
    """生成 (url, host, port) 列表

    规则:只扫"看起来像 web" 的端口(80/443/8080/8443 等)
    """
    web_ports = {80, 443, 8080, 8443, 8000, 8008, 8888, 9000, 9090, 7001, 5601, 9200, 9300, 5984}
    targets = []
    for p in ports:
        if p not in web_ports and p not in COMMON_PORTS:
            continue
        # 推断 scheme
        for scheme in schemes:
            if scheme == "https" and p in (443, 8443, 5984):
                targets.append((f"{scheme}://{host}:{p}", host, p))
            elif scheme == "http" and p in (80, 8080, 8000, 8008, 8888, 9000, 9090, 7001, 5601, 9200, 9300):
                targets.append((f"{scheme}://{host}:{p}", host, p))
    # 去重
    seen = set()
    uniq = []
    for t in targets:
        if t[0] not in seen:
            seen.add(t[0])
            uniq.append(t)
    return uniq


async def probe(
    host: str,
    ports: list[int] | None = None,
    schemes: list[str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> AsyncIterator[dict]:
    """HTTP 探活

    Args:
        host: 目标 host(IP 或域名)
        ports: 已知开放端口列表(从 portscan 来的)
        schemes: ["http", "https"] 默认两个都试

    Yields:
        {url, host, port, scheme, status, title, server, tech, content_length}
    """
    schemes = schemes or ["http", "https"]
    ports = ports or [80, 443, 8080, 8443]
    targets = _build_targets(host, ports, schemes)
    if not targets:
        log.debug(f"httpx_probe: no web-like ports for {host}")
        return

    loop = asyncio.get_running_loop()
    pool = ThreadPoolExecutor(max_workers=concurrency)
    try:
        futures = {pool.submit(_do_request, url, timeout): (url, h, p)
                   for url, h, p in targets}
        for fut in asyncio.as_completed([asyncio.wrap_future(f) for f in futures]):
            # wrap_future 让事件循环在等待时能调度其他协程;
            # 旧的 await loop.run_in_executor(None, fut.result) 会阻塞整个
            # loop(实测冻结 2s+),gather 里其他模块全部停摆
            r = await fut
            url = r['url']
            _, h, p = next(t for t in targets if t[0] == url)
            if r.get("error") and not r.get("status"):
                # 网络错(无响应)
                continue
            # HTTP 错(4xx/5xx)也算"站点存活",保留
            body = r.get("body", "")
            title = _extract_title(body) if body else ""
            tech = _extract_tech(r)
            scheme = url.split("://")[0]
            yield {
                "url": url,
                "tls_verified": r.get("tls_verified"),
                "host": h,
                "port": p,
                "scheme": scheme,
                "status": r.get("status", 0),
                "title": title,
                "server": r.get("server", ""),
                "tech": tech,
                "content_length": r.get("content_length", 0),
                "content_type": r.get("content_type", ""),
            }
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
