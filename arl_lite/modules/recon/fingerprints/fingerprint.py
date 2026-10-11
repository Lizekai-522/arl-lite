"""arl_lite.modules.recon.fingerprints.fingerprint

指纹识别模块:对 HTTP 响应跑指纹库(内置规则 + ARL webapp 指纹库,共 2000+ 条)。

输入:target(域名或 URL),模块直接抓取 target 的 HTTP 响应来匹配
     (不走 sites 表——httpx_probe 探测过的 http/https 站点在这里会被
     重新以 http 抓一次;https 站点的指纹以 Server/X-Powered-By 头为准)
输出:finding 入库

典型用法:
  run -t example.com -m portscan,httpx_probe,fingerprint

指纹库来源:
- fingerprints.json      内置手工规则
- fingerprints_arl.json  从 ARL(灯塔)app/dicts/webapp.json 转换(MIT)
"""
from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
import urllib.request
import urllib.error
from pathlib import Path

from ....core.base_module import BaseModule, ModuleResult
from ....core.fingerprint_engine import load_fingerprints, match_all
from ....integrations.httpx_probe import _ssl_context

log = logging.getLogger("arl_lite.modules.fingerprint")

DEFAULT_TIMEOUT = 10


def _fingerprint_dir() -> Path:
    """指纹目录:包内优先,退路是相对当前工作目录"""
    d = Path(__file__).parent.parent.parent.parent / "fingerprints"
    if d.exists():
        return d
    return Path("arl_lite/fingerprints")


def load_all_fingerprints() -> list[dict]:
    """加载指纹目录下全部 *.json(内置 + ARL 库),按 name 去重(先加载的优先)"""
    seen: set[str] = set()
    all_fps: list[dict] = []
    for f in sorted(_fingerprint_dir().glob("*.json")):
        for fp in load_fingerprints(f):
            key = str(fp.get("name", "")).strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            all_fps.append(fp)
    return all_fps


class FingerprintModule(BaseModule):
    name = "fingerprint"
    category = "recon/fingerprints"
    description = "对 HTTP 响应跑指纹库(内置 + ARL 库 2000+ 条,CMS/框架/设备识别)"
    input_type = "site"
    output_type = "finding"
    required_tools = []
    author = "arl-lite"
    version = "0.7.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 加载指纹(只加载一次,实例内缓存)
        self.fingerprints = load_all_fingerprints()

    async def run(self, target: str, **kwargs) -> ModuleResult:
        start = time.time()
        timeout = int(kwargs.get("timeout", DEFAULT_TIMEOUT))
        # target 是 URL 或 host[:port]
        url = target if target.startswith("http") else f"http://{target}"

        # 1. 拉响应(裸 host 默认 http;网络级失败再试 https,
        # 否则纯 https 站点会漏检)
        def _is_cert_error(e: Exception) -> bool:
            if isinstance(e, ssl.SSLCertVerificationError):
                return True
            return isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError)

        def _fetch_once(target_url: str):
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; arl-lite)"},
            )

            def _fetch():
                # 默认校验证书,自签/过期再降级重试(与 httpx_probe 同策略)
                try:
                    return urllib.request.urlopen(
                        req, timeout=timeout, context=_ssl_context(verify=True))
                except Exception as e:
                    if target_url.startswith("https://") and _is_cert_error(e):
                        return urllib.request.urlopen(
                            req, timeout=timeout, context=_ssl_context(verify=False))
                    raise

            return asyncio.get_running_loop().run_in_executor(None, _fetch)

        try:
            try:
                resp = await _fetch_once(url)
                if url.startswith("http://") and not hasattr(resp, "status"):
                    raise RuntimeError("no http response")
            except (urllib.error.URLError, OSError, RuntimeError) as e:
                # http 打不通(连接拒绝/非 HTTP 服务)→ 试 https;
                # HTTPError(4xx/5xx)说明 http 本身通,不重试
                if not url.startswith("http://") or isinstance(e, urllib.error.HTTPError):
                    raise
                alt = "https://" + url[len("http://"):]
                try:
                    resp = await _fetch_once(alt)
                    url = alt
                except (urllib.error.URLError, OSError):
                    raise e  # 两个 scheme 都失败,抛原始错误

            body = (await asyncio.to_thread(resp.read, 200 * 1024)).decode("utf-8", errors="ignore")
            status = resp.status
            headers = {k: v for k, v in resp.headers.items()}
            resp.close()
        except urllib.error.HTTPError as e:
            # 4xx/5xx 也保留响应(404 也有 server header)
            try:
                body = (await asyncio.to_thread(e.read, 200 * 1024)).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            status = e.code
            headers = {k: v for k, v in (e.headers or {}).items()}
        except Exception as e:
            return ModuleResult(
                success=False, target=target, found=0,
                duration_seconds=time.time() - start,
                sources=[self.make_source_result(
                    data=[], source=self.name, start_time=start,
                    error=f"{type(e).__name__}: {e}", error_type="network"
                )],
                errors=[f"{type(e).__name__}: {e}"],
            )

        # 2. 提取 title
        title_m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        title = title_m.group(1).strip() if title_m else ""

        # 3. 跑指纹
        hits = match_all(
            self.fingerprints, headers=headers, body=body, title=title, status=status
        )

        # 4. 入库 findings
        for hit in hits:
            self.storage.add_finding(
                task_id=self.task_id,
                target=url,
                finding_type="fingerprint",
                title=hit["name"],
                description=f"category={hit['category']}, rule={hit['rule']}",
                target_type="site",
                severity="info",
                source=self.name,
                confidence=80,
            )

        sr = self.make_source_result(
            data=hits, source=self.name, start_time=start,
        )

        return ModuleResult(
            success=sr.ok, target=target, found=len(hits),
            duration_seconds=time.time() - start,
            sources=[sr], errors=[],
            metadata={"url": url, "status": status, "fingerprints_loaded": len(self.fingerprints)}
        )

    def _host_from_url(self, url: str) -> str:
        try:
            from urllib.parse import urlparse
            u = urlparse(url)
            return u.hostname or ""
        except Exception:
            return ""
