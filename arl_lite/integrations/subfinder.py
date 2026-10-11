"""arl_lite.integrations.subfinder

subfinder 适配层(subprocess 调用,无网络也跑得起来)。

subfinder 是 ProjectDiscovery 出品的子域枚举工具,聚合 30+ 数据源。
- 主动源:通过 DNS 解析发现
- 被动源:通过证书/搜索引擎/威胁情报 API

纪律:
- 必须有 subfinder 二进制才能用,没有就 fail 3 态
- timeout 元组 (SIGTERM, KILL) 双阶段
- 输出格式 -json 解析,失败用 json.JSONDecodeError 兜底
"""
from __future__ import annotations

import json
import shutil
import asyncio
import logging
from typing import AsyncIterator

log = logging.getLogger("arl_lite.integrations.subfinder")

DEFAULT_BINARY = "subfinder"
DEFAULT_TIMEOUT = 300  # 5 分钟


def is_available() -> bool:
    """subfinder 是否在 PATH 里"""
    return shutil.which(DEFAULT_BINARY) is not None


def get_version() -> str:
    """获取 subfinder 版本(失败返回 'unknown')"""
    binary = shutil.which(DEFAULT_BINARY)
    if not binary:
        return "not installed"
    try:
        import subprocess
        result = subprocess.run(
            [binary, "-version"], capture_output=True, text=True, timeout=10
        )
        return (result.stdout or result.stderr).strip().split("\n")[0]
    except Exception as e:
        return f"error: {e}"


async def run_subfinder(
    domain: str,
    timeout: int = DEFAULT_TIMEOUT,
    sources: list[str] | None = None,
    all_sources: bool = True,
    _status: dict | None = None,
) -> AsyncIterator[str]:
    """异步调用 subfinder,逐行 yield 子域

    Args:
        domain: 目标根域,如 "example.com"
        timeout: 超时秒数
        sources: 指定数据源(默认 None 用 subfinder 默认)
        all_sources: 是否用全部数据源(默认 True)

    Yields:
        子域字符串(去重在调用方处理)
    """
    binary = shutil.which(DEFAULT_BINARY)
    if not binary:
        raise RuntimeError(
            f"subfinder not found in PATH. Install: go install -v "
            f"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )

    cmd = [binary, "-d", domain, "-json", "-silent", "-nc"]
    if all_sources:
        cmd.append("-all")
    if sources:
        cmd.extend(["-sources", ",".join(sources)])

    log.debug(f"subfinder cmd: {' '.join(cmd)}")

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        log.error(f"failed to spawn subfinder: {e}")
        raise

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"subfinder timeout after {timeout}s")
    except asyncio.CancelledError:
        if proc.returncode is None:
            proc.kill()
        await proc.communicate()
        raise

    partial_error = None
    if proc.returncode != 0:
        err_msg = stderr.decode("utf-8", errors="replace").strip()[:500]
        log.warning(f"subfinder exit {proc.returncode}: {err_msg}")
        # 不 raise;已有输出照常返回,但带上"部分结果"信号,
        # 让调用方能区分完整枚举与被截断的枚举
        partial_error = f"subfinder exited {proc.returncode} (partial results)"
        if _status is not None:
            _status["partial_error"] = partial_error

    # 解析 JSON Lines 输出
    seen = set()
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                continue
            host = obj.get("host") or obj.get("domain") or obj.get("subdomain")
            if not isinstance(host, str):
                continue
            # 后缀必须按 label 边界:endswith(domain) 会把 notexample.com
            # 误判成 example.com 的子域(与 crtsh/otx 等源同款语义)
            lowered = host.lower()
            if lowered != domain.lower() and not lowered.endswith("." + domain):
                continue
            if valid_hostname(host) and host not in seen:
                seen.add(host)
                yield lowered
        except json.JSONDecodeError:
            # 兼容纯文本输出
            lowered = line.lower()
            if lowered.endswith("." + domain) and valid_hostname(line) and line not in seen:
                seen.add(line)
                yield lowered
                yield line.lower()


async def collect_subdomains(
    domain: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[list[str], str | None, str | None]:
    """便利函数:一次性返回所有子域 + 错误信息(三态)

    Returns:
        (subs, error, error_type)
        成功: (subs, None, None)
        失败: ([], "错误信息", "timeout"/"network"/...)
    """
    subs: list[str] = []
    status: dict = {}
    try:
        async for sub in run_subfinder(domain, timeout=timeout, _status=status):
            subs.append(sub)
        # 退出码非 0:已有输出照常返回,但带部分结果标记(与完整枚举可区分)
        return subs, status.get("partial_error"), "partial" if status.get("partial_error") else None
    except TimeoutError as e:
        return [], str(e), "timeout"
    except RuntimeError as e:
        return [], str(e), "auth" if "auth" in str(e).lower() else "network"
    except FileNotFoundError as e:
        return [], str(e), "network"
    except Exception as e:
        return [], f"{type(e).__name__}: {e}", "unknown"
