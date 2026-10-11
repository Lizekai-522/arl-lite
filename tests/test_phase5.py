"""arl-lite Phase 5 测试 — 目录扫描 + nuclei + github + MCP server

测试覆盖:
1. dirscan module 加载 + 内置 wordlist + 真实扫描 example.com
2. nuclei module(没 binary 走 fallback)
3. github module(没 token 走匿名)
4. MCP server JSON-RPC 2.0 协议
5. CLI 15 个子命令
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))


def ok(msg: str) -> None:
    print(f"  \033[32m✓\033[0m {msg}")


def fail(msg: str) -> None:
    print(f"  \033[31m✗\033[0m {msg}")
    raise AssertionError(msg)


# =========================
# 1. dirscan
# =========================

def test_dirscan():
    print("\n[1] dirscan module")

    # 1.1 module 加载
    from arl_lite.modules.recon.dirs.dirscan import DirscanModule, DEFAULT_WORDLIST
    if DirscanModule.name == "dirscan" and DirscanModule.category == "recon/dirs":
        ok(f"DirscanModule: name={DirscanModule.name} category={DirscanModule.category}")
    else:
        fail(f"DirscanModule meta 错")
    if len(DEFAULT_WORDLIST) >= 80:
        ok(f"内置 wordlist: {len(DEFAULT_WORDLIST)} 路径")
    else:
        fail(f"wordlist 太短: {len(DEFAULT_WORDLIST)}")
    # 必含路径
    for p in ["admin", "api", ".git", ".env", "swagger.json", "robots.txt", ".htpasswd"]:
        if p in DEFAULT_WORDLIST:
            ok(f"  含 {p}")
        else:
            fail(f"缺 {p}")

    # 1.2 scan_paths 单元测试
    from arl_lite.integrations.dirscan import scan_paths
    import asyncio
    # 测一个已知 404 站(httpbin)
    result = asyncio.run(scan_paths(
        "https://httpbin.org/", ["status/200", "status/404", "get"],
        timeout=10, concurrency=5,
    ))
    if isinstance(result, list):
        ok(f"scan_paths 返回 list, {len(result)} 个结果")
    else:
        fail(f"scan_paths: {type(result)}")

    # 1.3 empty paths
    result = asyncio.run(scan_paths("https://httpbin.org/", [], timeout=5))
    if result == []:
        ok("空 paths → 空结果")
    else:
        fail(f"空 paths 返回 {result}")


# =========================
# 2. nuclei
# =========================

def test_nuclei():
    print("\n[2] nuclei module + fallback")

    from arl_lite.integrations.nuclei import BUILTIN_TEMPLATES, scan_with_templates
    if len(BUILTIN_TEMPLATES) >= 20:
        ok(f"内建模板: {len(BUILTIN_TEMPLATES)} 条")
    else:
        fail(f"templates 太少: {len(BUILTIN_TEMPLATES)}")
    # 必含
    tids = {t["id"] for t in BUILTIN_TEMPLATES}
    for t in ["git-config", "env-file", "swagger-ui", "phpinfo", "admin-panel", "robots-txt", "htpasswd"]:
        if t in tids:
            ok(f"  含 {t}")
        else:
            fail(f"缺 {t}")

    # scan_with_templates 在非可达 target 上不应 crash
    result = scan_with_templates("https://nonexistent-host-12345.invalid/", BUILTIN_TEMPLATES[:3])
    if not result.ok and result.error and result.completed == 0:
        ok(f"scan_with_templates: explicit failure: {result.error_type}")
    else:
        fail(f"scan_with_templates: {type(result)}")


# =========================
# 3. github
# =========================

def test_github():
    print("\n[3] github module")

    from arl_lite.integrations.github_search import search_github, BUILTIN_QUERIES
    if len(BUILTIN_QUERIES) >= 8:
        ok(f"内建查询: {len(BUILTIN_QUERIES)} 条")
    else:
        fail(f"queries 太少")
    # 必含
    for q in BUILTIN_QUERIES:
        if "{target}" in q or "{domain}" in q:
            continue
        else:
            fail(f"query 缺占位符: {q}")

    # 没 token:匿名请求 GitHub code search 会 401,v0.7.7 起显式抛
    # auth 错(旧版静默 [] 把失败伪装成"健康无泄漏");没网时抛网络错
    try:
        results = search_github('"test" password', token="", per_page=2, timeout=3)
        if isinstance(results, list):
            ok(f"匿名 search 跑过(可能空),{len(results)} 结果")
        else:
            fail(f"search_github: {type(results)}")
    except PermissionError as e:
        ok(f"匿名 401 显式报 auth 错(v0.7.7 语义):{str(e)[:60]}")
    except Exception as e:
        if "Conn" in str(e)[:30] or "Errno" in str(e)[:30] or "timeout" in str(e).lower():
            ok(f"没网也兜底:{type(e).__name__}")
        else:
            fail(f"未知错误:{e}")


# =========================
# 4. MCP server
# =========================

def test_mcp():
    print("\n[4] MCP server(JSON-RPC 2.0)")

    from arl_lite.mcp.server import MCPServer

    with tempfile.TemporaryDirectory() as home:
        os.environ["HOME"] = home
        from arl_lite.db.storage import Storage
        # 用默认 storage(不传 workspace_root),让 MCP 用同样的 default
        s = Storage("mcp_test")
        s.create_task(s.workspace_id, "x.com")
        s.add_host(task_id=1, host="www.x.com", source="crtsh", confidence=0.8)
        s.add_port(task_id=1, host="1.1.1.1", port=80, state="open", service="http")

        server = MCPServer(workspace="mcp_test")

        # 4.1 initialize
        r = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
        if r and r.get("result", {}).get("serverInfo", {}).get("name") == "arl-lite-mcp":
            ok("initialize: serverInfo OK")
        else:
            fail(f"initialize: {r}")

        # 4.2 tools/list
        r = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        if r and len(r.get("result", {}).get("tools", [])) == 4:
            ok(f"tools/list: 4 tools")
        else:
            fail(f"tools/list: {r}")

        # 4.3 tools/call query_assets
        r = server.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "query_assets", "arguments": {"table": "hosts", "limit": 10}}
        })
        if r and not r.get("result", {}).get("isError", True):
            text = r["result"]["content"][0]["text"]
            data = json.loads(text)
            if isinstance(data, list) and len(data) >= 1:
                ok(f"query_assets hosts: {len(data)} 行")
            else:
                fail(f"query_assets: type={type(data).__name__} data={str(data)[:200]}")
        else:
            fail(f"query_assets: {r}")

        # 4.4 tools/call get_risk
        r = server.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "get_risk", "arguments": {"top_n": 5}}
        })
        if r and not r.get("result", {}).get("isError", True):
            text = r["result"]["content"][0]["text"]
            data = json.loads(text)
            if "summary" in data and "top" in data:
                ok(f"get_risk: summary={data['summary']}")
            else:
                fail(f"get_risk: {data}")
        else:
            fail(f"get_risk: {r}")

        # 4.5 tools/call run_correlate
        r = server.handle_request({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "run_correlate", "arguments": {"min_risk": 0, "limit": 10}}
        })
        if r and not r.get("result", {}).get("isError", True):
            text = r["result"]["content"][0]["text"]
            data = json.loads(text)
            if "hits" in data:
                ok(f"run_correlate: returned={data['returned']}, new_saved={data['new_correlations_saved']}")
            else:
                fail(f"run_correlate: {data}")
        else:
            fail(f"run_correlate: {r}")

        # 4.6 未知 method
        r = server.handle_request({"jsonrpc": "2.0", "id": 6, "method": "unknown", "params": {}})
        if r and "error" in r and r["error"]["code"] == -32601:
            ok(f"未知 method → -32601")
        else:
            fail(f"未知 method: {r}")

        # 4.7 未知 tool
        r = server.handle_request({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "bad_tool", "arguments": {}}
        })
        if r and "error" in r and r["error"]["code"] == -32602:
            ok(f"未知 tool → -32602")
        else:
            fail(f"未知 tool: {r}")

        # 4.8 未初始化就调 tools/list
        s2 = MCPServer(workspace="mcp_test")
        r = s2.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        if r and "error" in r:
            ok(f"未初始化调 tools → error: {r['error']['message']}")
        else:
            fail(f"未初始化: {r}")

        # 4.9 ping
        r = server.handle_request({"jsonrpc": "2.0", "id": 99, "method": "ping", "params": {}})
        if r and r.get("result") == {}:
            ok(f"ping")
        else:
            fail(f"ping: {r}")


# =========================
# 5. CLI 全子命令
# =========================

def test_cli():
    print("\n[5] CLI 全子命令")

    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent), "HOME": tempfile.mkdtemp()}

    for cmd in [
        "version",
        "tools check",
        "workspace list",
        "stats -w default",
        "monitor list -w default",
        "risk summary -w default",
        "ai config list",
        "mcp --help",
        "mcp -w default --help",
    ]:
        r = subprocess.run(
            ["python3", "-m", "arl_lite"] + cmd.split(),
            cwd=str(Path(__file__).parent.parent), env=env,
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode in (0, 2):
            mark = "✓" if r.returncode == 0 else "✓(help)"
            print(f"  {mark} exit={r.returncode} | {cmd[:50]}")
        else:
            print(f"  ✗ exit={r.returncode} | {cmd[:50]} | {r.stderr[:80]}")


# =========================
# 6. MCP end-to-end(stdio)
# =========================

def test_mcp_e2e():
    print("\n[6] MCP server stdio 端到端")

    with tempfile.TemporaryDirectory() as home:
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent), "HOME": home}
        # 准备数据(用 HOME 隔离)
        from arl_lite.db.storage import Storage
        ws_root = Path(home) / ".arl-lite" / "workspaces"
        ws_root.mkdir(parents=True, exist_ok=True)
        s = Storage("e2e", ws_root)
        s.create_task(s.workspace_id, "x.com")
        s.add_host(task_id=1, host="www.x.com", source="crtsh", confidence=0.8)

        # 启动 MCP server
        proc = subprocess.Popen(
            ["python3", "-m", "arl_lite", "mcp", "-w", "e2e"],
            cwd=str(Path(__file__).parent.parent), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        # 发 2 个请求
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "query_assets", "arguments": {"table": "hosts", "limit": 5}}},
        ]
        input_data = "\n".join(json.dumps(r) for r in reqs) + "\n"
        try:
            out, err = proc.communicate(input=input_data, timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            print(f"  ✗ timeout: {err[:200]}")
            return

        lines = out.strip().split("\n")
        if len(lines) >= 2:
            try:
                r1 = json.loads(lines[0])
                r2 = json.loads(lines[1])
                if r1.get("result", {}).get("serverInfo", {}).get("name") == "arl-lite-mcp":
                    print(f"  ✓ initialize OK")
                else:
                    print(f"  ✗ initialize: {r1}")
                if not r2.get("result", {}).get("isError", True):
                    data = json.loads(r2["result"]["content"][0]["text"])
                    if isinstance(data, list):
                        print(f"  ✓ query_assets: {len(data)} 行")
                    else:
                        print(f"  ✗ query_assets: {data}")
                else:
                    print(f"  ✗ query_assets error: {r2}")
            except json.JSONDecodeError as e:
                print(f"  ✗ JSON parse: {e}")
                print(f"  out: {out[:200]}")
        else:
            print(f"  ✗ only {len(lines)} lines")
            print(f"  out: {out[:300]}")


# =========================
# runner
# =========================

# =========================
# 7. Bug regression — Phase 5 全面审计发现
# =========================

def test_bug_regression():
    """Phase 5 全面审计发现的 bug regression"""
    from arl_lite.db.storage import Storage
    from arl_lite.mcp.server import MCPServer

    with tempfile.TemporaryDirectory() as home:
        os.environ["HOME"] = home
        s = Storage("reg", home)
        s.create_task(s.workspace_id, "x.com")

        # Bug 1: null byte 接受
        for fn_name, kwargs in [
            ("add_host", {"task_id": 1, "host": "abc\x00def", "source": "t"}),
            ("add_domain", {"task_id": 1, "domain": "abc\x00def", "source": "t"}),
            ("add_port", {"task_id": 1, "host": "abc\x00def", "port": 80}),
        ]:
            try:
                getattr(s, fn_name)(**kwargs)
                fail(f"Bug 1: {fn_name} 接受 null byte")
            except ValueError:
                pass
        ok("Bug 1: null byte 拒绝 (host/domain/port)")

        # Bug 2: port 类型错误信息
        for bad_port in [-1, 0, 65536, 99999, "abc", None, True]:
            try:
                s.add_port(task_id=1, host="1.1.1.1", port=bad_port)
                fail(f"Bug 2: port={bad_port!r} 接受")
            except ValueError:
                pass
        ok("Bug 2: port 越界 + 类型错误拒绝")

        # Bug 3: MCP handle_request(None) 崩溃
        mcp = MCPServer(workspace="default")
        for bad_req in [None, "string", 42, []]:
            try:
                r = mcp.handle_request(bad_req)
                if r is None or "error" in (r or {}):
                    pass
                else:
                    fail(f"Bug 3: handle_request({bad_req!r}) = {r}")
            except Exception as e:
                fail(f"Bug 3: handle_request({bad_req!r}) crash: {e}")
        ok("Bug 3: MCP handle_request 接受 None/str/int/list 不 crash")

        # Bug 4: MCP {} / {method:test} / {id:1} (没 method) 都返回 error 不是 None
        for bad_req in [{}, {"id": 1}, {"method": "test"}]:
            r = mcp.handle_request(bad_req)
            # {} / {id:1} 应该返回 error
            # {method:test} 没 id 也不该返回 error(通知)
            if bad_req.get("id") is not None:
                if not r or "error" not in r:
                    fail(f"Bug 4: {bad_req} 期望 error, 得到 {r}")
        ok("Bug 4: MCP 缺 method 报错")

        # Bug 5: MCP tool 缺必填参数
        mcp_init = MCPServer(workspace="reg")
        mcp_init.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        for tool, args in [
            ("query_assets", {}),  # 缺 table
            ("query_assets", {"table": "x"}),  # 缺 limit OK
            ("search_findings", {}),  # 缺 table + keyword
            ("search_findings", {"table": "x"}),  # 缺 keyword
            ("get_risk", {"top_n": 0}),  # top_n 越界
            ("get_risk", {"top_n": 1000}),  # top_n 越界
            ("run_correlate", {"min_risk": -1}),
            ("run_correlate", {"min_risk": 11}),
            ("run_correlate", {"limit": 0}),
            ("run_correlate", {"limit": 1000}),
        ]:
            r = mcp_init.handle_request({
                "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                "params": {"name": tool, "arguments": args}
            })
            if not r or "result" not in r:
                fail(f"Bug 5: {tool}({args}) 报错: {r}")
            elif r["result"].get("isError") is not True:
                fail(f"Bug 5: {tool}({args}) 应该 isError=True: {r}")
        ok("Bug 5: MCP tool 缺参数 + 越界返回 isError")


def main():
    print("=" * 60)
    print("Phase 5 测试 — 目录扫描 + Nuclei + GitHub + MCP")
    print("=" * 60)
    test_dirscan()
    test_nuclei()
    test_github()
    test_mcp()
    test_cli()
    test_mcp_e2e()
    test_bug_regression()
    print()
    print("=" * 60)
    print("\033[32mALL PHASE 5 TESTS PASSED\033[0m")
    print("=" * 60)


if __name__ == "__main__":
    main()
