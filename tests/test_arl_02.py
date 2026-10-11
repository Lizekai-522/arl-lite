"""Offline cancellation/concurrency contracts; child process is local Python."""
import asyncio
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from arl_lite.core.base_module import BaseModule, ModuleResult
from arl_lite.core.task_runner import TaskRunner
from arl_lite.core.process import run_process
from arl_lite.db.storage import Storage
from arl_lite.integrations.portscan import scan_tcp
from arl_lite.integrations.httpx_probe import probe


class Slow(BaseModule):
    name, category = "slow_fixture", "fixture"
    entered = None
    torn_down = False
    async def run(self, target):
        self.entered.set()
        await asyncio.sleep(60)
        return ModuleResult(True, target, 0, 0)
    async def teardown(self):
        type(self).torn_down = True


class SetupCrash(Slow):
    name = "setup_crash_fixture"
    def __init__(self, **kwargs):
        raise RuntimeError("fixture constructor")


class ExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_thread_waits_do_not_block_other_coroutines(self):
        ticks = []
        async def heartbeat():
            await asyncio.sleep(0.02)
            ticks.append(time.monotonic())
        def tcp(*args):
            time.sleep(0.15)
            return None
        def http(url, timeout):
            time.sleep(0.15)
            return {"url": url, "status": 200, "body": ""}
        async def consume(stream):
            return [item async for item in stream]
        for target, stub, stream in [
            ("arl_lite.integrations.portscan._probe_tcp", tcp, scan_tcp("fixture", [80])),
            ("arl_lite.integrations.httpx_probe._do_request", http, probe("fixture", [80], ["http"])),
        ]:
            ticks.clear()
            with patch(target, stub):
                started = time.monotonic()
                await asyncio.gather(consume(stream), heartbeat())
            self.assertLess(ticks[0] - started, 0.12)

    async def test_stop_finalizes_and_tears_down(self):
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("fixture", root)
            runner = TaskRunner(storage, storage.workspace_id)
            Slow.entered, Slow.torn_down = asyncio.Event(), False
            with patch("arl_lite.core.task_runner.discover_modules", return_value={Slow.name: Slow}):
                task = asyncio.create_task(runner.run("fixture", [Slow.name]))
                await Slow.entered.wait()
                runner.request_stop_all()
                await asyncio.wait_for(task, 1)
            self.assertEqual(storage.query("tasks")[0]["status"], "STOPPED")
            self.assertEqual(storage.query("source_status")[0]["error_type"], "cancelled")
            self.assertTrue(Slow.torn_down)
            self.assertEqual(runner.current_task_id, 0)
            storage.close()

    async def test_constructor_failure_cannot_leave_running_task(self):
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("fixture", root)
            with patch("arl_lite.core.task_runner.discover_modules", return_value={SetupCrash.name: SetupCrash}):
                with self.assertRaises(RuntimeError):
                    await TaskRunner(storage, storage.workspace_id).run("fixture", [SetupCrash.name])
            row = storage.query("tasks")[0]
            self.assertEqual(row["status"], "FAILED")
            self.assertTrue(row["finished_at"])
            storage.close()

    async def test_cancel_kills_local_child(self):
        processes = []
        original = asyncio.create_subprocess_exec
        async def record(*args, **kwargs):
            proc = await original(*args, **kwargs)
            processes.append(proc)
            return proc
        with patch("asyncio.create_subprocess_exec", record):
            task = asyncio.create_task(run_process([sys.executable, "-c", "import time; time.sleep(60)"], 120))
            while not processes:
                await asyncio.sleep(0.01)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
        self.assertIsNotNone(processes[0].returncode)


class ExitTests(unittest.TestCase):
    def test_stopped_cli_returns_130_even_with_successful_source(self):
        from arl_lite.cli import cmd_run
        from arl_lite.core.base_module import SourceResult
        async def result(*args, **kwargs):
            return ModuleResult(True, "fixture", 0, 0, [SourceResult(True, source="fixture")])
        shutdown = SimpleNamespace(install=lambda: None, shutdown_requested=True)
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("fixture", root)
            with patch("arl_lite.cli.Storage", return_value=storage), patch("arl_lite.cli.GracefulShutdown", return_value=shutdown), patch.object(TaskRunner, "run", result):
                self.assertEqual(cmd_run(SimpleNamespace(target="fixture", workspace="fixture", modules=None, preset=None)), 130)
            storage.close()


if __name__ == "__main__":
    unittest.main()
