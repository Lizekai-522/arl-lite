"""Local-only source outcome regressions; no scanner or network calls."""
import asyncio
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from arl_lite.core.base_module import BaseModule, ModuleResult, SourceResult
from arl_lite.core.task_runner import TaskRunner
from arl_lite.db.storage import Storage
from arl_lite.integrations.nuclei import run_nuclei, scan_with_templates, BUILTIN_TEMPLATES
from arl_lite.modules.recon.dirs.nuclei import NucleiModule
from arl_lite.modules.recon.sites.httpx_probe import HttpxProbeModule


class Healthy(BaseModule):
    name, category = "healthy_fixture", "fixture"
    async def run(self, target):
        return ModuleResult(True, target, 0, 0, [SourceResult(True, source=self.name)])


class Crashed(Healthy):
    name = "crashed_fixture"
    async def run(self, target):
        raise RuntimeError("fixture storage failure")


class SourceTests(unittest.TestCase):
    def test_nuclei_success_empty_and_timeout_are_distinct(self):
        with patch("arl_lite.integrations.nuclei.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")):
            result = run_nuclei("fixture.invalid")
            self.assertTrue(result.ok)
            self.assertEqual(result.data, [])
        with patch("arl_lite.integrations.nuclei.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture", 1)):
            result = run_nuclei("fixture.invalid")
            self.assertFalse(result.ok)
            self.assertEqual(result.error_type, "timeout")

    def test_partial_output_with_nonzero_exit_keeps_evidence_and_error(self):
        record = {"matched-at": "https://fixture.invalid/a", "template-id": "fixture", "info": {"name": "Fixture", "severity": "high"}}
        with patch("arl_lite.integrations.nuclei.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout=json.dumps(record), stderr="failed")):
            result = run_nuclei("fixture.invalid")
        self.assertFalse(result.ok)
        self.assertEqual(result.data[0]["severity"], "high")
        self.assertEqual(result.data[0]["matched_at"], record["matched-at"])

    def test_fallback_records_incomplete_coverage(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError("fixture timeout")):
            result = scan_with_templates("https://fixture.invalid", BUILTIN_TEMPLATES[:2])
        self.assertFalse(result.ok)
        self.assertEqual((result.attempted, result.completed), (2, 0))

    def test_crash_is_counted_with_healthy_source(self):
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("fixture", root)
            with patch("arl_lite.core.task_runner.discover_modules", return_value={Healthy.name: Healthy, Crashed.name: Crashed}):
                out = asyncio.run(TaskRunner(storage, storage.workspace_id).run("fixture.invalid", [Healthy.name, Crashed.name]))
            task = storage.query("tasks")[0]
            self.assertEqual((task["status"], task["sources_ok"], task["sources_failed"]), ("DONE_PARTIAL", 1, 1))
            self.assertEqual(len(storage.query("source_status")), 2)
            self.assertFalse(out.success)
            storage.close()

    def test_module_keeps_timeout_and_http_error_contract(self):
        async def failed_probe(*args, **kwargs):
            yield {"url": "https://fixture.invalid", "status": 0, "error": "timeout"}
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("fixture", root)
            with patch("arl_lite.modules.recon.dirs.nuclei.shutil.which", return_value="fixture"), patch("arl_lite.integrations.nuclei.subprocess.run", side_effect=subprocess.TimeoutExpired("fixture", 1)):
                result = asyncio.run(NucleiModule(storage=storage).run("fixture.invalid"))
            self.assertFalse(result.sources[0].ok)
            self.assertEqual(result.sources[0].error_type, "timeout")
            with patch("arl_lite.modules.recon.sites.httpx_probe.probe", failed_probe):
                result = asyncio.run(HttpxProbeModule(storage=storage).run("fixture.invalid"))
            self.assertFalse(result.sources[0].ok)
            storage.close()


if __name__ == "__main__":
    unittest.main()
