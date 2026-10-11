"""Run provenance, field changes and watch attribution, entirely offline."""
import json
import asyncio
import errno
import tempfile
import unittest
from unittest.mock import patch
from arl_lite.db.storage import Storage
from arl_lite.core.watcher import Watcher, WatchTarget
from arl_lite.core.base_module import ModuleResult
from arl_lite.notify import WebhookConfig


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.storage = Storage("fixture", self.temp.name)
    def tearDown(self):
        self.storage.close(); self.temp.cleanup()
    def run_id(self, target="fixture.invalid"):
        return self.storage.create_task(self.storage.workspace_id, target)

    def test_source_and_run_provenance_preserved(self):
        one, two = self.run_id(), self.run_id()
        self.storage.add_domain(one, "a.fixture.invalid", "crtsh")
        self.storage.add_domain(two, "a.fixture.invalid", "rapiddns")
        first = self.storage.get_run_observations(one)[0]
        second = self.storage.get_run_observations(two)[0]
        self.assertEqual(first["asset_hash"], second["asset_hash"])
        self.assertEqual((first["source"], second["source"]), ("crtsh", "rapiddns"))
        self.assertEqual(len(self.storage.query("domains")), 1)

    def test_confirmed_empty_clears_and_unknown_does_not(self):
        one, two = self.run_id(), self.run_id()
        self.storage.add_site(one, "https://fixture.invalid", "fixture.invalid", "192.0.2.1", 443, "https", title="old", tech="old-tech")
        self.storage.add_site(two, "https://fixture.invalid", "fixture.invalid", None, 443, "https", title="", tech="")
        row = self.storage.query("sites")[0]
        self.assertEqual((row["title"], row["tech"], row["ip"]), ("", "", "192.0.2.1"))
        changes = self.storage.get_run_changes(two)
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["change_type"], "FIELDS_CHANGED")
        self.assertEqual(json.loads(changes[0]["before_value"])["title"], "old")
        self.assertEqual(json.loads(changes[0]["after_value"])["title"], "")
        self.assertNotIn("ip", json.loads(changes[0]["diff"]))

    def test_failed_measurement_unknown_never_disappeared(self):
        one, two, other = self.run_id(), self.run_id(), self.run_id("other.invalid")
        self.storage.add_domain(one, "a.fixture.invalid", "crtsh")
        self.storage.add_domain(other, "a.other.invalid", "crtsh")
        self.storage.record_source_status(two, "crtsh", False, error_type="timeout", error_message="fixture")
        observations = self.storage.get_run_observations(two)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["status"], "UNKNOWN")
        self.assertEqual(self.storage.get_run_changes(two), [])
        self.assertEqual(len(self.storage.query("domains")), 2)

    def test_watch_counts_ports_sites_and_excludes_another_run(self):
        async def runner_fixture(runner, target, modules):
            one = self.run_id(target)
            other = self.run_id("other.invalid")
            self.storage.add_finding(other, "other.invalid", "fixture", title="unrelated critical", severity="critical")
            self.storage.add_port(one, "192.0.2.1", 443)
            self.storage.add_site(one, "https://fixture.invalid", "fixture.invalid", None, 443, "https")
            self.storage.add_finding(one, "fixture.invalid", "fixture", title="own critical", severity="critical")
            return ModuleResult(True, target, 3, 0, metadata={"task_id": one})
        watch = Watcher(self.storage, WebhookConfig(provider="local"))
        wt = WatchTarget("fixture.invalid")
        with patch("arl_lite.core.task_runner.TaskRunner.run", runner_fixture), patch("arl_lite.notify.notify_task_done") as done, patch("arl_lite.notify.notify_critical_finding") as critical:
            watch._run_target(wt)
        self.assertEqual(wt.new_count, 3)
        self.assertEqual(done.call_args.kwargs["found"], 3)
        critical.assert_called_once()
        self.assertEqual(critical.call_args.args[1]["title"], "own critical")

    def test_partial_failure_keeps_this_runs_present_observations(self):
        one, two = self.run_id(), self.run_id()
        for name in ("a.fixture.invalid", "b.fixture.invalid"):
            self.storage.add_domain(one, name, "crtsh")
        self.storage.add_domain(two, "a.fixture.invalid", "crtsh")
        self.storage.record_source_status(two, "crtsh", False, error_type="parse", error_message="partial fixture")
        rows = self.storage.get_run_observations(two)
        self.assertEqual(sorted(row["status"] for row in rows), ["PRESENT", "UNKNOWN"])

    def test_closed_port_is_absent_and_timeout_does_not_reopen_or_close(self):
        one, two, three, four = [self.run_id() for _ in range(4)]
        self.storage.add_port(one, "192.0.2.1", 443, state="open")
        self.storage.record_port_unknown(two, "192.0.2.1", 443, "portscan", "timeout")
        self.assertEqual(self.storage.query("ports")[0]["state"], "open")
        self.assertEqual(self.storage.get_run_changes(two), [])
        self.storage.add_port(three, "192.0.2.1", 443, state="closed")
        self.assertEqual(self.storage.get_run_observations(three)[0]["status"], "ABSENT")
        self.assertEqual(self.storage.get_run_changes(three)[0]["change_type"], "DISAPPEARED")
        self.storage.add_port(four, "192.0.2.1", 443, state="open")
        self.assertEqual(self.storage.get_run_changes(four)[0]["change_type"], "REAPPEARED")

    def test_port_module_persists_real_negative_and_unknown_separately(self):
        from arl_lite.modules.recon.ports.portscan import PortscanModule
        one, two = self.run_id(), self.run_id()
        self.storage.add_port(one, "192.0.2.1", 443, state="open")
        self.storage.add_port(one, "192.0.2.1", 80, state="open")
        async def scanner(*args, **kwargs):
            self.assertTrue(kwargs["include_closed"])
            return [{"host": "192.0.2.1", "port": 443, "state": "closed", "service": "https"},
                    {"host": "192.0.2.1", "port": 80, "state": "unknown", "reason": "timeout"}], None, None
        module = PortscanModule(task_id=two, storage=self.storage)
        with patch("arl_lite.modules.recon.ports.portscan.scan", scanner), patch("arl_lite.modules.recon.ports.portscan.check_nmap", return_value=False):
            result = asyncio.run(module.run("192.0.2.1", prefer="python"))
        self.assertEqual(result.found, 0)
        self.assertEqual({r["port"]: r["state"] for r in self.storage.query("ports")}, {80: "open", 443: "closed"})
        self.assertEqual(sorted(o["status"] for o in self.storage.get_run_observations(two)), ["ABSENT", "UNKNOWN"])

    def test_probe_classifies_refused_as_negative_and_timeout_as_unknown(self):
        from arl_lite.integrations.portscan import _probe_tcp
        with patch("arl_lite.integrations.portscan.socket.socket") as factory:
            sock = factory.return_value.__enter__.return_value
            sock.connect_ex.return_value = errno.ECONNREFUSED
            self.assertEqual(_probe_tcp("192.0.2.1", 443, 1, True)["state"], "closed")
            self.assertIsNone(_probe_tcp("192.0.2.1", 443, 1))
            sock.connect_ex.return_value = errno.ETIMEDOUT
            self.assertEqual(_probe_tcp("192.0.2.1", 443, 1, True)["state"], "unknown")


if __name__ == "__main__": unittest.main()
