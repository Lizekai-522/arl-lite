"""CLI watch state and persistent notification wiring, without network."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from arl_lite.cli import build_parser, cmd_watch_start, _load_webhook
from arl_lite.db.storage import Storage
from arl_lite.core.watcher import Watcher, WatchTarget
from arl_lite.core.base_module import ModuleResult


class WatchConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.parser = build_parser()
        self.storages = []
        def tracked_storage(*args, **kwargs):
            storage = Storage(*args, **kwargs)
            self.storages.append(storage)
            return storage
        self.patches = [patch("arl_lite.db.storage.get_default_workspace_root", return_value=self.root),
                        patch("arl_lite.cli.get_default_workspace_root", return_value=self.root),
                        patch("arl_lite.cli.GracefulShutdown.install"),
                        patch("arl_lite.cli.Storage", tracked_storage)]
        for p in self.patches: p.start()
    def tearDown(self):
        for storage in self.storages: storage.close()
        for p in self.patches: p.stop()
        self.temp.cleanup()
    def run_command(self, args):
        parsed = self.parser.parse_args(args)
        return parsed.func(parsed)

    def test_workspace_lists_and_persistent_webhook_are_independent(self):
        for name in ["one", "two"]:
            self.assertEqual(self.run_command(["watch", "add", "fixture.invalid", "-w", name, "--modules", "dns"]), 0)
        self.assertEqual(self.run_command(["notify", "set", "-w", "one", "--provider", "local"]), 0)
        one, two = Storage("one", self.root), Storage("two", self.root)
        self.assertEqual(_load_webhook(one).provider, "local")
        self.assertIsNone(_load_webhook(two))
        self.assertEqual(self.run_command(["watch", "remove", "fixture.invalid", "-w", "one"]), 0)
        self.assertEqual(json.loads((one.workspace_dir / "watch.json").read_text()), [])
        self.assertEqual(len(json.loads((two.workspace_dir / "watch.json").read_text())), 1)
        one.close(); two.close()

    def test_start_loads_notification_configuration_and_critical_event(self):
        self.run_command(["watch", "add", "fixture.invalid", "-w", "one", "--modules", "dns"])
        self.run_command(["notify", "set", "-w", "one", "--provider", "local", "--min-severity", "critical"])
        class InlineWatcher(Watcher):
            def start(self):
                self._run_target(self.list()[0])
            def is_running(self): return False
            def stop(self, timeout=5): pass
        async def fixture(runner, target, modules):
            runner.storage.add_finding(1, "fixture.invalid", "fixture", title="critical fixture", severity="critical")
            return ModuleResult(True, target, 1, 0)
        with patch("arl_lite.core.watcher.Watcher", InlineWatcher), patch("arl_lite.core.task_runner.TaskRunner.run", fixture), patch("arl_lite.notify.notify_task_done"), patch("arl_lite.notify.notify_critical_finding") as critical:
            args = self.parser.parse_args(["watch", "start", "-w", "one"])
            self.assertEqual(cmd_watch_start(args), 0)
            critical.assert_called_once()
            self.assertEqual(critical.call_args.args[0].min_severity, "critical")
            self.assertEqual(critical.call_args.args[1]["title"], "critical fixture")


if __name__ == "__main__": unittest.main()
