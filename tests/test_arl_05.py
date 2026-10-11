"""Offline correlation identity/lifecycle regressions against real SQLite."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from arl_lite.core.correlation_engine import (
    CorrelationEvaluation, CorrelationHit, Rule, RuleAction, _parse_yaml,
    load_all_rules, run_all_rules, run_rule, save_correlations,
)
from arl_lite.core.risk_score import compute_asset_risks, risk_summary
from arl_lite.db.storage import DEFAULT_SCHEMA, Storage


class CorrelationLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.storage = Storage("first", self.temp.name)
        self.task = self.storage.create_task(self.storage.workspace_id, "192.0.2.1")
        self.rule = Rule("ports", "open ports", 6,
                         collect=[RuleAction("ports", "state='open'")])

    def tearDown(self):
        self.storage.close()
        self.temp.cleanup()

    def ports(self):
        for port in (23, 445, 6379):
            self.storage.add_port(self.task, "192.0.2.1", port)

    def evaluate(self, rule=None):
        result = run_all_rules(self.storage, rules_override=[rule or self.rule])
        save_correlations(self.storage, result)
        return result

    def test_three_ports_and_protocol_and_url_identity(self):
        self.ports()
        result = self.evaluate()
        self.assertIsInstance(result, list)
        self.assertEqual(result.successful_rules, {"ports"})
        rows = self.storage.query("correlations")
        self.assertEqual({r["target"] for r in rows},
                         {f"tcp://192.0.2.1:{p}" for p in (23, 445, 6379)})
        self.assertEqual({json.loads(r["evidence"])[0]["port"] for r in rows}, {23, 445, 6379})
        self.assertEqual(len(compute_asset_risks(self.storage)), 3)
        # Correlation identity distinguishes protocol even when imported asset
        # rows have their own independent hashes.
        save_correlations(self.storage, [CorrelationHit("ports", 6,
            {"ip": "192.0.2.1", "port": 23, "protocol": "udp"}, "udp")])
        self.assertEqual(len(self.storage.query("correlations")), 4)
        for url in ("http://a.example/", "http://b.example/login"):
            self.storage.add_site(self.task, url, "example", "192.0.2.1", 80, "http")
        sites = Rule("sites", "", 8, collect=[RuleAction("sites", "1=1")])
        self.evaluate(sites)
        self.assertEqual({r["target"] for r in self.storage.query("correlations", "rule_name='sites'")},
                         {"http://a.example/", "http://b.example/login"})

    def test_successful_empty_resolves_and_retains_history(self):
        self.ports()
        first = self.evaluate()
        with self.storage._conn() as conn:
            conn.execute("UPDATE ports SET state='closed'")
        second = self.evaluate()
        self.assertEqual(second, [])
        self.assertEqual(second.successful_rules, {"ports"})
        self.assertNotEqual(first.evaluated_run, second.evaluated_run)
        rows = self.storage.query("correlations")
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r["status"] == "resolved" for r in rows))
        self.assertTrue(all(r["resolved_run"] == second.evaluated_run for r in rows))
        self.assertEqual(compute_asset_risks(self.storage), [])
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 0)
        history = self.storage.query("correlation_history")
        self.assertEqual(len(history), 6)
        self.assertEqual({r["status"] for r in history}, {"active", "resolved"})
        self.assertTrue(all(json.loads(r["snapshot"])["evidence"] for r in history))

    def test_recurrence_keeps_prior_evidence_and_is_idempotent(self):
        self.ports()
        first = self.evaluate()
        save_correlations(self.storage, first)
        self.assertEqual(len(self.storage.query("correlation_history")), 3)
        with self.storage._conn() as conn:
            conn.execute("UPDATE ports SET state='closed'")
        self.evaluate()
        self.storage.add_port(self.task, "192.0.2.1", 23, banner="new evidence")
        self.evaluate()
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 1)
        snapshots = [json.loads(r["snapshot"]) for r in self.storage.query("correlation_history")
                     if r["target"] == "tcp://192.0.2.1:23" and r["status"] == "active"]
        self.assertEqual(len(snapshots), 2)
        self.assertEqual({json.loads(s["evidence"])[0]["banner"] for s in snapshots}, {None, "new evidence"})

    def test_failure_paths_and_incomplete_rules_do_not_clear(self):
        self.ports()
        self.evaluate()
        cases = [
            Rule("ports", "", 6, collect=[RuleAction("ports", "missing_column=1")]),
            Rule("ports", "", 6, collect=[RuleAction("other", "1=1")]),
            Rule("ports", "", 6, collect=[RuleAction("ports", "1=1; DROP TABLE ports")]),
            Rule("ports", "", 6, collect=self.rule.collect,
                 cross_ref=[RuleAction("sites", "missing_column=1")]),
            Rule("ports", "", 6, collect=self.rule.collect,
                 exclusion=[RuleAction("sites", "missing_column=1")]),
            _parse_yaml("name: ports\ncollect:\n  - table: ports\n    where: 1=1\nexclusion:\n  - table: sites\n"),
            Rule("ports", "", 6, collect=self.rule.collect, identity="unknown"),
        ]
        for rule in cases:
            with self.subTest(rule=rule):
                result = self.evaluate(rule)
                self.assertIn("ports", result.failed_rules)
                self.assertNotIn("ports", result.successful_rules)
                self.assertEqual(result, [])
                self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)

    def test_empty_collect_still_validates_cross_reference_sql(self):
        self.ports()
        self.evaluate()
        rule = Rule("ports", "", 6, collect=[RuleAction("ports", "port=9999")],
                    cross_ref=[RuleAction("sites", "missing_column=1")])
        result = self.evaluate(rule)
        self.assertIn("ports", result.failed_rules)
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)
        rule.cross_ref = [RuleAction("sites", "ip=ports.ip")]
        result = self.evaluate(rule)
        self.assertEqual(result.successful_rules, {"ports"})
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 0)

    def test_truncated_collect_retains_prior_risk(self):
        self.ports()
        self.evaluate()
        with self.storage._conn() as conn:
            conn.executemany("""INSERT INTO ports (workspace_id, ip, port, hash)
                                VALUES (?, '192.0.2.2', ?, ?)""",
                             [(self.storage.workspace_id, n, f"bulk-{n}") for n in range(1, 1002)])
        result = self.evaluate()
        self.assertIn("1000-row", result.failed_rules["ports"])
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)

    def test_explicit_host_aggregation_preserves_all_matches(self):
        self.ports()
        self.rule.identity = "host"
        self.evaluate()
        rows = self.storage.query("correlations")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["matched_count"], 3)
        self.assertEqual({a["port"] for a in json.loads(rows[0]["matched_assets"])}, {23, 445, 6379})
        parsed = _parse_yaml("name: custom\nidentity: host\ncollect:\n  - table: ports\n    where: 1=1\n")
        self.assertEqual(parsed.identity, "host")

    def test_workspace_isolation_and_plain_list_conservative_save(self):
        self.ports()
        result = self.evaluate()
        save_correlations(self.storage, [])
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)
        # Same SQLite file, different registered workspace: rule closures must
        # use workspace_id, not merely a separate database path.
        with self.storage._conn() as conn:
            conn.execute("INSERT INTO workspaces (name) VALUES ('other')")
            other_id = conn.execute("SELECT id FROM workspaces WHERE name='other'").fetchone()[0]
            conn.execute("""INSERT INTO correlations (workspace_id, rule_name, target, risk)
                            VALUES (?, 'ports', 'other-host', 9)""", (other_id,))
            conn.execute("UPDATE ports SET state='closed'")
        self.evaluate()
        self.assertEqual(self.storage.query("correlations", workspace_id=other_id)[0]["status"], "active")
        other = Storage("second", self.temp.name)
        try:
            with self.assertRaisesRegex(ValueError, "another workspace"):
                save_correlations(other, result)
            self.assertEqual(other.query("correlations"), [])
        finally:
            other.close()

    def test_save_failure_rolls_back_hits_and_resolution(self):
        self.ports()
        self.evaluate()
        prior_history = self.storage.query("correlation_history")
        with self.storage._conn() as conn:
            conn.execute("""CREATE TRIGGER fail_corr BEFORE INSERT ON correlations
                            WHEN NEW.target='tcp://192.0.2.1:445'
                            BEGIN SELECT RAISE(ABORT, 'forced save failure'); END""")
        result = run_rule(self.rule, self.storage)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced save failure"):
            save_correlations(self.storage, result)
        self.assertEqual(self.storage.query("correlation_history"), prior_history)
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)

    def test_other_rule_not_evaluated_is_not_resolved(self):
        self.ports()
        save_correlations(self.storage, [CorrelationHit("unrelated", 9, {"ip": "192.0.2.9"}, "old")])
        self.evaluate()
        with self.storage._conn() as conn:
            conn.execute("UPDATE ports SET state='closed'")
        self.evaluate()
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 1)
        self.assertEqual(compute_asset_risks(self.storage)[0].rule_names, ["unrelated"])

    def test_mixed_rule_success_and_failure_resolve_independently(self):
        self.ports()
        self.evaluate()
        other = Rule("other", "", 9, collect=self.rule.collect)
        self.evaluate(other)
        with self.storage._conn() as conn:
            conn.execute("UPDATE ports SET state='closed'")
        broken = Rule("other", "", 9, collect=[RuleAction("ports", "invalid_column=1")])
        result = run_all_rules(self.storage, rules_override=[self.rule, broken])
        self.assertEqual(result.successful_rules, {"ports"})
        self.assertEqual(set(result.failed_rules), {"other"})
        save_correlations(self.storage, result)
        self.assertEqual(risk_summary(self.storage)["total_correlations"], 3)
        self.assertEqual({r["rule_name"] for r in self.storage.query("correlations", "status='active'")}, {"other"})

    def test_count_rule_exclusion_failure_does_not_bypass_lifecycle(self):
        self.ports()
        aggregate = Rule("aggregate", "", 8, count_min=2,
                         collect=self.rule.collect, exclusion=[RuleAction("sites", "missing=1")])
        result = self.evaluate(aggregate)
        self.assertIn("aggregate", result.failed_rules)
        aggregate.exclusion = []
        self.evaluate(aggregate)
        row = self.storage.query("correlations")[0]
        self.assertEqual(row["matched_count"], 3)
        self.assertEqual(len(json.loads(row["evidence"])), 3)

    def test_bundled_rules_load_with_identity(self):
        rules = load_all_rules(Path(__file__).parents[1] / "arl_lite/modules/analysis/rules")
        self.assertGreaterEqual(len(rules), 30)
        self.assertEqual(next(r for r in rules if r.name == "port_high_risk").identity, "port")

    def test_same_hash_across_asset_tables_retains_both_matches(self):
        self.storage.add_domain(self.task, "same.example", "fixture")
        self.storage.add_host(self.task, "same.example")
        self.assertEqual(self.storage.query("domains")[0]["hash"],
                         self.storage.query("hosts")[0]["hash"])
        rule = Rule("mixed", "", 5, collect=[RuleAction("domains", "1=1"),
                                              RuleAction("hosts", "1=1"),
                                              RuleAction("domains", "1=1")])
        result = self.evaluate(rule)
        self.assertEqual(len(result), 2)
        row = self.storage.query("correlations")[0]
        self.assertEqual(row["matched_count"], 2)
        evidence = json.loads(row["matched_assets"])
        self.assertEqual(len(evidence), 2)
        self.assertTrue(any("domain" in asset for asset in evidence))
        self.assertTrue(any("host" in asset for asset in evidence))


class LegacyMigrationTests(unittest.TestCase):
    def test_existing_unique_index_does_not_skip_lifecycle_migration(self):
        for duplicated in (False, True):
            with self.subTest(duplicated=duplicated), tempfile.TemporaryDirectory() as td:
                directory = Path(td) / "old"
                directory.mkdir()
                conn = sqlite3.connect(directory / "data.db")
                schema = DEFAULT_SCHEMA.read_text(encoding="utf-8")
                # Start from the complete previous schema, excluding new fields.
                start = schema.index("-- Append-only evidence snapshots")
                end = schema.index("-- ----------------------------------------------------------------------------", start)
                schema = schema[:start] + schema[end:]
                for line in schema.splitlines():
                    if any(key in line for key in ("status TEXT NOT NULL", "evaluated_run TEXT", "resolved_run TEXT", "resolved_at TIMESTAMP")):
                        schema = schema.replace(line + "\n", "")
                if duplicated:
                    before, corr = schema.split("CREATE TABLE IF NOT EXISTS correlations (", 1)
                    corr = corr.replace("    UNIQUE(workspace_id, rule_name, target),\n", "", 1)
                    schema = before + "CREATE TABLE IF NOT EXISTS correlations (" + corr
                conn.executescript(schema)
                conn.execute("INSERT INTO workspaces (name) VALUES ('old')")
                conn.execute("""INSERT INTO correlations (workspace_id, rule_name, target, risk, evidence)
                                VALUES (1, 'ports', '192.0.2.1', 6, 'legacy evidence')""")
                if duplicated:
                    conn.execute("""INSERT INTO correlations (workspace_id, rule_name, target, risk, evidence)
                                    VALUES (1, 'ports', '192.0.2.1', 7, 'second evidence')""")
                else:
                    conn.execute("CREATE UNIQUE INDEX idx_correlations_uniq ON correlations(workspace_id, rule_name, target)")
                conn.commit()
                conn.close()
                storage = Storage("old", td)
                try:
                    self.assertEqual(risk_summary(storage)["total_correlations"], 1)
                    history = storage.query("correlation_history")
                    self.assertEqual(len(history), 2 if duplicated else 1)
                    self.assertIn("legacy evidence", {json.loads(r["snapshot"])["evidence"] for r in history})
                    result = run_rule(Rule("ports", "", 6, collect=[RuleAction("ports", "state='open'")]), storage)
                    save_correlations(storage, result)
                    self.assertEqual(risk_summary(storage)["total_correlations"], 0)
                    self.assertEqual(storage.query("correlations")[0]["status"], "resolved")
                finally:
                    storage.close()
                reopened = Storage("old", td)
                try:
                    self.assertEqual(len(reopened.query("correlation_history")), (2 if duplicated else 1) + 1)
                finally:
                    reopened.close()


if __name__ == "__main__":
    unittest.main()
