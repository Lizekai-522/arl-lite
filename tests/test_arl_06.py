"""Offline regression: rule timeout and reuse of the interrupted connection."""
import sqlite3
import tempfile
import time
import unittest
from arl_lite.db.storage import Storage
from arl_lite.core.correlation_engine import _guarded_query


class RuleBudgetTests(unittest.TestCase):
    def test_budget_interrupts_and_connection_recovers(self):
        with tempfile.TemporaryDirectory() as root:
            storage = Storage("budget", root)
            started = time.monotonic()
            with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted"):
                _guarded_query(storage, "WITH RECURSIVE n(x) AS "
                               "(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000000) "
                               "SELECT sum(x) FROM n", [], budget=0.01)
            self.assertLess(time.monotonic() - started, 2)
            self.assertGreater(storage._local.deadline, time.monotonic() + 100)
            self.assertEqual(_guarded_query(storage, "SELECT 42", [])[0][0], 42)
            storage.close()

    def test_nonpositive_budget_rejected(self):
        with self.assertRaises(ValueError):
            _guarded_query(None, "SELECT 1", [], budget=0)


if __name__ == "__main__":
    unittest.main()
