import json
import sqlite3
import unittest
from pathlib import Path

from proofsift.agent import SelfCorrectingInvestigator, load_case_config
from proofsift.graph import EvidenceGraph
from proofsift.integrity import calculate_integrity_seal


class AdvancedVerificationTest(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.case_path = root / "cases" / "demo_case" / "case.json"
        self.output = root / "cases" / "demo_case" / "advanced_test_outputs"
        config = load_case_config(self.case_path, output_override=self.output, max_iterations=3)
        self.result = SelfCorrectingInvestigator(config).run()
        self.conn = sqlite3.connect(self.output / "evidence_graph.sqlite")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self):
        self.conn.close()

    def test_clock_drift_is_applied_to_observations(self):
        drift = self.conn.execute("select * from clock_drifts").fetchone()
        self.assertIsNotNone(drift)
        self.assertEqual(drift["source"], "evtx")
        self.assertEqual(drift["reference_source"], "netscan")
        self.assertEqual(drift["delta_seconds"], 120)
        shifted = self.conn.execute(
            "select count(*) as count from observations where source = 'evtx' and drift_seconds = 120"
        ).fetchone()
        self.assertGreaterEqual(shifted["count"], 1)

    def test_anti_forensics_anomalies_are_recorded(self):
        rows = self.conn.execute("select details_json from anomalies where kind = 'ANTI_FORENSICS'").fetchall()
        details = "\n".join(row["details_json"] for row in rows)
        self.assertIn("mft_creation_postdates_prefetch_execution", details)
        self.assertIn("mft_created_after_modified", details)

    def test_mitre_sequence_recommends_targeted_tools(self):
        rows = self.conn.execute("select * from sequence_recommendations").fetchall()
        self.assertGreaterEqual(len(rows), 1)
        tools = set()
        for row in rows:
            tools.update(json.loads(row["recommended_tools_json"]))
        self.assertIn("disk_prefetch", tools)
        self.assertIn("windows_evtx", tools)

    def test_deep_protocol_artifacts_are_first_class(self):
        counts = {
            kind: self.conn.execute(
                "select count(*) as count from artifacts where kind = ?",
                (kind,),
            ).fetchone()["count"]
            for kind in [
                "malfind",
                "shimcache",
                "process_creation",
                "powershell_log",
                "prefetch",
                "amcache",
                "mft",
                "usn",
            ]
        }
        for kind, count in counts.items():
            self.assertGreaterEqual(count, 1, f"{kind} should be represented")

    def test_report_2_is_generated_for_strict_confirmed_review(self):
        self.assertTrue((self.output / "report_2.md").exists())

    def test_execution_log_contains_advanced_traces(self):
        log = (self.output / "execution_log.jsonl").read_text(encoding="utf-8")
        self.assertIn('"actor": "clock_drift"', log)
        self.assertIn('"actor": "anti_forensics"', log)
        self.assertIn('"actor": "mitre_sequence"', log)

    def test_merkle_dag_integrity_root_is_verifiable(self):
        graph = EvidenceGraph(self.output / "evidence_graph.sqlite")
        try:
            seal = calculate_integrity_seal(graph)
        finally:
            graph.close()
        self.assertTrue(seal["ok"])
        self.assertTrue(seal["root_seal"].startswith("sha256:"))
        self.assertGreaterEqual(seal["relationship_block_count"], 1)
        self.assertEqual(seal["artifact_hash_mismatches"], [])

    def test_bayesian_scores_are_recorded_for_claims(self):
        rows = self.conn.execute("select * from bayesian_scores").fetchall()
        self.assertGreaterEqual(len(rows), 1)
        posteriors = [row["posterior"] for row in rows]
        self.assertTrue(all(0.0 <= posterior <= 0.9999 for posterior in posteriors))
        signals = "\n".join(row["signals_json"] for row in rows)
        self.assertIn("network", signals)
        self.assertIn("prefetch", signals)

    def test_counterfactual_failures_are_logged_as_denied_escalations(self):
        rows = self.conn.execute("select * from counterfactual_checks where status = 'FAIL'").fetchall()
        self.assertGreaterEqual(len(rows), 1)
        missing = "\n".join(row["missing_artifacts_json"] for row in rows)
        self.assertIn("Shimcache/AppCompatCache entry", missing)
        log = (self.output / "execution_log.jsonl").read_text(encoding="utf-8")
        self.assertIn("[COUNTERFACTUAL FAILURE] Denied escalation", log)


if __name__ == "__main__":
    unittest.main()
