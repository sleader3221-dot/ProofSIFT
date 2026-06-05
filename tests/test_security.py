from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proofsift.crypto_auth import EphemeralToolAuthorizer
from proofsift.mcp_server import _handle
from proofsift.security import PolicyViolation, SafePathPolicy


class SafePathPolicyTest(unittest.TestCase):
    def test_blocks_evidence_writes(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            output = root / "outputs"
            evidence.mkdir()
            policy = SafePathPolicy([evidence], output)
            self.assertTrue(policy.assert_no_evidence_write())
            with self.assertRaises(PolicyViolation):
                policy.validate_write(evidence / "new.txt")

    def test_allows_output_writes(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            output = root / "outputs"
            evidence.mkdir()
            policy = SafePathPolicy([evidence], output)
            allowed = policy.validate_write(output / "report.md")
            self.assertEqual(allowed.name, "report.md")

    def test_ephemeral_authorizer_rejects_replay(self):
        authorizer = EphemeralToolAuthorizer(secret=b"unit-test-secret", ttl_seconds=30)
        arguments = {"case_path": "cases/demo_case/case.json"}
        envelope = authorizer.issue("proofsift_run_case", arguments).public()
        accepted, reason = authorizer.verify_and_consume("proofsift_run_case", arguments, envelope)
        self.assertTrue(accepted, reason)
        replayed, replay_reason = authorizer.verify_and_consume("proofsift_run_case", arguments, envelope)
        self.assertFalse(replayed)
        self.assertEqual(replay_reason, "nonce already consumed")

    def test_mcp_bridge_rejects_calls_without_nonce(self):
        response = _handle(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "proofsift_run_case",
                    "arguments": {"case_path": "cases/demo_case/case.json"},
                },
            }
        )
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("tool authorization rejected", response["error"]["message"])

        authorization = _handle(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/authorize",
                "params": {
                    "name": "proofsift_run_case",
                    "arguments": {"case_path": "cases/demo_case/case.json"},
                },
            }
        )
        self.assertIn("authorization", authorization["result"])


if __name__ == "__main__":
    unittest.main()
