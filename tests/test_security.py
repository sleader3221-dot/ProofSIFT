from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

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


if __name__ == "__main__":
    unittest.main()

