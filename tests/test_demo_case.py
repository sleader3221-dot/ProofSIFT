from pathlib import Path
import unittest

from proofsift.benchmark import run_benchmark


class DemoCaseTest(unittest.TestCase):
    def test_demo_benchmark_passes(self):
        root = Path(__file__).resolve().parents[1]
        case = root / "cases" / "demo_case" / "case.json"
        truth = root / "cases" / "demo_case" / "ground_truth.json"
        output = root / "cases" / "demo_case" / "test_outputs"
        score = run_benchmark(case, truth, output_dir=output, max_iterations=3)
        self.assertTrue(score["passed"], score)
        self.assertGreaterEqual(score["self_corrections"], 1)
        self.assertEqual(score["hallucinated_confirmed_claims"], [])


if __name__ == "__main__":
    unittest.main()

