"""Iterative ProofSIFT engine facade."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from proofsift.agent import SelfCorrectingInvestigator, load_case_config


def run_case(case_path: str | Path, max_iterations: int = 3) -> dict[str, Any]:
    config = load_case_config(Path(case_path), max_iterations=max_iterations)
    return SelfCorrectingInvestigator(config).run()

