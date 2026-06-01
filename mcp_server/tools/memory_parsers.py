"""Memory parser wrappers for Volatility/SIFT-derived artifacts."""

from __future__ import annotations

from proofsift.tools import ToolRunner


def memory_pslist(runner: ToolRunner):
    return runner.memory_pslist()


def memory_psscan(runner: ToolRunner):
    return runner.memory_psscan()


def memory_netscan(runner: ToolRunner):
    return runner.memory_netscan()


def memory_malfind(runner: ToolRunner):
    return runner.memory_malfind()

