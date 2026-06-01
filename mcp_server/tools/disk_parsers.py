"""Disk parser wrappers for SIFT-derived artifacts.

The concrete parser contracts live in `proofsift.tools.ToolRunner`. These
functions intentionally expose structured operations instead of raw shell
execution.
"""

from __future__ import annotations

from proofsift.tools import ToolRunner


def timeline_mft(runner: ToolRunner):
    return runner.timeline_mft()


def timeline_usn(runner: ToolRunner):
    return runner.timeline_usn()


def disk_prefetch(runner: ToolRunner):
    return runner.disk_prefetch()


def disk_amcache(runner: ToolRunner):
    return runner.disk_amcache()


def disk_shimcache(runner: ToolRunner):
    return runner.disk_shimcache()

