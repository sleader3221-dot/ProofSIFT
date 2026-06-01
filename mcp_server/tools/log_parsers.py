"""Windows event-log and PowerShell parser wrappers."""

from __future__ import annotations

from proofsift.tools import ToolRunner


def windows_evtx(runner: ToolRunner):
    return runner.windows_evtx()


def windows_process_creation(runner: ToolRunner):
    return runner.windows_process_creation()


def powershell_logs(runner: ToolRunner):
    return runner.powershell_logs()


def registry_autoruns(runner: ToolRunner):
    return runner.registry_autoruns()

