from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .agent import SelfCorrectingInvestigator, load_case_config
from .benchmark import run_benchmark


def serve_stdio() -> int:
    """Small stdio JSON-RPC bridge for Protocol SIFT style tool calls.

    It intentionally exposes high-level typed operations rather than raw shell
    execution. Hosts can call `tools/list` and `tools/call` over newline-delimited
    JSON-RPC messages.
    """

    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            request = json.loads(line)
            response = _handle(request)
        except Exception as exc:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": str(exc)}}
        sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")
        sys.stdout.flush()
    return 0


def _handle(request: dict[str, Any]) -> dict[str, Any]:
    method = request.get("method")
    request_id = request.get("id")
    params = request.get("params") or {}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"name": "proofsift", "version": "0.1.0"}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": _tools()}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        return {"jsonrpc": "2.0", "id": request_id, "result": _call(name, arguments)}
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": f"unknown method: {method}"}}


def _tools() -> list[dict[str, Any]]:
    return [
        {
            "name": "proofsift_run_case",
            "description": "Run the self-correcting investigation loop against a case.json file.",
            "inputSchema": {"type": "object", "required": ["case_path"], "properties": {"case_path": {"type": "string"}, "output_dir": {"type": "string"}, "max_iterations": {"type": "integer"}}},
        },
        {
            "name": "proofsift_benchmark",
            "description": "Run investigation and score against ground truth.",
            "inputSchema": {"type": "object", "required": ["case_path", "ground_truth_path"], "properties": {"case_path": {"type": "string"}, "ground_truth_path": {"type": "string"}, "output_dir": {"type": "string"}}},
        },
    ]


def _call(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "proofsift_run_case":
        config = load_case_config(
            Path(arguments["case_path"]),
            output_override=Path(arguments["output_dir"]) if arguments.get("output_dir") else None,
            max_iterations=arguments.get("max_iterations"),
        )
        return SelfCorrectingInvestigator(config).run()
    if name == "proofsift_benchmark":
        return run_benchmark(
            Path(arguments["case_path"]),
            Path(arguments["ground_truth_path"]),
            output_dir=Path(arguments["output_dir"]) if arguments.get("output_dir") else None,
        )
    raise ValueError(f"unknown tool: {name}")

