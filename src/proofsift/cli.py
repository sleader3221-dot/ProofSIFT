from __future__ import annotations

import argparse
import json
from pathlib import Path

from .agent import SelfCorrectingInvestigator, load_case_config
from .benchmark import run_benchmark
from .graph import EvidenceGraph
from .mcp_server import serve_stdio
from .tools import ToolRunner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="proofsift", description="Evidence-proven, self-correcting DFIR agent.")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run autonomous investigation")
    run_p.add_argument("--case", required=True, type=Path)
    run_p.add_argument("--output", type=Path)
    run_p.add_argument("--max-iterations", type=int)

    bench_p = sub.add_parser("benchmark", help="Run investigation and score against ground truth")
    bench_p.add_argument("--case", required=True, type=Path)
    bench_p.add_argument("--ground-truth", required=True, type=Path)
    bench_p.add_argument("--output", type=Path)
    bench_p.add_argument("--max-iterations", type=int)

    trace_p = sub.add_parser("trace", help="Trace a claim back to evidence and tool execution")
    trace_p.add_argument("--graph", required=True, type=Path)
    trace_p.add_argument("--claim-id", required=True)

    tools_p = sub.add_parser("list-tools", help="List typed tools exposed by ProofSIFT")
    tools_p.add_argument("--case", type=Path)

    val_p = sub.add_parser("validate-submission", help="Check required hackathon submission files")
    val_p.add_argument("--root", default=Path("."), type=Path)

    sub.add_parser("mcp-stdio", help="Serve high-level typed tools over newline JSON-RPC stdio")

    args = parser.parse_args(argv)
    if args.command == "run":
        config = load_case_config(args.case, output_override=args.output, max_iterations=args.max_iterations)
        result = SelfCorrectingInvestigator(config).run()
        print(json.dumps({"output_dir": result["output_dir"], "claim_count": len(result["claims"]), "correction_count": len(result["corrections"]), "reports": result["reports"]}, indent=2))
        return 0
    if args.command == "benchmark":
        result = run_benchmark(args.case, args.ground_truth, output_dir=args.output, max_iterations=args.max_iterations)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 2
    if args.command == "trace":
        graph = EvidenceGraph(args.graph)
        print(json.dumps(graph.trace_claim(args.claim_id), indent=2, sort_keys=True))
        graph.close()
        return 0
    if args.command == "list-tools":
        if args.case:
            config = load_case_config(args.case)
            investigator = SelfCorrectingInvestigator(config)
            print(json.dumps(investigator.tools.catalog(), indent=2))
        else:
            print(json.dumps(ToolRunner.catalog(ToolRunner), indent=2))
        return 0
    if args.command == "validate-submission":
        result = validate_submission(args.root)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["passed"] else 3
    if args.command == "mcp-stdio":
        return serve_stdio()
    raise AssertionError(args.command)


def validate_submission(root: Path) -> dict[str, object]:
    root = root.resolve()
    required = {
        "README.md": root / "README.md",
        "LICENSE": root / "LICENSE",
        "Architecture docs": root / "docs" / "architecture.md",
        "Dataset docs": root / "docs" / "dataset_documentation.md",
        "Accuracy report template": root / "docs" / "accuracy_report.md",
        "Final pre-submission validation": root / "docs" / "final_pre_submission_validation.md",
        "Demo script": root / "docs" / "demo_video_script.md",
        "Project story": root / "docs" / "project_description.md",
        "Demo case": root / "cases" / "demo_case" / "case.json",
        "Ground truth": root / "cases" / "demo_case" / "ground_truth.json",
        ".cursorrules": root / ".cursorrules",
        "requirements.txt": root / "requirements.txt",
        "MCP server": root / "mcp_server" / "server.py",
        "MCP disk tools": root / "mcp_server" / "tools" / "disk_parsers.py",
        "MCP memory tools": root / "mcp_server" / "tools" / "memory_parsers.py",
        "MCP log tools": root / "mcp_server" / "tools" / "log_parsers.py",
        "Agent investigator": root / "agent" / "investigator.py",
        "Agent critic": root / "agent" / "critic.py",
        "Agent engine": root / "agent" / "engine.py",
        "DB schema": root / "db" / "schema.py",
        "DB manager": root / "db" / "manager.py",
        "Benchmark evaluator": root / "benchmark" / "evaluator.py",
        "Submission architecture PNG": root / "submission_docs" / "architecture.png",
        "Submission dataset docs": root / "submission_docs" / "dataset_documentation.md",
        "Submission accuracy report": root / "submission_docs" / "accuracy_report.md",
        "Submission final report": root / "submission_docs" / "report_3.md",
        "Submission execution log": root / "submission_docs" / "execution_log.jsonl",
    }
    missing = [label for label, path in required.items() if not path.exists()]
    return {"passed": not missing, "missing": missing, "checked_root": str(root)}


if __name__ == "__main__":
    raise SystemExit(main())
