# ProofSIFT

Evidence-proven, self-correcting autonomous DFIR triage for the SANS Find Evil hackathon.

ProofSIFT is built around one principle: **the agent cannot make a confirmed finding unless it can prove the finding with traceable forensic evidence**. Every claim is linked to the exact artifact, parser, command ID, timestamped audit event, and evidence hash that produced it.

## Why This Is Built To Score

The Find Evil rules reward autonomous execution, IR accuracy, depth, architectural constraints, audit trail quality, and usability. ProofSIFT maps directly to those criteria:

| Judging Criterion | ProofSIFT Answer |
| --- | --- |
| Autonomous execution quality | Deterministic `Plan -> Collect -> Hypothesize -> Verify -> Correct -> Report` loop with max-iteration caps. |
| IR accuracy | Confirmed claims require independent artifact corroboration; weak claims are downgraded. |
| Breadth and depth | Focused Windows triage across memory, network, execution, registry, filesystem, event logs, and IOC scan outputs. |
| Constraint implementation | Typed tools and path policy instead of raw shell access. Evidence reads are allowed; evidence writes are blocked. |
| Audit trail quality | JSONL execution log, SQLite evidence graph, trace command, Markdown/HTML reports. |
| Usability and documentation | No runtime dependencies for demo mode; SIFT integration path documented. |

## Quick Start

```bash
python -m pip install -e .
proofsift run --case cases/demo_case/case.json --max-iterations 3
proofsift benchmark --case cases/demo_case/case.json --ground-truth cases/demo_case/ground_truth.json
```

If the console script is unavailable, use the module entry point:

```bash
PYTHONPATH=src python -m proofsift run --case cases/demo_case/case.json --max-iterations 3
```

PowerShell equivalent:

```powershell
$env:PYTHONPATH="src"; python -m proofsift run --case cases/demo_case/case.json --max-iterations 3
```

Inspect a claim:

```bash
proofsift trace --graph cases/demo_case/outputs/evidence_graph.sqlite --claim-id <claim-id>
```

Check required submission assets:

```bash
proofsift validate-submission --root .
```

## What The Demo Shows

The demo case contains:

- A real malicious chain: `powershell.exe` stages `evil.exe`, `evil.exe` executes, persists through HKCU Run, and communicates with a known C2 IP.
- A deliberate weak signal: `unknown.exe` appears in a network artifact with a C2-looking IP but lacks process, disk, and execution corroboration.
- A negative control: `svchost.exe` is observed but must not be escalated as malicious without proof.

Expected behavior:

- `evil.exe` C2 communication becomes `CONFIRMED` only after disk and log corroboration.
- `unknown.exe` is not confirmed.
- `svchost.exe` is kept as context, not a malicious finding.
- EVTX timestamps are normalized by a detected `+120s` drift against memory network evidence.
- `evil.exe` timestomping-style metadata divergence is flagged as anti-forensics signal.
- MITRE ATT&CK sequence gaps trigger targeted tool recommendations before confirmation.

## 75 Advanced Features

1. Typed forensic tool facade instead of unrestricted shell execution.
2. Read-only evidence path policy.
3. Output-only write policy.
4. Spoliation probe that proves evidence-root writes are blocked.
5. SHA-256 hashing of all evidence before analysis.
6. SQLite evidence graph.
7. Claim-to-artifact provenance.
8. Tool-run-to-artifact provenance.
9. Timestamped JSONL execution log.
10. Estimated token usage recorded in audit events.
11. Max-iteration autonomous loop.
12. Self-correction downgrade for unsupported confirmed claims.
13. Upgrade only after independent artifact corroboration.
14. Confirmed, inferred, possible, and contradicted claim states.
15. Confidence scoring.
16. Severity scoring.
17. MITRE ATT&CK technique tags.
18. Memory process parser contract.
19. Hidden process scan parser contract.
20. Network connection parser contract.
21. Volatility-style `malfind` injected-memory parser contract.
22. Prefetch execution parser contract.
23. Amcache inventory parser contract.
24. Shimcache/AppCompatCache parser contract.
25. Autorun persistence parser contract.
26. MFT timeline parser contract.
27. USN journal parser contract.
28. Windows EVTX parser contract.
29. Security 4688 process-creation parser contract.
30. PowerShell log parser contract.
31. Keyword-YARA style IOC scan.
32. Cross-source memory/disk correlation.
33. Negative-control handling for common system processes.
34. Benchmark harness against ground truth.
35. Precision and recall calculation.
36. Hallucinated confirmed-claim detection.
37. Markdown investigation report.
38. Strict-review `report_2.md` generation.
39. HTML investigation report.
40. Stdio JSON-RPC bridge for Protocol SIFT style tool calls.
41. SQLite `observations` table for timestamp-level forensic facts.
42. Automatic timestamp extraction from typed artifacts.
43. Clock-drift anchor discovery across evidence sources.
44. Network-to-EVTX shared-anchor matching.
45. Source-level drift delta calculation.
46. Dynamic normalized timestamp updates in SQLite.
47. Indexed normalized timestamp queries for cross-source windows.
48. Clock-drift audit events.
49. Clock-drift correction traces.
50. Clock-drift report section.
51. Differential MFT-to-Prefetch timestomping detection.
52. Differential MFT-to-USN timestomping detection.
53. MFT created-after-modified anomaly detection.
54. Anti-forensics anomaly table.
55. Confidence multiplier model for anti-forensics evidence.
56. Anti-forensics audit events.
57. Anti-forensics claim confidence adjustment.
58. Anti-forensics report section.
59. MITRE ATT&CK tactic mapping.
60. MITRE behavioral sequence state machine.
61. High-impact behavior validation for Command and Control.
62. High-impact behavior validation for Credential Access.
63. Missing-predecessor detection for Execution behavior.
64. Targeted tool recommendation generation.
65. Targeted artifact path recommendation generation.
66. Sequence-gap audit events.
67. Sequence-gap correction traces.
68. MITRE sequence report section.
69. Parser anomaly artifacts for malformed CSV inputs.
70. Graceful parser degradation on malformed rows.
71. Parser error capture without evidence modification.
72. Expanded benchmark scoring for anomalies and clock drift.
73. Advanced verification unit tests.
74. Synthetic clock-drift validation fixture.
75. Synthetic anti-forensics validation fixture.

## Repository Layout

```text
src/proofsift/              Core package
mcp_server/                 Judge-facing typed MCP server boundary
mcp_server/tools/           Read-only disk, memory, and log parser wrappers
agent/                      Investigator, critic, and self-correction engine facades
db/                         Evidence graph schema and manager facades
benchmark/                  Ground-truth evaluator facade
cases/demo_case/            Runnable demo evidence and ground truth
docs/architecture.md        Architecture and trust boundaries
docs/sift_integration.md    How to replace fixtures with real SIFT tools
docs/dataset_documentation.md
docs/accuracy_report.md
docs/demo_video_script.md
docs/project_description.md
submission_docs/            Architecture PNG, final report, accuracy, logs for judges
```

## Protocol SIFT / MCP Bridge

ProofSIFT exposes high-level typed operations over stdio:

```bash
proofsift mcp-stdio
```

The bridge intentionally exposes operations like `proofsift_run_case` and `proofsift_benchmark`, not shell execution. This keeps the security boundary in code instead of relying on prompt obedience.

## SIFT Integration Direction

Demo mode uses normalized CSV/text exports so judges can run it immediately. On SIFT, keep the same typed contracts and replace fixture reads with adapters for tools such as Volatility, Plaso/log2timeline, RegRipper, EvtxECmd, MFTECmd, AmcacheParser, PECmd, and YARA.

See [docs/sift_integration.md](docs/sift_integration.md).

## Research Basis

ProofSIFT was designed against:

- Find Evil official rules and judging criteria: <https://findevil.devpost.com/rules>
- Find Evil overview and required submission components: <https://findevil.devpost.com/>
- SANS SIFT Workstation: <https://www.sans.org/tools/sift-workstation/>
- SIFT GitHub repository: <https://github.com/sans-dfir/sift>
- Protocol SIFT repository: <https://github.com/teamdfir/protocol-sift>
- Model Context Protocol security guidance: <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- NIST CFReDS forensic reference datasets: <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/cfreds>

## License

MIT.
