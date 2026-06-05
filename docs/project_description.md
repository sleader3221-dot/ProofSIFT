# Project Description

## What It Does

ProofSIFT is an autonomous incident-response agent that turns SIFT-style forensic artifacts into evidence-backed investigative findings. It hashes evidence, runs nonce-authorized typed forensic tools, builds a provenance graph, verifies each claim, self-corrects unsupported output, and generates reports with traceable proof. The latest version adds a Merkle-DAG evidence root seal, active counterfactual falsification, Bayesian posterior confidence scoring, bounded model checking for timeline contradictions, and MFT sequence entropy analysis.

## How It Was Built

The project uses a custom typed tool architecture instead of exposing raw shell execution. Each tool returns structured artifacts. A SQLite evidence graph links tool runs, artifacts, claims, and corrections. The agent runs an autonomous loop:

```text
Collect -> Hypothesize -> Verify -> Correct -> Corroborate -> Report
```

The MCP-style stdio bridge exposes high-level operations for Protocol SIFT integration. Calls cross a one-time HMAC-SHA256 authorization gate before execution, binding the tool name and payload hash to a short-lived nonce.

## Advanced Tradeoffs

ProofSIFT deliberately chooses mathematical and cryptographic verification over prompt-driven heuristics:

- **Cryptographic truth verification:** `proofsift verify-integrity` computes a Merkle-DAG root over tool runs, artifact content hashes, observations, claims, signed claim-evidence relationship blocks, corrections, Bayesian scores, counterfactual checks, BMC results, entropy analyses, and tool authorization records.
- **Active falsification:** the critic runs counterfactual alibi checks. If a high-impact claim lacks expected operating-system side effects such as Shimcache, Amcache, Prefetch, Event ID 4688, MFT, or USN evidence, escalation is denied and logged.
- **Bayesian confidence calculus:** confidence is reported as a posterior probability using `P(H|E)=P(E|H)*P(H)/P(E)`, not an arbitrary label or prompt-generated percentage.
- **Formal timeline verification:** a bounded model checker proves when Prefetch, Amcache, USN, and MFT timestamps cannot all be true in one causal model.
- **MFT entropy calculus:** record-number spacing and timestamp density are scored to detect structural timestomping patterns that simple timestamp comparisons can miss.
- **Ephemeral MCP authorization:** typed tool calls require a nonce-backed payload signature, and replayed calls are rejected before execution.

## Challenges

- Preventing hallucinated conclusions from becoming confirmed findings.
- Designing useful autonomous behavior without hiding the reasoning path.
- Making the demo runnable without a large SIFT VM while preserving the real integration model.
- Keeping evidence integrity enforcement in code rather than in prompts.
- Balancing judge-readable reports with enough cryptographic detail to expose tampering or unsupported claim links.
- Making advanced checks deterministic and audit-friendly rather than opaque model-generated commentary.

## What We Learned

Autonomous DFIR is not just about speed. The harder problem is evidence discipline. A fast agent that cannot prove its claims creates analyst burden. A useful agent must know when to downgrade itself.

## What's Next

- Replace normalized fixture parsers with native SIFT adapters.
- Add real public datasets from NIST CFReDS and SANS sample cases.
- Add richer timeline fusion, ATT&CK mapping, and public prior calibration datasets for the Bayesian matrix.
- Calibrate BMC and entropy thresholds against larger public corpora.
- Add optional Claude Code/OpenClaw prompts that operate through the typed MCP boundary.
- Publish benchmark runs across multiple case families.
