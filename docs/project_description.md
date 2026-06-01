# Project Description

## What It Does

ProofSIFT is an autonomous incident-response agent that turns SIFT-style forensic artifacts into evidence-backed investigative findings. It hashes evidence, runs typed forensic tools, builds a provenance graph, verifies each claim, self-corrects unsupported output, and generates reports with traceable proof.

## How It Was Built

The project uses a custom typed tool architecture instead of exposing raw shell execution. Each tool returns structured artifacts. A SQLite evidence graph links tool runs, artifacts, claims, and corrections. The agent runs an autonomous loop:

```text
Collect -> Hypothesize -> Verify -> Correct -> Corroborate -> Report
```

The MCP-style stdio bridge exposes high-level operations for Protocol SIFT integration.

## Challenges

- Preventing hallucinated conclusions from becoming confirmed findings.
- Designing useful autonomous behavior without hiding the reasoning path.
- Making the demo runnable without a large SIFT VM while preserving the real integration model.
- Keeping evidence integrity enforcement in code rather than in prompts.

## What We Learned

Autonomous DFIR is not just about speed. The harder problem is evidence discipline. A fast agent that cannot prove its claims creates analyst burden. A useful agent must know when to downgrade itself.

## What's Next

- Replace normalized fixture parsers with native SIFT adapters.
- Add real public datasets from NIST CFReDS and SANS sample cases.
- Add richer timeline fusion and ATT&CK mapping.
- Add optional Claude Code/OpenClaw prompts that operate through the typed MCP boundary.
- Publish benchmark runs across multiple case families.

