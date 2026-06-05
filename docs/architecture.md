# Architecture

ProofSIFT uses the **Custom MCP Server / typed tool** strategy because the challenge explicitly values architectural guardrails over prompt-only rules.

```mermaid
flowchart LR
  Evidence["Evidence Root<br/>disk, memory, logs, normalized exports"] --> Policy["SafePathPolicy<br/>read evidence only"]
  Policy --> Tools["Typed Tool Facade<br/>no raw shell"]
  Tools --> Graph["Evidence Graph<br/>SQLite provenance"]
  Graph --> Drift["Clock Drift Normalizer<br/>normalized observations"]
  Graph --> Anti["Anti-Forensics Detector<br/>MFT, USN, Prefetch"]
  Graph --> Mitre["MITRE Sequence Validator<br/>behavioral state machine"]
  Graph --> Counter["Counterfactual Falsifier<br/>missing-evidence alibi checks"]
  Graph --> Bayes["Bayesian Scorer<br/>posterior confidence calculus"]
  Graph --> Merkle["Merkle-DAG Integrity<br/>root seal verification"]
  Tools --> Audit["Execution Log<br/>JSONL timestamps"]
  Drift --> Agent["Self-Correcting Agent<br/>verify, downgrade, upgrade"]
  Anti --> Agent
  Mitre --> Agent
  Counter --> Agent
  Bayes --> Agent
  Merkle --> Reports
  Agent --> Reports["Reports<br/>Markdown, HTML, trace index"]
  Agent --> Bench["Benchmark Harness<br/>ground truth scoring"]
  Reports --> Judges["Judges<br/>trace every claim"]
  Bench --> Judges
```

## Trust Boundaries

| Boundary | Enforcement |
| --- | --- |
| Evidence reads | `SafePathPolicy.validate_read()` allows only configured evidence roots. |
| Evidence writes | `SafePathPolicy.validate_write()` allows only output directory writes. |
| Tool invocation | Agent calls typed Python functions, not arbitrary shell commands. |
| Confirmed findings | Verification gate requires independent evidence kinds. |
| Time normalization | Clock drift is written to derived observations only; source artifacts are untouched. |
| Anti-forensics | MFT, USN, and Prefetch are compared as typed artifacts and stored as derived anomalies. |
| MITRE sequencing | High-impact claims trigger typed tool recommendations instead of free-form shell exploration. |
| Counterfactual falsification | High-impact claims must satisfy expected OS side effects; missing Shimcache, Amcache, Prefetch, Event ID 4688, MFT, or USN evidence denies escalation. |
| Bayesian scoring | Claim confidence is recalculated with `P(H|E)=P(E|H)*P(H)/P(E)` and persisted in `bayesian_scores`. |
| Chain of custody | `proofsift verify-integrity` computes a Merkle-DAG root over artifacts, claims, signed relationship blocks, corrections, and scoring records. |
| Auditability | Tool results, artifacts, claims, corrections, and traces are stored. |

## Agent Loop

```text
1. Register and hash evidence.
2. Run spoliation probe.
3. Collect memory and network artifacts.
4. Create initial hypotheses.
5. Verify and downgrade weak claims.
6. Run disk, registry, event, timeline, and IOC tools when gaps exist.
7. Normalize source clock drift through the observations table.
8. Correlate memory and disk evidence.
9. Detect timestomping and anti-forensics anomalies.
10. Validate MITRE ATT&CK behavioral sequence.
11. Run counterfactual alibi checks for missing OS side effects.
12. Recalculate Bayesian posterior confidence.
13. Seal the evidence graph with a Merkle-DAG root.
14. Upgrade only if independent artifacts agree.
15. Apply negative controls.
16. Generate report, trace index, and benchmark outputs.
```

## Architectural vs Prompt Guardrails

Architectural:

- No raw shell tool is exposed.
- Evidence write validation fails by construction.
- Confirmed claim status is computed by verifier logic.
- Every claim must link to stored artifact IDs.

Prompt-level:

- The project story asks the agent to think like a senior analyst.
- Report language reminds users that inferred claims are not confirmed.

The scoring bet is that architectural guardrails matter more to judges than eloquent prompts.
