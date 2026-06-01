# Research Notes

## Design Inputs

ProofSIFT was designed after reviewing the Find Evil rules and overview. The highest-value pattern is a custom typed MCP server because it lets the architecture enforce read-only evidence handling and structured outputs.

Primary sources:

- Find Evil official rules: <https://findevil.devpost.com/rules>
- Find Evil overview: <https://findevil.devpost.com/>
- SANS SIFT Workstation: <https://www.sans.org/tools/sift-workstation/>
- SIFT repository: <https://github.com/sans-dfir/sift>
- Protocol SIFT repository: <https://github.com/teamdfir/protocol-sift>
- MCP security guidance: <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- NIST CFReDS: <https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt/cfreds>
- MITRE ATT&CK Enterprise tactics: <https://attack.mitre.org/tactics/>
- MITRE ATT&CK Enterprise matrix: <https://attack.mitre.org/matrices/enterprise/>
- MITRE ATT&CK T1059: <https://attack.mitre.org/techniques/T1059/>
- MITRE ATT&CK T1003: <https://attack.mitre.org/techniques/T1003/>

## Strategic Choice

The project intentionally combines three starter ideas from the challenge:

- Self-correcting triage agent.
- Multi-source correlation engine.
- Accuracy benchmarking framework.
- Clock-drift normalization.
- Anti-forensics detection.
- MITRE ATT&CK behavioral sequence validation.

This is stronger than implementing any one idea alone because it gives judges a live autonomous loop, defensible accuracy, and traceability.

## Winning Hypothesis

Judges will prefer a tool that is honest and traceable over a tool that produces flashy but unverified findings. ProofSIFT therefore treats uncertainty as a first-class output state.
