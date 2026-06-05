# SIFT Integration

ProofSIFT is runnable without SIFT for judging convenience, but the target deployment is Linux/SIFT Workstation.

## Install On SIFT

```bash
git clone https://github.com/sleader3221-dot/ProofSIFT.git proofsift
cd proofsift
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
proofsift run --case cases/demo_case/case.json --max-iterations 3
```

## Protocol SIFT Bridge

```bash
proofsift mcp-stdio
```

The bridge accepts newline-delimited JSON-RPC:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

Authorize a case run. The bridge returns a short-lived HMAC-SHA256 nonce envelope bound to the exact tool name and arguments:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/authorize","params":{"name":"proofsift_run_case","arguments":{"case_path":"cases/demo_case/case.json","max_iterations":3}}}
```

Run the case with the returned authorization:

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"proofsift_run_case","arguments":{"case_path":"cases/demo_case/case.json","max_iterations":3},"authorization":{"version":"proofsift-ephemeral-mcp-auth-v1","nonce":"<nonce>","issued_at_utc":"<issued>","expires_at_utc":"<expires>","tool_name":"proofsift_run_case","payload_hash":"<hash>","signature":"<hmac>"}}}
```

Calls without a valid nonce are rejected with `tool authorization rejected` before the tool executes.

## Replacing Fixture Parsers With SIFT Tools

Keep the public typed methods stable:

| ProofSIFT method | SIFT adapter examples |
| --- | --- |
| `memory_pslist()` | `vol.py -f memory.raw windows.pslist` |
| `memory_psscan()` | `vol.py -f memory.raw windows.psscan` |
| `memory_netscan()` | `vol.py -f memory.raw windows.netscan` |
| `memory_malfind()` | `vol.py -f memory.raw windows.malfind` |
| `disk_prefetch()` | `PECmd` or SIFT prefetch parser output |
| `disk_amcache()` | `AmcacheParser` output |
| `disk_shimcache()` | AppCompatCache/Shimcache parser output |
| `registry_autoruns()` | `RegRipper` autoruns plugins |
| `timeline_mft()` | `MFTECmd` or Plaso/log2timeline |
| `timeline_usn()` | `MFTECmd` USN parser |
| `windows_evtx()` | `EvtxECmd` or SIFT event log tooling |
| `windows_process_creation()` | Security Event ID 4688 process-creation events |
| `powershell_logs()` | PowerShell operational/script-block/process-creation evidence |
| `yara_keyword_scan()` | `yara` with curated rules |

Adapter rule: parse raw tool output into structured `Artifact` records before returning to the agent. Do not dump huge raw command output into an LLM context.

## Safety Requirements

- Mount disk images read-only.
- Hash source evidence before parsing.
- Write derived artifacts only to `outputs/`.
- Log command ID, parser version, parameters, duration, and warnings.
- Treat parser failure as a first-class artifact gap, not as permission to invent a finding.
