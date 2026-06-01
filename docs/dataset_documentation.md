# Dataset Documentation

## Demo Dataset

Path: `cases/demo_case`

This dataset is synthetic and intentionally small so judges can run the full loop quickly without downloading a large image. It models normalized outputs from common SIFT workflows.

## Evidence Files

| File | Artifact Type |
| --- | --- |
| `processes.csv` | Memory process listings from `pslist` and `psscan` style tools. |
| `netscan.csv` | Memory network connection artifacts. |
| `malfind.csv` | Injected-memory style findings from Volatility `malfind`. |
| `prefetch.csv` | Windows Prefetch execution evidence. |
| `amcache.csv` | Amcache program inventory and hash evidence. |
| `shimcache.csv` | Shimcache/AppCompatCache execution-presence artifacts. |
| `autoruns.csv` | Registry persistence locations. |
| `mft.csv` | Filesystem timeline evidence. |
| `usn.csv` | USN journal evidence. |
| `evtx.csv` | Windows event log process/service events. |
| `payload_notes.txt` | Recovered strings used by the keyword scan. |

## Ground Truth

Path: `cases/demo_case/ground_truth.json`

Expected confirmed findings:

- `evil.exe` communicated with known C2 indicator `203.0.113.50`.
- `evil.exe` established user-level persistence through an autorun registry location.

Expected non-confirmed findings:

- `unknown.exe` must not be confirmed from network-only evidence.
- `svchost.exe` must not be reported as malicious without corroboration.

Expected advanced verification:

- EVTX has a `4624` anchor for `203.0.113.50` that is two minutes behind memory `netscan`; the normalizer should apply a `+120` second EVTX offset to derived observations.
- `evil.exe` has an MFT creation timestamp later than Prefetch execution and USN activity; the detector should emit anti-forensics anomalies.
- First-pass Command and Control claims should trigger MITRE sequence recommendations for `disk_prefetch`, `disk_amcache`, `windows_evtx`, and `memory_psscan`.

## Public Dataset Expansion Plan

For final submission depth, add at least one public dataset with documented answers:

- NIST CFReDS forensic reference datasets.
- DFIR Madness challenge datasets with published answer keys.
- Any SANS-provided Find Evil sample case data from the Protocol SIFT Slack.

Document each dataset with source URL, license/usage notes, evidence hashes, expected findings, and known limitations.
