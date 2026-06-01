# Evidence Dataset Documentation

## Demo Dataset

**Path:** `cases/demo_case/`
**Format:** Normalized CSV/text exports (no binary disk images required)
**Size:** ~5 KB total (11 evidence files)
**Purpose:** Runnable immediately on any system with Python 3.10+; no SIFT VM or external tools needed

The demo dataset models a realistic Windows triage scenario: a malicious `powershell.exe` -> `evil.exe` infection chain with C2 communication, registry persistence, timestomping, and clock drift. It includes deliberate weak signals and negative controls to test autonomous reasoning.

---

## Evidence File Details

### 1. `processes.csv` — Memory Process Listings

| Field | Example Values | Description |
|-------|---------------|-------------|
| `pid` | 412, 632, 1888, 2100 | Process ID |
| `ppid` | 4, 632, 632 | Parent Process ID |
| `name` | svchost.exe, explorer.exe, evil.exe, powershell.exe | Process name |
| `image_path` | C:\Windows\System32\svchost.exe, C:\Users\victim\AppData\Roaming\evil.exe | Full executable path |
| `created_utc` | 2026-05-20T13:58:11Z, 2026-05-20T14:02:10Z | Process creation timestamp |
| `source` | pslist, psscan | Source tool type (pslist for standard, psscan for hidden) |
| `user` | NT AUTHORITY\SYSTEM, WIN10\victim | Process owner |

**Artifacts:** 4 processes, 2 sources (pslist + psscan). `evil.exe` (PID 1888) is detected by `psscan` indicating it may be hidden from standard API enumeration.

### 2. `netscan.csv` — Network Connections

| Field | Example Values | Description |
|-------|---------------|-------------|
| `pid` | 412, 1888, 4444 | Process ID owning the connection |
| `process` | svchost.exe, evil.exe, unknown.exe | Process name |
| `local` | 10.0.2.15:49701, 10.0.2.15:49822 | Local IP:port |
| `remote_ip` | 10.0.2.2, 203.0.113.50, 198.51.100.24 | Remote IP address |
| `remote_port` | 53, 443 | Remote port |
| `state` | ESTABLISHED, CLOSED | Connection state |
| `first_seen` | 2026-05-20T14:01:00Z, 2026-05-20T14:03:30Z | First observation timestamp |

**Artifacts:** 3 connections. `evil.exe` (PID 1888) connects to C2 IP `203.0.113.50:443`. `unknown.exe` (PID 4444) connects to `198.51.100.24:443` — a deliberate weak signal with no disk evidence.

### 3. `prefetch.csv` — Prefetch Execution Evidence

| Field | Example Values | Description |
|-------|---------------|-------------|
| `executable` | POWERSHELL.EXE, EVIL.EXE | Executable name |
| `path` | C:\Windows\Prefetch\EVIL.EXE-9A8B7C6D.pf | Prefetch file path |
| `run_count` | 1, 3 | Execution count |
| `last_run_utc` | 2026-05-20T14:01:58Z, 2026-05-20T14:02:13Z | Last execution timestamp |

**Artifacts:** 2 executables. `EVIL.EXE` has 3 runs (persistent usage). `powershell.exe` has 1 run (staging script).

### 4. `amcache.csv` — Amcache Program Inventory

| Field | Example Values | Description |
|-------|---------------|-------------|
| `file_name` | evil.exe, powershell.exe | File name |
| `path` | C:\Users\victim\AppData\Roaming\evil.exe | Full installation path |
| `sha256` | 4f7b4e9e... (64 hex chars) | File hash |
| `first_run_utc` | 2026-05-20T14:02:11Z | First execution timestamp |
| `publisher` | Unsigned, Microsoft Windows | Publisher/signer information |

**Artifacts:** 2 programs. `evil.exe` is unsigned (suspicious). `powershell.exe` is Microsoft-signed (legitimate).

### 5. `shimcache.csv` — Shimcache/AppCompatCache

| Field | Example Values | Description |
|-------|---------------|-------------|
| `file_path` | C:\Users\victim\AppData\Roaming\evil.exe | Executable path |
| `last_modified_utc` | 2026-05-20T14:02:05Z | Last modification timestamp |
| `entry_type` | AppCompatCache | Cache entry type |
| `source` | System hive | Registry hive source |

**Artifacts:** 2 entries confirming execution presence of both evil.exe and powershell.exe.

### 6. `mft.csv` — MFT Filesystem Timeline

| Field | Example Values | Description |
|-------|---------------|-------------|
| `path` | C:\Users\victim\AppData\Roaming\evil.exe | File path |
| `created_utc` | 2026-05-20T14:10:05Z | File creation timestamp |
| `modified_utc` | 2026-05-20T14:02:05Z | File modification timestamp |
| `entry` | 391244, 391211 | MFT entry number |
| `notes` | "creation time postdates execution artifacts, simulating timestomping" | Analyst notes |

**Artifacts:** 2 files. `evil.exe` has creation time (14:10:05Z) **after** modification time (14:02:05Z) — a timestomping indicator. Also postdates Prefetch last_run (14:02:13Z) by ~472 seconds, triggering anti-forensics detection.

### 7. `usn.csv` — USN Journal

| Field | Example Values | Description |
|-------|---------------|-------------|
| `path` | C:\Users\victim\AppData\Roaming\evil.exe | File path |
| `reason` | FILE_CREATE\|DATA_EXTEND, BASIC_INFO_CHANGE | USN reason code |
| `time_utc` | 2026-05-20T14:02:05Z, 2026-05-20T14:02:25Z | Journal timestamp |

**Artifacts:** 2 entries. FILE_CREATE at 14:02:05Z predates MFT creation (14:10:05Z) confirming timestomping.

### 8. `evtx.csv` — Windows Event Logs

| Field | Example Values | Description |
|-------|---------------|-------------|
| `event_id` | 4624, 4688, 7045 | Windows Event ID |
| `time_utc` | 2026-05-20T14:01:30Z, 2026-05-20T14:01:55Z | Event timestamp |
| `channel` | Security, System | Event log channel |
| `user` | WIN10\victim | User context |
| `message` | "Successful logon Type 3 from source 203.0.113.50", "powershell.exe...stage.ps1", "evil.exe launched by powershell.exe", "Service creation attempt failed for UpdaterSvc" | Event message |

**Artifacts:** 4 events.
- **4624** (Logon): Source IP `203.0.113.50` — shared anchor with netscan for clock drift detection (+120s offset)
- **4688** (Process Creation): `powershell.exe` staging script, `evil.exe` launched by powershell.exe
- **7045** (Service Creation): Failed service creation for "UpdaterSvc"

### 9. `malfind.csv` — Injected Memory Regions

| Field | Example Values | Description |
|-------|---------------|-------------|
| `pid` | 1888 | Process ID |
| `process` | evil.exe | Process name |
| `vad_start` | 0x000001f4a0000000 | VAD region start |
| `vad_end` | 0x000001f4a001ffff | VAD region end |
| `protection` | PAGE_EXECUTE_READWRITE | Memory protection |
| `tag` | VadS | VAD tag |
| `disasm` | "MZ header and suspicious beacon stub observed" | Disassembly notes |

**Artifacts:** 1 injected memory region in evil.exe (PID 1888) with RWX protection and MZ header — consistent with code injection.

### 10. `autoruns.csv` — Registry Persistence

| Field | Example Values | Description |
|-------|---------------|-------------|
| `name` | Updater, OneDrive | Autorun entry name |
| `path` | C:\Users\victim\AppData\Roaming\evil.exe, C:\Users\victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe | Executable path |
| `registry_key` | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Registry key |
| `created_utc` | 2026-05-20T14:02:30Z, 2026-05-19T10:00:00Z | Timestamp |
| `user` | WIN10\victim | User context |

**Artifacts:** 2 entries. "Updater" points to evil.exe in HKCU\Run (malicious persistence). "OneDrive" is legitimate.

### 11. `payload_notes.txt` — Recovered IOC Strings

```
Recovered string notes from unallocated-space carving:
evil beacon initialized
c2 channel: 203.0.113.50:443
credential harvest module disabled in this sample
```

**Used by:** `yara_keyword_scan()` tool for IOC keyword matching. Keywords `evil beacon` and `c2 channel` match configured YARA indicators.

---

## Ground Truth

**Path:** `cases/demo_case/ground_truth.json`

### Expected Confirmed Findings

| Finding | Corroboration Sources | Rationale |
|---------|----------------------|-----------|
| evil.exe C2 communication with 203.0.113.50 | process + network + prefetch + amcache + shimcache + MFT + EVTX + USN + malfind + yara + process_creation | Cross-source corroboration across memory, disk, logs, and IOC scan (>=3 artifact kinds) |
| evil.exe user-level persistence (HKCU\Run) | autorun + process + prefetch + amcache + MFT + EVTX | Autorun registry path matches execution artifacts |

### Forbidden Confirmed Findings

| Finding | Reason |
|---------|--------|
| unknown.exe C2 with 198.51.100.24 | Network-only evidence — no disk or execution corroboration |
| svchost.exe malicious | Negative control — benign system process |

### Expected Anomalies

| Anomaly Type | Trigger |
|-------------|---------|
| mft_creation_postdates_prefetch_execution | MFT created 14:10:05Z > Prefetch last_run 14:02:13Z (skew 472s) |
| mft_created_after_modified | MFT created 14:10:05Z > MFT modified 14:02:05Z |

### Expected Clock Drifts

| Drift | Anchor | Delta |
|-------|--------|-------|
| EVTX normalized against netscan | Remote IP 203.0.113.50 in both netscan.first_seen (14:03:30Z) and evtx 4624 logon (14:01:30Z) | +120 seconds |

---

## Dataset Design Principles

1. **Minimal but complete** — Every major forensic domain (memory, disk, registry, logs, network) is represented
2. **Deterministic results** — The same evidence always produces the same claims and corrections
3. **Deliberate edge cases** — Weak signals (unknown.exe), negative controls (svchost.exe), clock drift, timestomping
4. **Self-validating** — Ground truth file enables automated benchmark scoring
5. **No external dependencies** — CSV/text format eliminates need for binary parsers or SIFT tools
