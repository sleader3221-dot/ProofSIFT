import { createFileRoute } from "@tanstack/react-router";
import { Panel } from "@/components/Panel";
import { Download, FileJson, ShieldCheck } from "lucide-react";
import { downloadTextFile } from "@/lib/download";

export const Route = createFileRoute("/report")({
  head: () => ({ meta: [{ title: "Forensic Report · ProofSIFT" }] }),
  component: ReportPage,
});

function buildReportMarkdown(generatedAtUtc: string) {
  return `# ProofSIFT Forensic Investigation Report

Generated: ${generatedAtUtc}
Case: proofsift-demo-001
Analyst: ProofSIFT Autonomous Investigator v1.0

## 1. Executive Summary

On 2024-08-14 14:02-14:12 UTC, the autonomous ProofSIFT investigator confirmed an active command-and-control compromise on the subject host. The malicious binary evil.exe (SHA-256 9f3c...b201) was staged by powershell.exe, persisted through HKCU\\Run\\Updater, executed three times, and communicated with C2 endpoint 203.0.113.50:443.

Evidence integrity remained 100% intact. SafePathPolicy blocked two spoliation attempts.

## 2. Confirmed Findings

1. evil.exe -> C2 203.0.113.50:443
   - Status: CONFIRMED - CRITICAL
   - Confidence: 0.93
   - Evidence: memory_netscan, disk_prefetch, disk_amcache, timeline_mft, memory_malfind
   - MITRE: T1071.001, T1055, T1547.001

2. Registry persistence - HKCU\\Run\\Updater
   - Status: CONFIRMED - CRITICAL
   - Confidence: 0.91
   - Evidence: registry_autoruns + disk_amcache SHA match
   - MITRE: T1547.001

3. PowerShell parent-child staging
   - Status: CONFIRMED - CRITICAL
   - Confidence: 0.74
   - Evidence: windows_process_creation + disk_prefetch + yara_keyword_scan
   - MITRE: T1059.001, T1105

## 3. Inferred / Capped

unknown.exe -> 198.51.100.24 remains INFERRED - HIGH because no matching disk execution evidence (prefetch/amcache) corroborates the network signal.

## 4. Anti-Forensics and Clock Drift

- EVTX vs memory_netscan: +120s raw clock skew normalized against the Netscan anchor.
- evil.exe MFT STANDARD_INFORMATION created timestamp (14:10:05Z) appears after modified timestamp (14:02:05Z), so timestomping was flagged with a 1.12x confidence multiplier.

## 5. Integrity and Spoliation

- SafePathPolicy blocked 2 unsanctioned write attempts targeting /case/evidence/mft.csv.
- SHA-256 chain re-verified with 0 evidence modifications.
- Audit hash: 9f3c2b01...44ae.

## 6. Recommendations

1. Block egress to 203.0.113.50/32 and 198.51.100.24/32 at the perimeter.
2. Quarantine the host; preserve memory image and MFT.
3. Remove HKCU\\Run\\Updater; rotate credentials for the affected user.
4. Acquire full disk image for unknown.exe corroboration.
`;
}

function buildEvidencePackage(generatedAtUtc: string) {
  return {
    case_id: "proofsift-demo-001",
    generated_at_utc: generatedAtUtc,
    integrity: {
      safe_path_policy: "read=evidence/, write=outputs/",
      spoliation_attempts_blocked: 2,
      evidence_modifications: 0,
      audit_hash: "9f3c2b01...44ae",
    },
    confirmed_findings: [
      {
        id: "clm-3c76c94c3ce5",
        title: "evil.exe communicated with known C2 indicator 203.0.113.50:443",
        status: "CONFIRMED - CRITICAL",
        confidence: 0.93,
        evidence: [
          "memory_netscan",
          "disk_prefetch",
          "disk_amcache",
          "timeline_mft",
          "memory_malfind",
        ],
      },
      {
        id: "clm-7f01a2b9c4d1",
        title: "Registry persistence: HKCU\\Run\\Updater -> evil.exe",
        status: "CONFIRMED - CRITICAL",
        confidence: 0.91,
        evidence: ["registry_autoruns", "disk_amcache"],
      },
      {
        id: "clm-55c1ee84a020",
        title: "PowerShell staged evil.exe",
        status: "CONFIRMED - CRITICAL",
        confidence: 0.74,
        evidence: ["windows_process_creation", "disk_prefetch", "yara_keyword_scan"],
      },
    ],
    clock_drift: {
      source: "EVTX",
      reference: "memory_netscan",
      raw_offset_seconds: 120,
      normalization: "EVTX timestamps shifted -120s to align with Netscan anchor",
    },
    anti_forensics: [
      {
        target: "evil.exe",
        anomaly: "MFT created timestamp appears after modified/execution evidence",
        multiplier: 1.12,
      },
    ],
  };
}

function downloadReportMarkdown() {
  const generatedAtUtc = new Date().toISOString();
  downloadTextFile(
    "proofsift-demo-001-forensic-report.md",
    buildReportMarkdown(generatedAtUtc),
    "text/markdown",
  );
}

function downloadEvidenceJson() {
  const generatedAtUtc = new Date().toISOString();
  downloadTextFile(
    "proofsift-demo-001-evidence-package.json",
    `${JSON.stringify(buildEvidencePackage(generatedAtUtc), null, 2)}\n`,
    "application/json",
  );
}

function ReportPage() {
  return (
    <div className="space-y-6 p-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="font-mono text-[11px] uppercase tracking-[0.25em] text-confirmed">
            // tier-3 incident response report
          </div>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">
            Forensic Investigation Report
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Case proofsift-demo-001 — ready for CISO &amp; court submission.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={downloadReportMarkdown}
            className="inline-flex items-center gap-2 rounded-md border border-confirmed/50 bg-confirmed/10 px-4 py-2 font-mono text-xs uppercase tracking-widest text-confirmed hover:bg-confirmed/20"
          >
            <Download className="h-3.5 w-3.5" /> export markdown
          </button>
          <button
            onClick={downloadEvidenceJson}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-background/50 px-4 py-2 font-mono text-xs uppercase tracking-widest text-muted-foreground transition hover:border-confirmed/50 hover:text-confirmed"
          >
            <FileJson className="h-3.5 w-3.5" /> evidence json
          </button>
        </div>
      </div>

      <Panel accent="confirmed">
        <article className="prose-report mx-auto max-w-4xl font-mono text-[13.5px] leading-relaxed text-foreground">
          <header className="mb-6 rounded-md border border-confirmed/40 bg-confirmed/5 p-5">
            <div className="flex items-center gap-2 text-confirmed">
              <ShieldCheck className="h-5 w-5" />
              <span className="font-semibold tracking-wider">EXECUTIVE SUMMARY</span>
            </div>
            <p className="mt-3 text-foreground">
              On <span className="text-confirmed">2024-08-14 14:02–14:12 UTC</span> the autonomous
              ProofSIFT investigator confirmed an active command-and-control compromise on the
              subject host. The malicious binary
              <span className="text-blocked"> evil.exe (SHA-256 9f3c…b201)</span> was staged by
              <span className="text-inferred"> powershell.exe</span>, persisted through
              <span className="text-blocked"> HKCU\Run\Updater</span>, executed three times, and
              communicated with C2 endpoint <span className="text-blocked">203.0.113.50:443</span>.
              Evidence integrity remained
              <span className="text-confirmed"> 100% intact</span> — two spoliation attempts were
              blocked by SafePathPolicy.
            </p>
          </header>

          <h2 className="mt-6 text-base font-semibold uppercase tracking-widest text-confirmed">
            1 · Case Metadata
          </h2>
          <hr className="my-3 border-confirmed/30" />
          <table className="w-full border-collapse text-xs">
            <tbody>
              {[
                ["case_id", "proofsift-demo-001"],
                ["analyst", "ProofSIFT Autonomous Investigator v1.0"],
                ["iterations", "3 / 3"],
                ["evidence root", "/case/proofsift-demo-001/evidence/"],
                ["graph", "outputs/evidence_graph.sqlite"],
                ["audit log", "outputs/audit.jsonl (4,217 events)"],
              ].map(([k, v]) => (
                <tr key={k} className="border-b border-border/40">
                  <td className="w-44 py-1.5 pr-4 text-muted-foreground">{k}</td>
                  <td className="py-1.5 text-foreground">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2 className="mt-8 text-base font-semibold uppercase tracking-widest text-confirmed">
            2 · Confirmed Findings
          </h2>
          <hr className="my-3 border-confirmed/30" />
          <ol className="space-y-4">
            <li>
              <div className="flex items-baseline gap-3">
                <span className="rounded border border-confirmed/50 bg-confirmed/10 px-1.5 py-0.5 text-[10px] text-confirmed">
                  CONFIRMED · CRITICAL
                </span>
                <span className="text-foreground">evil.exe → C2 203.0.113.50:443</span>
              </div>
              <p className="mt-1 text-muted-foreground">
                Cross-corroborated by 5 independent sources: memory_netscan, disk_prefetch,
                disk_amcache, timeline_mft, memory_malfind. MITRE T1071.001 · T1055 · T1547.001.
                Confidence 0.93.
              </p>
            </li>
            <li>
              <div className="flex items-baseline gap-3">
                <span className="rounded border border-confirmed/50 bg-confirmed/10 px-1.5 py-0.5 text-[10px] text-confirmed">
                  CONFIRMED · CRITICAL
                </span>
                <span className="text-foreground">Registry persistence — HKCU\Run\Updater</span>
              </div>
              <p className="mt-1 text-muted-foreground">
                registry_autoruns + disk_amcache SHA match. T1547.001. Confidence 0.91.
              </p>
            </li>
            <li>
              <div className="flex items-baseline gap-3">
                <span className="rounded border border-confirmed/50 bg-confirmed/10 px-1.5 py-0.5 text-[10px] text-confirmed">
                  CONFIRMED · CRITICAL
                </span>
                <span className="text-foreground">PowerShell parent-child staging</span>
              </div>
              <p className="mt-1 text-muted-foreground">
                windows_process_creation + disk_prefetch + yara_keyword_scan. T1059.001 · T1105.
                Confidence 0.74.
              </p>
            </li>
          </ol>

          <h2 className="mt-8 text-base font-semibold uppercase tracking-widest text-inferred">
            3 · Inferred / Capped
          </h2>
          <hr className="my-3 border-inferred/30" />
          <p className="text-muted-foreground">
            <span className="rounded border border-inferred/50 bg-inferred/10 px-1.5 py-0.5 text-[10px] text-inferred">
              INFERRED · HIGH
            </span>
            <span className="ml-2 text-foreground">unknown.exe → 198.51.100.24</span> — the
            falsification engine explicitly capped this claim because no matching disk execution
            evidence (prefetch/amcache) corroborates the network signal. Recommendation: acquire
            endpoint disk image for the subject host before escalating.
          </p>

          <h2 className="mt-8 text-base font-semibold uppercase tracking-widest text-inferred">
            4 · Anti-Forensics &amp; Clock Drift
          </h2>
          <hr className="my-3 border-inferred/30" />
          <ul className="ml-5 list-disc space-y-1 text-foreground/90">
            <li>
              EVTX vs memory_netscan: <span className="text-inferred">+120s</span> offset
              normalized.
            </li>
            <li>
              evil.exe MFT $STANDARD_INFORMATION: created{" "}
              <span className="text-inferred">14:10:05Z</span>, modified{" "}
              <span className="text-inferred">14:02:05Z</span> — timestomping flagged with{" "}
              <span className="text-inferred">×1.12</span> confidence multiplier.
            </li>
          </ul>

          <h2 className="mt-8 text-base font-semibold uppercase tracking-widest text-blocked">
            5 · Integrity &amp; Spoliation
          </h2>
          <hr className="my-3 border-blocked/30" />
          <p className="text-foreground/90">
            SafePathPolicy intercepted{" "}
            <span className="text-blocked">2 unsanctioned write attempts</span> targeting
            <span className="text-blocked"> /case/evidence/mft.csv</span>. Both transactions
            dropped. SHA-256 chain re-verified;
            <span className="text-confirmed"> 0 modifications</span> to evidence.
          </p>

          <h2 className="mt-8 text-base font-semibold uppercase tracking-widest text-confirmed">
            6 · Recommendations
          </h2>
          <hr className="my-3 border-confirmed/30" />
          <ol className="ml-5 list-decimal space-y-1 text-foreground/90">
            <li>Block egress to 203.0.113.50/32 and 198.51.100.24/32 at perimeter.</li>
            <li>Quarantine the host; preserve memory image and MFT.</li>
            <li>Remove HKCU\Run\Updater value; rotate credentials for the affected user.</li>
            <li>Acquire full disk image for unknown.exe corroboration.</li>
          </ol>

          <footer className="mt-10 border-t border-border pt-4 text-[10px] uppercase tracking-widest text-muted-foreground">
            Generated by ProofSIFT v1.0 · Audit hash: 9f3c2b01…44ae · Reviewed by Critic ✓
          </footer>
        </article>
      </Panel>
    </div>
  );
}
