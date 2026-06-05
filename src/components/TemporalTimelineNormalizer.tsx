import { useMemo, useState } from "react";
import { AlertTriangle, Clock, RotateCcw } from "lucide-react";
import {
  CartesianGrid,
  LabelList,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Panel } from "@/components/Panel";
import { clockDriftDetail } from "@/lib/proofsift-data";

const timelineRows = ["Filesystem", "Event Log", "Network"] as const;

type TimelinePoint = {
  x: number;
  y: number;
  label: string;
  detail: string;
};

function formatOffset(seconds: number) {
  if (seconds === 0) return "T+0s";
  return seconds > 0 ? `T+${seconds}s` : `T${seconds}s`;
}

export function TemporalTimelineNormalizer() {
  const [normalized, setNormalized] = useState(false);
  const rawEvtxOffset = clockDriftDetail.delta_seconds;

  const points = useMemo(() => {
    const evtxOffset = normalized ? 0 : rawEvtxOffset;
    return {
      netscan: [{ x: 0, y: 3, label: "Netscan", detail: "memory_netscan first_seen anchor" }],
      evtx: [
        {
          x: evtxOffset,
          y: 2,
          label: normalized ? "EVTX aligned" : `EVTX raw +${rawEvtxOffset}s`,
          detail: "Event 4688 clock skew corrected against Netscan",
        },
      ],
      prefetch: [{ x: 180, y: 1, label: "Prefetch exec", detail: "EVIL.EXE execution cache" }],
      mft: [{ x: 480, y: 1, label: "MFT creation", detail: "created after execution: anomalous" }],
    } satisfies Record<string, TimelinePoint[]>;
  }, [normalized, rawEvtxOffset]);

  return (
    <Panel
      title="temporal timeline normalizer"
      subtitle="EVTX skew correction + anti-forensics anomaly flag"
      accent={normalized ? "confirmed" : "inferred"}
      action={
        <button
          onClick={() => setNormalized((v) => !v)}
          className="inline-flex items-center gap-2 rounded-md border border-confirmed/50 bg-confirmed/10 px-3 py-1.5 font-mono text-[10px] uppercase tracking-widest text-confirmed transition hover:bg-confirmed/20"
        >
          {normalized ? <RotateCcw className="h-3 w-3" /> : <Clock className="h-3 w-3" />}
          {normalized ? "reset skew" : "normalize time skew"}
        </button>
      }
    >
      <div className="h-[260px] rounded-md border border-border bg-background/40 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <ScatterChart margin={{ top: 28, right: 32, bottom: 18, left: 14 }}>
            <CartesianGrid stroke="var(--border)" strokeDasharray="3 5" opacity={0.65} />
            <XAxis
              type="number"
              dataKey="x"
              domain={[-150, 520]}
              tickFormatter={formatOffset}
              stroke="var(--muted-foreground)"
              tick={{
                fill: "var(--muted-foreground)",
                fontSize: 11,
                fontFamily: "ui-monospace, monospace",
              }}
            />
            <YAxis
              type="number"
              dataKey="y"
              domain={[0.5, 3.5]}
              ticks={[1, 2, 3]}
              tickFormatter={(value) => timelineRows[value - 1] ?? ""}
              stroke="var(--muted-foreground)"
              tick={{
                fill: "var(--muted-foreground)",
                fontSize: 11,
                fontFamily: "ui-monospace, monospace",
              }}
            />
            <Tooltip
              cursor={{ stroke: "var(--confirmed)", strokeOpacity: 0.3 }}
              content={({ active, payload }) => {
                const item = payload?.[0]?.payload as TimelinePoint | undefined;
                if (!active || !item) return null;
                return (
                  <div className="rounded-md border border-border bg-card px-3 py-2 font-mono text-xs shadow-xl">
                    <div className="text-confirmed">{item.label}</div>
                    <div className="text-muted-foreground">{item.detail}</div>
                    <div className="mt-1 text-foreground">{formatOffset(item.x)}</div>
                  </div>
                );
              }}
            />
            <ReferenceLine
              x={0}
              stroke="var(--confirmed)"
              strokeDasharray="4 4"
              label={{ value: "netscan anchor", fill: "var(--confirmed)", fontSize: 10 }}
            />
            <ReferenceLine x={180} stroke="var(--inferred)" strokeDasharray="4 4" opacity={0.7} />
            <Scatter
              name="Netscan"
              data={points.netscan}
              fill="var(--confirmed)"
              isAnimationActive
              animationDuration={900}
            >
              <LabelList dataKey="label" position="top" fill="var(--confirmed)" fontSize={10} />
            </Scatter>
            <Scatter
              name="EVTX"
              data={points.evtx}
              fill={normalized ? "var(--confirmed)" : "var(--inferred)"}
              isAnimationActive
              animationDuration={900}
            >
              <LabelList
                dataKey="label"
                position="top"
                fill={normalized ? "var(--confirmed)" : "var(--inferred)"}
                fontSize={10}
              />
            </Scatter>
            <Scatter
              name="Prefetch"
              data={points.prefetch}
              fill="var(--inferred)"
              isAnimationActive
              animationDuration={900}
            >
              <LabelList dataKey="label" position="top" fill="var(--inferred)" fontSize={10} />
            </Scatter>
            <Scatter
              name="MFT"
              data={points.mft}
              fill="var(--blocked)"
              isAnimationActive
              animationDuration={900}
            >
              <LabelList dataKey="label" position="top" fill="var(--blocked)" fontSize={10} />
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>
      <div className="mt-3 grid gap-3 text-xs md:grid-cols-2">
        <div className="rounded-md border border-confirmed/40 bg-confirmed/5 p-3 font-mono text-confirmed">
          EVTX offset:{" "}
          {normalized ? "0s after normalization" : `+${rawEvtxOffset}s raw skew ahead of Netscan`}
        </div>
        <div className="flex items-start gap-2 rounded-md border border-blocked/50 bg-blocked/10 p-3 text-blocked">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>
            MFT Creation is anomalous: creation timestamp appears after Prefetch execution.
          </span>
        </div>
      </div>
    </Panel>
  );
}
