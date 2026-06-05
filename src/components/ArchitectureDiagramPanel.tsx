import { useEffect, useState, type ComponentType } from "react";

import "../frontend/styles.css";

type DiagramState =
  | { status: "loading"; Component?: undefined; error?: undefined }
  | { status: "ready"; Component: ComponentType; error?: undefined }
  | { status: "error"; Component?: undefined; error: Error };

export function ArchitectureDiagramPanel() {
  const [diagram, setDiagram] = useState<DiagramState>({ status: "loading" });

  useEffect(() => {
    let cancelled = false;

    import("../frontend/ProofSIFTArchitectureFlow.jsx")
      .then((module) => {
        if (!cancelled) {
          setDiagram({ status: "ready", Component: module.default });
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setDiagram({
            status: "error",
            error: error instanceof Error ? error : new Error(String(error)),
          });
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (diagram.status === "loading") {
    return (
      <section className="architecture-shell">
        <div className="architecture-intro">
          <div>
            <div className="architecture-intro__eyebrow">ProofSIFT Security Visualization</div>
            <h1>Loading Trust-Boundary Architecture</h1>
          </div>
          <p>Preparing the interactive React Flow graph.</p>
        </div>
      </section>
    );
  }

  if (diagram.status === "error") {
    return (
      <section className="rounded-lg border border-blocked bg-blocked/10 p-5">
        <div className="font-mono text-xs uppercase tracking-widest text-blocked">
          architecture diagram failed to load
        </div>
        <p className="mt-2 text-sm text-foreground">{diagram.error.message}</p>
      </section>
    );
  }

  const Diagram = diagram.Component;
  return <Diagram />;
}
