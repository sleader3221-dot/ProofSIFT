import { createFileRoute } from "@tanstack/react-router";
import ProofSIFTArchitectureFlow from "@/frontend/ProofSIFTArchitectureFlow";

export const Route = createFileRoute("/")({
  head: () => ({ meta: [{ title: "Architecture · ProofSIFT" }] }),
  component: ProofSIFTArchitectureFlow,
});
