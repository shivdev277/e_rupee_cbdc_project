const STAGES = [
  { key: "sign", label: "Sign (ECDSA)" },
  { key: "prove", label: "ZK Proof (Schnorr)" },
  { key: "verify", label: "Ledger Verify" },
  { key: "record", label: "Recorded" },
];

// status: "idle" | { [stageKey]: "active" | "done" | "failed" }
export default function Pipeline({ status }) {
  return (
    <div className="pipeline">
      {STAGES.map((stage, i) => {
        const state = status?.[stage.key] || "";
        return (
          <div className={`stage ${state}`} key={stage.key}>
            <span className="num">STAGE {i + 1}</span>
            <span className="name">{stage.label}</span>
          </div>
        );
      })}
    </div>
  );
}