import { useState } from "react";
import { api } from "../api";

export default function ComplianceTab({ pendingTxHash }) {
  const [txHash, setTxHash] = useState(pendingTxHash || "");
  const [regulatorKey, setRegulatorKey] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  async function revealDemoKey() {
    const { data } = await api.getRegulatorKey();
    setRegulatorKey(data.regulator_key);
  }

  function useWrongKey() {
    setRegulatorKey("00".repeat(32));
  }

  async function attemptDecrypt() {
    if (!txHash || !regulatorKey) return;
    setBusy(true);
    setResult(null);
    try {
      const { data } = await api.decryptDisclosure(txHash, regulatorKey);
      setResult(data);
    } catch (e) {
      setResult({ success: false, reason: "Request failed." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Compliance / Selective Disclosure</h1>
      <p className="page-sub">
        Transactions of Rs 2,00,000 or more are encrypted into a disclosure
        package that only an authorised regulator key can open. Small
        transactions never generate a package at all &mdash; they simply
        stay private.
      </p>

      <div className="card">
        <h3>Attempt to unlock a large transaction</h3>

        <div className="field-row">
          <div className="field" style={{ minWidth: 340 }}>
            <label>Transaction hash</label>
            <input
              value={txHash}
              onChange={(e) => setTxHash(e.target.value)}
              placeholder="Send a Rs 2,00,000+ transaction first"
            />
          </div>
        </div>

        <div className="field-row">
          <div className="field" style={{ minWidth: 340 }}>
            <label>Regulator key</label>
            <input
              value={regulatorKey}
              onChange={(e) => setRegulatorKey(e.target.value)}
              placeholder="Paste a regulator key, or use a button below"
            />
          </div>
        </div>

        <div className="field-row">
          <button className="btn outline" onClick={revealDemoKey}>
            Reveal correct key (demo only)
          </button>
          <button className="btn outline" onClick={useWrongKey}>
            Use a wrong key instead
          </button>
          <button className="btn gold" onClick={attemptDecrypt} disabled={busy || !txHash || !regulatorKey}>
            {busy ? "Decrypting..." : "Attempt decrypt"}
          </button>
        </div>

        <p className="hint">
          In a real deployment, the regulator key would never be exposed by
          an API &mdash; it would be held under legal process, likely split
          across several officials. It is shown here only so the unlock flow
          can be demonstrated live.
        </p>

        {result && (
          <div className={`result-banner ${result.success ? "success" : "error"}`}>
            {result.success ? (
              <>
                Decryption succeeded. Revealed transaction:
                <pre style={{ marginTop: 8, fontSize: 12 }}>
                  {JSON.stringify(result.transaction, null, 2)}
                </pre>
              </>
            ) : (
              <>Decryption blocked: {result.reason}</>
            )}
          </div>
        )}
      </div>
    </div>
  );
}