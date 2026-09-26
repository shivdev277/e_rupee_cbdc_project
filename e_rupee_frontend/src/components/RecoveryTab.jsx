import { useState } from "react";
import { api } from "../api";

const CUSTODIANS = ["Phone", "Bank", "Trusted Contact", "RBI Recovery Service", "Backup Location"];

export default function RecoveryTab({ wallets }) {
  const [walletAddr, setWalletAddr] = useState("");
  const [shares, setShares] = useState([]);
  const [kept, setKept] = useState([]);
  const [recovered, setRecovered] = useState(null);
  const [busy, setBusy] = useState(false);

  const wallet = wallets.find((w) => w.address === walletAddr);

  async function handleSplit() {
    if (!wallet) return;
    setBusy(true);
    setRecovered(null);
    try {
      const { data } = await api.splitWallet(wallet.private_key, 3, 5);
      setShares(data.shares);
      setKept(data.shares.map((_, i) => i)); // start with all kept
    } finally {
      setBusy(false);
    }
  }

  function toggleShare(i) {
    setKept((prev) =>
      prev.includes(i) ? prev.filter((x) => x !== i) : [...prev, i]
    );
  }

  async function handleRecover() {
    if (kept.length < 3) return;
    setBusy(true);
    try {
      const chosen = kept.slice(0, 3).map((i) => shares[i]);
      const { data } = await api.recoverWallet(chosen);
      setRecovered({
        key: data.private_key,
        matches: data.private_key === wallet.private_key,
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Key Recovery</h1>
      <p className="page-sub">
        Simulates losing a device. The wallet's private key is split into 5
        shares using Shamir's Secret Sharing &mdash; any 3 can rebuild it,
        any 2 or fewer reveal nothing.
      </p>

      <div className="card">
        <h3>1. Choose a wallet to split</h3>
        <div className="field-row">
          <div className="field">
            <select value={walletAddr} onChange={(e) => setWalletAddr(e.target.value)}>
              <option value="">Select wallet...</option>
              {wallets.map((w) => (
                <option key={w.address} value={w.address}>
                  {w.label} ({w.address.slice(0, 10)}...)
                </option>
              ))}
            </select>
          </div>
          <button className="btn gold" onClick={handleSplit} disabled={!wallet || busy}>
            Split into 5 shares
          </button>
        </div>

        {shares.length > 0 && (
          <>
            <h3 style={{ marginTop: 22 }}>2. Simulate losing some shares</h3>
            <p className="hint">
              Click a card to mark it lost. You need at least 3 remaining to recover.
            </p>
            <div className="share-grid">
              {shares.map((s, i) => (
                <div
                  key={i}
                  className={`share-card ${kept.includes(i) ? "kept" : "lost"}`}
                  onClick={() => toggleShare(i)}
                >
                  <span className="who">{CUSTODIANS[i]}</span>
                  {kept.includes(i) ? "Available" : "LOST"}
                </div>
              ))}
            </div>

            <button
              className="btn gold"
              onClick={handleRecover}
              disabled={kept.length < 3 || busy}
            >
              Recover wallet ({kept.length} of {shares.length} available)
            </button>

            {recovered && (
              <div className={`result-banner ${recovered.matches ? "success" : "error"}`} style={{ marginTop: 16 }}>
                {recovered.matches
                  ? "Recovery successful. The reconstructed key exactly matches the original wallet."
                  : "Recovery failed. Reconstructed key does not match."}
              </div>
            )}
          </>
        )}

        {wallets.length === 0 && (
          <p className="hint">Create a wallet first, in the Wallet tab.</p>
        )}
      </div>
    </div>
  );
}