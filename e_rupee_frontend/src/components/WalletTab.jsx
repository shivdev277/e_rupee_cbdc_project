import { useState } from "react";
import { api } from "../api";

function short(str, n = 18) {
  if (!str) return "";
  return str.length > n ? `${str.slice(0, n)}...` : str;
}

export default function WalletTab({ wallets, onCreateWallet }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  async function handleCreate() {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.createWallet();
      onCreateWallet(data);
    } catch (e) {
      setError(
        "Could not reach the backend. Is the Flask server running on port 5000?"
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Wallets</h1>
      <p className="page-sub">
        Each wallet holds a private key (ECDSA), a public key, and a
        zero-knowledge identity secret. The private key never leaves this
        demo's local state, exactly like it would stay on a real device.
      </p>

      <div className="card">
        <h3>Create a new wallet</h3>
        <p className="hint">
          Generates a fresh key pair using the SECP256k1 curve, plus a
          Schnorr zero-knowledge identity.
        </p>
        <button className="btn gold" onClick={handleCreate} disabled={loading}>
          {loading ? "Generating..." : "Create Wallet"}
        </button>
        {error && (
          <p style={{ color: "#7a2820", marginTop: 12, fontSize: 13 }}>
            {error}
          </p>
        )}
      </div>

      {wallets.length > 0 && (
        <div className="card">
          <h3>Your wallets ({wallets.length})</h3>
          {wallets.map((w) => (
            <div className="wallet-card" key={w.address}>
              <span className="key-label">{w.label}</span>
              <div className="addr">{w.address}</div>
              <div style={{ marginTop: 10 }}>
                <span className="key-label">Private key (kept local only)</span>
                <div className="key-block">{short(w.private_key, 40)}</div>
              </div>
              <div>
                <span className="key-label">Public key</span>
                <div className="key-block">{short(w.public_key, 40)}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}