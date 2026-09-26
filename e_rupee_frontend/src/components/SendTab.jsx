import { useState } from "react";
import { api } from "../api";
import Pipeline from "./Pipeline";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default function SendTab({ wallets, onDisclosureCreated }) {
  const [senderAddr, setSenderAddr] = useState("");
  const [receiverAddr, setReceiverAddr] = useState("");
  const [amount, setAmount] = useState("500");
  const [pipeline, setPipeline] = useState({});
  const [result, setResult] = useState(null);
  const [sending, setSending] = useState(false);

  const sender = wallets.find((w) => w.address === senderAddr);

  async function handleSend() {
    if (!sender || !receiverAddr || !amount) return;
    setSending(true);
    setResult(null);
    setPipeline({ sign: "active" });

    try {
      await sleep(500);
      setPipeline({ sign: "done", prove: "active" });

      await sleep(500);
      setPipeline({ sign: "done", prove: "done", verify: "active" });

      const { data } = await api.sendTransaction({
        sender_private_key: sender.private_key,
        sender_public_key: sender.public_key,
        sender_zkp_secret: sender.zkp_secret,
        sender_zkp_public: sender.zkp_public,
        sender_address: sender.address,
        receiver_address: receiverAddr,
        amount: Number(amount),
      });

      await sleep(400);

      if (data.accepted) {
        setPipeline({ sign: "done", prove: "done", verify: "done", record: "done" });
      } else {
        setPipeline({ sign: "done", prove: "done", verify: "failed" });
      }

      setResult(data);

      if (data.accepted && data.requires_disclosure && data.tx_hash) {
        onDisclosureCreated(data.tx_hash);
      }
    } catch (e) {
      setPipeline({ sign: "failed" });
      setResult({ accepted: false, reason: "Could not reach the backend server." });
    } finally {
      setSending(false);
    }
  }

  return (
    <div>
      <h1 className="page-title">Send e-Rupees</h1>
      <p className="page-sub">
        Every transfer is signed, proven with a zero-knowledge proof, and
        checked against the ledger before being recorded. Watch the pipeline
        below light up as each stage completes.
      </p>

      <div className="card">
        <h3>Transfer</h3>

        <div className="field-row">
          <div className="field">
            <label>From wallet</label>
            <select value={senderAddr} onChange={(e) => setSenderAddr(e.target.value)}>
              <option value="">Select sender...</option>
              {wallets.map((w) => (
                <option key={w.address} value={w.address}>
                  {w.label} ({w.address.slice(0, 10)}...)
                </option>
              ))}
            </select>
          </div>

          <div className="field">
            <label>To address</label>
            <select value={receiverAddr} onChange={(e) => setReceiverAddr(e.target.value)}>
              <option value="">Select receiver...</option>
              {wallets
                .filter((w) => w.address !== senderAddr)
                .map((w) => (
                  <option key={w.address} value={w.address}>
                    {w.label} ({w.address.slice(0, 10)}...)
                  </option>
                ))}
            </select>
          </div>

          <div className="field" style={{ minWidth: 140 }}>
            <label>Amount (Rs)</label>
            <input
              type="number"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
            />
          </div>

          <button
            className="btn gold"
            onClick={handleSend}
            disabled={sending || !sender || !receiverAddr || !amount}
          >
            {sending ? "Processing..." : "Send"}
          </button>
        </div>

        <p className="hint">
          Amounts of Rs 2,00,000 or more will trigger the AML compliance
          layer (see the Compliance tab) instead of staying fully private.
        </p>

        <Pipeline status={pipeline} />

        {result && (
          <div className={`result-banner ${result.accepted ? "success" : "error"}`}>
            {result.accepted ? "Accepted: " : "Rejected: "}
            {result.reason}
            {result.accepted && (
              <>
                {" "}
                {result.requires_disclosure ? (
                  <span className="tag flagged" style={{ marginLeft: 8 }}>
                    Flagged for AML disclosure
                  </span>
                ) : (
                  <span className="tag private" style={{ marginLeft: 8 }}>
                    Stayed fully private
                  </span>
                )}
              </>
            )}
          </div>
        )}

        {wallets.length < 2 && (
          <p className="hint">Create at least two wallets first, in the Wallet tab.</p>
        )}
      </div>
    </div>
  );
}