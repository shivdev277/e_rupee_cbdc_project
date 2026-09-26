import { useState, useEffect } from "react";
import { api } from "../api";

export default function LedgerTab() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);

  async function refresh() {
    setLoading(true);
    try {
      const { data } = await api.getLedger();
      setRows(data.reverse());
    } catch (e) {
      // silent - backend may not be running yet
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  return (
    <div>
      <h1 className="page-title">RBI Ledger</h1>
      <p className="page-sub">
        This is everything the ledger actually stores. There is no sender,
        receiver, or amount column at all &mdash; only a transaction hash, a
        status, and a timestamp. This is the privacy guarantee in practice,
        not just a claim.
      </p>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3>Stored entries ({rows.length})</h3>
          <button className="btn outline" onClick={refresh} disabled={loading}>
            {loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>

        {rows.length === 0 ? (
          <p className="hint">
            No transactions recorded yet. Send one from the Send tab.
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Transaction hash</th>
                <th>Status</th>
                <th>Recorded at</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.tx_hash}>
                  <td className="hash">{r.tx_hash}</td>
                  <td>
                    <span className="tag ok">{r.status}</span>
                  </td>
                  <td>{new Date(r.recorded_at * 1000).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}