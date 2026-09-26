const TABS = [
  { id: "wallet", label: "Wallet" },
  { id: "send", label: "Send" },
  { id: "ledger", label: "Ledger" },
  { id: "recovery", label: "Recovery" },
  { id: "compliance", label: "Compliance" },
];

export default function Sidebar({ activeTab, onChange }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="mark">e₹ Framework</span>
        <span className="sub">Privacy-preserving CBDC security demo</span>
      </div>

      <nav className="nav">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            className={activeTab === tab.id ? "active" : ""}
            onClick={() => onChange(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        Zero-Knowledge Proofs · Threshold Key Management
        <br />
        Backend: Flask · http://127.0.0.1:5000
      </div>
    </aside>
  );
}