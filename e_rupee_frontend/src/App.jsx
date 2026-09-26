import { useState } from "react";
import Sidebar from "./components/Sidebar";
import WalletTab from "./components/WalletTab";
import SendTab from "./components/SendTab";
import LedgerTab from "./components/LedgerTab";
import RecoveryTab from "./components/RecoveryTab";
import ComplianceTab from "./components/ComplianceTab";

const WALLET_LABELS = ["Wallet A (Alice)", "Wallet B (Bob)", "Wallet C", "Wallet D", "Wallet E"];

export default function App() {
  const [activeTab, setActiveTab] = useState("wallet");
  const [wallets, setWallets] = useState([]);
  const [pendingTxHash, setPendingTxHash] = useState("");

  function handleCreateWallet(walletData) {
    const label = WALLET_LABELS[wallets.length] || `Wallet ${wallets.length + 1}`;
    setWallets((prev) => [...prev, { ...walletData, label }]);
  }

  return (
    <div className="app-shell">
      <Sidebar activeTab={activeTab} onChange={setActiveTab} />

      <main className="main">
        {activeTab === "wallet" && (
          <WalletTab wallets={wallets} onCreateWallet={handleCreateWallet} />
        )}
        {activeTab === "send" && (
          <SendTab wallets={wallets} onDisclosureCreated={setPendingTxHash} />
        )}
        {activeTab === "ledger" && <LedgerTab />}
        {activeTab === "recovery" && <RecoveryTab wallets={wallets} />}
        {activeTab === "compliance" && (
          <ComplianceTab pendingTxHash={pendingTxHash} />
        )}
      </main>
    </div>
  );
}