const BASE_URL = "http://127.0.0.1:5000";

async function request(path, options = {}) {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 403 && res.status !== 404) {
    throw new Error(data.reason || `Request to ${path} failed`);
  }
  return { status: res.status, data };
}

export const api = {
  health: () => request("/api/health"),

  createWallet: () => request("/api/wallet/create", { method: "POST" }),

  splitWallet: (privateKey, threshold = 3, totalShares = 5) =>
    request("/api/wallet/split", {
      method: "POST",
      body: JSON.stringify({
        private_key: privateKey,
        threshold,
        total_shares: totalShares,
      }),
    }),

  recoverWallet: (shares) =>
    request("/api/wallet/recover", {
      method: "POST",
      body: JSON.stringify({ shares }),
    }),

  sendTransaction: (payload) =>
    request("/api/transaction/send", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getLedger: () => request("/api/ledger"),

  getRegulatorKey: () => request("/api/compliance/regulator-key"),

  decryptDisclosure: (txHash, regulatorKey) =>
    request("/api/compliance/decrypt", {
      method: "POST",
      body: JSON.stringify({ tx_hash: txHash, regulator_key: regulatorKey }),
    }),
};