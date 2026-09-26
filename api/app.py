"""
app.py
-------
This file implements STEP 10 (bonus): THE API LAYER.

WHY THIS FILE EXISTS:
Everything built in Steps 3-8 is plain Python code, callable only from
another Python file or a terminal. A browser-based frontend (React)
cannot call Python functions directly -- it can only talk over HTTP
(sending requests to a URL and getting a response back).

This file wraps every backend function we already built and tested
inside a small Flask web server, exposing them as simple HTTP
endpoints. No new cryptography is introduced here -- this file is
purely "plumbing" that lets a web UI reach the real logic underneath.

ENDPOINTS PROVIDED:
    POST /api/wallet/create        -> create a new wallet (Step 3)
    POST /api/wallet/split         -> split a private key into shares (Step 3)
    POST /api/wallet/recover       -> rebuild a key from shares (Step 3)
    POST /api/transaction/send     -> sign + ZK-prove + submit a transaction
                                       (Steps 4, 5, 6 combined)
    GET  /api/ledger               -> view the ledger's stored hashes (Step 6)
    GET  /api/compliance/regulator-key
                                    -> DEMO ONLY: exposes the regulator's
                                       key so a presentation can show the
                                       AML unlock flow live. A real system
                                       would NEVER expose this over an API.
    POST /api/compliance/decrypt   -> decrypt a stored disclosure package
                                       using a regulator key (Step 7)

NOTE ON SECURITY IN THIS DEMO:
For simplicity, private keys and ZKP secrets are passed through the API
rather than staying only on the client device. In a real production
system, private keys would NEVER leave the user's device/wallet app --
only signatures and proofs would be sent over the network. This
simplification is clearly flagged here and in the report as a
DEMO-ONLY compromise, made purely to keep the frontend simple to build.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "wallet"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "zkp"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ledger"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "compliance"))

from flask import Flask, request, jsonify
from flask_cors import CORS

from key_generation import generate_wallet
from shamir_secret_sharing import (
    split_secret, reconstruct_secret,
    private_key_hex_to_int, int_to_private_key_hex,
)
from transaction import create_transaction, sign_transaction
from schnorr_proof import generate_zkp_keypair, create_proof
from mock_ledger import init_ledger, submit_transaction, view_ledger
from aml_module import (
    generate_regulator_key, requires_disclosure,
    create_disclosure_package, decrypt_disclosure_package,
)

app = Flask(__name__)
CORS(app)  # allows the React dev server (a different port) to call this API

# Set up the ledger database once when the server starts
init_ledger()

# One regulator key for the whole demo session (kept server-side in memory).
# In a real system this would be protected far more carefully (e.g. its
# own Shamir split across multiple compliance officers).
_REGULATOR_KEY = generate_regulator_key()

# In-memory store of disclosure packages, keyed by transaction hash, so the
# frontend can later ask to "unlock" a specific large transaction for demo
# purposes.
_disclosure_packages = {}


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/wallet/create", methods=["POST"])
def api_create_wallet():
    """Creates a new wallet: ECDSA keypair + a ZKP identity keypair."""
    private_key, public_key, address = generate_wallet()
    zkp_secret, zkp_public = generate_zkp_keypair()

    return jsonify({
        "private_key": private_key,
        "public_key": public_key,
        "address": address,
        "zkp_secret": str(zkp_secret),
        "zkp_public": str(zkp_public),
    })


@app.route("/api/wallet/split", methods=["POST"])
def api_split_wallet():
    """
    Body: { "private_key": "...", "threshold": 3, "total_shares": 5 }
    Returns the shares to distribute to different custodians.
    """
    data = request.get_json()
    private_key_hex = data["private_key"]
    threshold = data.get("threshold", 3)
    total_shares = data.get("total_shares", 5)

    secret_int = private_key_hex_to_int(private_key_hex)
    shares = split_secret(secret_int, threshold, total_shares)

    return jsonify({
        "shares": [{"x": x, "y": str(y)} for x, y in shares],
        "threshold": threshold,
        "total_shares": total_shares,
    })


@app.route("/api/wallet/recover", methods=["POST"])
def api_recover_wallet():
    """
    Body: { "shares": [{"x": 2, "y": "123..."}, ...] }
    Returns the reconstructed private key.
    """
    data = request.get_json()
    shares = [(s["x"], int(s["y"])) for s in data["shares"]]

    recovered_int = reconstruct_secret(shares)
    recovered_hex = int_to_private_key_hex(recovered_int)

    return jsonify({"private_key": recovered_hex})


@app.route("/api/transaction/send", methods=["POST"])
def api_send_transaction():
    """
    Body: {
        "sender_private_key": "...",
        "sender_public_key": "...",
        "sender_zkp_secret": "...",
        "sender_zkp_public": "...",
        "sender_address": "...",
        "receiver_address": "...",
        "amount": 500
    }

    Runs the full pipeline: create -> sign -> ZK-prove -> submit to ledger.
    """
    data = request.get_json()

    tx = create_transaction(
        data["sender_address"], data["receiver_address"], data["amount"]
    )
    signature = sign_transaction(tx, data["sender_private_key"])
    proof = create_proof(int(data["sender_zkp_secret"]), int(data["sender_zkp_public"]))

    accepted, reason = submit_transaction(
        tx, signature, data["sender_public_key"],
        int(data["sender_zkp_public"]), proof,
    )

    response = {
        "accepted": accepted,
        "reason": reason,
        "transaction": tx,
    }

    # If this transaction crosses the AML threshold, create (and store) a
    # disclosure package server-side, so it can be "unlocked" later via
    # the compliance endpoint below -- purely for demo purposes.
    if accepted and requires_disclosure(data["amount"]):
        from transaction import hash_transaction
        tx_hash = hash_transaction(tx)
        package = create_disclosure_package(tx, _REGULATOR_KEY)
        _disclosure_packages[tx_hash] = package
        response["requires_disclosure"] = True
        response["tx_hash"] = tx_hash
    else:
        response["requires_disclosure"] = False

    return jsonify(response)


@app.route("/api/ledger", methods=["GET"])
def api_view_ledger():
    """Returns everything the ledger actually stores -- hashes only."""
    rows = view_ledger()
    return jsonify([
        {"tx_hash": h, "status": s, "recorded_at": t} for h, s, t in rows
    ])


@app.route("/api/compliance/regulator-key", methods=["GET"])
def api_get_regulator_key():
    """
    DEMO ONLY. Exposes the regulator's AES key so a presentation can show
    the selective-disclosure "unlock" flow live. A real deployment would
    NEVER expose this key through a public API endpoint.
    """
    return jsonify({"regulator_key": _REGULATOR_KEY.hex()})


@app.route("/api/compliance/decrypt", methods=["POST"])
def api_decrypt_disclosure():
    """
    Body: { "tx_hash": "...", "regulator_key": "..." (hex) }
    Attempts to decrypt a stored disclosure package.
    """
    data = request.get_json()
    tx_hash = data["tx_hash"]
    regulator_key = bytes.fromhex(data["regulator_key"])

    package = _disclosure_packages.get(tx_hash)
    if package is None:
        return jsonify({"success": False, "reason": "No disclosure package found for this transaction"}), 404

    try:
        revealed = decrypt_disclosure_package(package, regulator_key)
        return jsonify({"success": True, "transaction": revealed})
    except Exception:
        return jsonify({"success": False, "reason": "Decryption failed - wrong key"}), 403


if __name__ == "__main__":
    print("=" * 60)
    print("e-Rupee Cybersecurity Framework - API server")
    print("=" * 60)
    print("Running on http://127.0.0.1:5000")
    print("Regulator key (DEMO ONLY, would never be printed in real life):")
    print(f"  {_REGULATOR_KEY.hex()}")
    app.run(debug=True, port=5000)