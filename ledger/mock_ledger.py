"""
mock_ledger.py
---------------
This file implements STEP 6: THE LEDGER + VERIFIER.

This is where everything we've built so far comes together into one
real transaction flow, matching our architecture diagram:

    User wallet --> signs tx + builds ZK proof
                --> HSM/key layer (Shamir, already built in Step 3)
                --> ZKP Verifier checks the proof
                --> RBI Ledger records ONLY a proof-hash (not raw data)

CONCEPT USED: Hashing (SHA-256) + combining previous concepts together

WHY THE LEDGER ONLY STORES A HASH:
This is the actual privacy mechanism in practice. If the ledger stored
the full transaction (sender, receiver, amount), anyone with ledger
access could see everyone's complete financial history -- this is
exactly Problem 1 (privacy leakage) from our problem statement.

Instead, our ledger stores ONLY:
    - the transaction's hash (a fingerprint, not the data itself)
    - a status (VALID / REJECTED)
    - a timestamp

This is enough to prove "this transaction happened and was verified"
without exposing WHO paid WHOM how much. We use SQLite here (a small,
file-based database) to make this feel like a real persistent ledger
rather than just a Python list that disappears when the program ends.

DOUBLE-SPEND PROTECTION:
Before accepting a transaction, the ledger checks whether this exact
transaction hash has ALREADY been recorded. If so, it's a double-spend
attempt (the same "token" being spent twice) and gets rejected. This
directly defends against the double-spend threat from our threat model.
"""

import sys
import os
import sqlite3
import time

# Allow importing our previously-built modules from sibling folders
# (wallet/ and zkp/), since this file lives inside ledger/.
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "wallet"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "zkp"))

from transaction import hash_transaction, verify_transaction   # from wallet/
from schnorr_proof import verify_proof                          # from zkp/


DB_PATH = os.path.join(os.path.dirname(__file__), "rbi_ledger.db")


def init_ledger(db_path=DB_PATH):
    """
    Creates the ledger database (and table) if it doesn't already exist.
    Notice the table ONLY has: tx_hash, status, recorded_at.
    There is deliberately NO column for sender, receiver, or amount.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            tx_hash TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            recorded_at REAL NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def _is_duplicate(tx_hash, db_path=DB_PATH):
    """Checks whether this transaction hash has already been recorded."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM ledger WHERE tx_hash = ?", (tx_hash,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def _record(tx_hash, status, db_path=DB_PATH):
    """Writes ONLY the hash + status + timestamp to the ledger."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO ledger (tx_hash, status, recorded_at) VALUES (?, ?, ?)",
        (tx_hash, status, time.time()),
    )
    conn.commit()
    conn.close()


def submit_transaction(transaction, signature_hex, sender_public_key_hex,
                        zkp_public_y, zkp_proof, db_path=DB_PATH):
    """
    The full verifier pipeline. A transaction is only accepted onto the
    ledger if ALL of these pass, in order:

        1. Digital signature is valid       (Step 4 -- authenticity/integrity)
        2. Zero-knowledge proof is valid    (Step 5 -- proves ownership
                                              without exposing the secret)
        3. Not a duplicate / double-spend   (Step 6 -- ledger's own check)

    Returns:
        (accepted: bool, reason: str)
    """
    tx_hash = hash_transaction(transaction)

    # --- Check 1: Signature ---
    if not verify_transaction(transaction, signature_hex, sender_public_key_hex):
        return False, "REJECTED: invalid or forged signature"

    # --- Check 2: Zero-Knowledge Proof ---
    if not verify_proof(zkp_public_y, zkp_proof):
        return False, "REJECTED: invalid zero-knowledge proof"

    # --- Check 3: Double-spend check ---
    if _is_duplicate(tx_hash, db_path):
        return False, "REJECTED: duplicate transaction (double-spend attempt)"

    # All checks passed -- record ONLY the hash, nothing else
    _record(tx_hash, "VALID", db_path)
    return True, f"ACCEPTED: transaction recorded with hash {tx_hash[:16]}..."


def view_ledger(db_path=DB_PATH):
    """
    Prints the full ledger -- demonstrating that only hashes are stored,
    never the actual sender, receiver, or amount.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT tx_hash, status, recorded_at FROM ledger")
    rows = cursor.fetchall()
    conn.close()
    return rows


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python ledger/mock_ledger.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from key_generation import generate_wallet
    from transaction import create_transaction, sign_transaction
    from schnorr_proof import generate_zkp_keypair, create_proof

    # Start with a clean ledger each demo run
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_ledger()

    print("=" * 60)
    print("STEP 6 DEMO: Full transaction flow through the ledger")
    print("=" * 60)

    # 1. Set up Alice's wallet + her ZKP keypair (proves ownership)
    alice_priv, alice_pub, alice_address = generate_wallet()
    bob_priv, bob_pub, bob_address = generate_wallet()
    zkp_secret, zkp_public = generate_zkp_keypair()

    # 2. Alice creates and signs a transaction
    tx = create_transaction(alice_address, bob_address, amount=750)
    signature = sign_transaction(tx, alice_priv)
    zkp_proof = create_proof(zkp_secret, zkp_public)

    print(f"\nAlice sends 750 e-Rupees to Bob.")
    print("(This amount is only known to Alice's wallet -- the ledger below")
    print(" will NOT show 750, or Alice's/Bob's addresses, anywhere.)")

    # 3. Submit to the ledger -- this runs signature + ZKP + double-spend checks
    print(f"\n[SUBMISSION 1] First time submitting this transaction...")
    accepted, reason = submit_transaction(tx, signature, alice_pub, zkp_public, zkp_proof)
    print(f"Result: {reason}")

    # 4. ATTACK SIMULATION: replay the exact same transaction again (double-spend)
    print(f"\n[SUBMISSION 2] Re-submitting the SAME transaction again (double-spend attempt)...")
    accepted2, reason2 = submit_transaction(tx, signature, alice_pub, zkp_public, zkp_proof)
    print(f"Result: {reason2}")

    # 5. Show what the ledger actually stores
    print(f"\n--- What the RBI ledger actually contains ---")
    rows = view_ledger()
    for tx_hash, status, recorded_at in rows:
        print(f"  hash: {tx_hash[:24]}...  status: {status}  time: {recorded_at:.2f}")
    print("\nNotice: no sender, no receiver, no amount is visible above.")
    print("This is the privacy guarantee our architecture provides.")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"First submission accepted:        {'PASSED' if accepted else 'FAILED'}")
    print(f"Double-spend correctly rejected:  {'PASSED' if not accepted2 else 'FAILED'}")