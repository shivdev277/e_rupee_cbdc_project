"""
transaction.py
---------------
This file implements STEP 4: TRANSACTION SIGNING.

CONCEPT USED: Digital Signatures (ECDSA)

THE SIMPLE IDEA:
When you send someone money, the system needs proof that the request
really came from YOU, and that nobody tampered with it (changed the
amount, changed the receiver, etc.) after you created it.

A digital signature does this using your PRIVATE KEY:
    1. You take the transaction details (sender, receiver, amount, time)
       and HASH them into a single fingerprint (SHA-256).
    2. You SIGN that fingerprint with your private key -> this produces
       a signature that only YOUR private key could have created.
    3. Anyone holding your PUBLIC KEY can VERIFY the signature is valid
       for this exact transaction -- but they can never forge a new
       signature themselves, since they don't have your private key.

If even a single character of the transaction changes (e.g. the amount
is edited from 500 to 5000 by an attacker), the hash changes completely,
the old signature becomes invalid, and the tampering is instantly
detectable. This is what gives the transaction INTEGRITY and
AUTHENTICITY.

This directly defends against:
    - Man-in-the-middle (MITM) tampering  (Threat Model, Section 4)
    - Impersonation (someone pretending to be you)
"""

import hashlib
import json
import time

from key_generation import load_private_key, load_public_key


def create_transaction(sender_address, receiver_address, amount):
    """
    Builds a plain transaction object (not yet signed).

    Using a dictionary keeps this simple and human-readable -- in a real
    system this might be a more compact binary format, but the security
    principle is identical.
    """
    return {
        "sender": sender_address,
        "receiver": receiver_address,
        "amount": amount,
        "timestamp": time.time(),
    }


def hash_transaction(transaction):
    """
    Converts the transaction dictionary into a single SHA-256 hash.

    IMPORTANT: json.dumps with sort_keys=True ensures the SAME
    transaction always produces the SAME hash, regardless of the
    order fields were added in -- this consistency is essential,
    otherwise signatures would randomly fail to verify.
    """
    tx_string = json.dumps(transaction, sort_keys=True)
    return hashlib.sha256(tx_string.encode()).hexdigest()


def sign_transaction(transaction, sender_private_key_hex):
    """
    Signs a transaction's hash using the sender's private key.

    Returns:
        signature_hex (str): the digital signature, in hex format.
        This gets attached to the transaction before it's sent to
        the network / ledger.
    """
    private_key = load_private_key(sender_private_key_hex)
    tx_hash = hash_transaction(transaction)

    # .sign() expects bytes, so we encode the hash string first
    signature = private_key.sign(tx_hash.encode())
    return signature.hex()


def verify_transaction(transaction, signature_hex, sender_public_key_hex):
    """
    Verifies that:
      1. The signature was created by the holder of the matching
         private key (authenticity), AND
      2. The transaction data has not been altered since signing
         (integrity) -- because the hash is recomputed fresh here
         and must match what was originally signed.

    Returns:
        True  -> transaction is authentic and untampered
        False -> either forged, or tampered with after signing
    """
    public_key = load_public_key(sender_public_key_hex)
    tx_hash = hash_transaction(transaction)
    signature = bytes.fromhex(signature_hex)

    try:
        return public_key.verify(signature, tx_hash.encode())
    except Exception:
        # ecdsa raises an exception (BadSignatureError) on failure
        # rather than returning False -- we catch it and return False
        # so this function is simple and predictable to use.
        return False


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python wallet/transaction.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from key_generation import generate_wallet

    print("=" * 60)
    print("STEP 4 DEMO: Signing and verifying a transaction")
    print("=" * 60)

    # 1. Create two wallets -- sender (Alice) and receiver (Bob)
    alice_priv, alice_pub, alice_address = generate_wallet()
    bob_priv, bob_pub, bob_address = generate_wallet()

    print(f"\nAlice's wallet address: {alice_address}")
    print(f"Bob's wallet address:   {bob_address}")

    # 2. Alice creates a transaction: sending 500 e-Rupees to Bob
    tx = create_transaction(alice_address, bob_address, amount=500)
    print(f"\nTransaction created:\n{json.dumps(tx, indent=2)}")

    # 3. Alice signs it with HER private key
    signature = sign_transaction(tx, alice_priv)
    print(f"\nSignature (created with Alice's private key):\n{signature[:64]}...")

    # 4. The network/ledger verifies it using Alice's PUBLIC key
    is_valid = verify_transaction(tx, signature, alice_pub)
    print(f"\n[CHECK 1] Verifying original, untampered transaction...")
    print(f"Result: {'VALID' if is_valid else 'INVALID'}")

    # 5. ATTACK SIMULATION: an attacker intercepts and changes the amount
    print(f"\n--- Simulating a Man-in-the-Middle (MITM) attack ---")
    tampered_tx = dict(tx)  # copy the transaction
    tampered_tx["amount"] = 50000  # attacker changes 500 -> 50000
    print(f"Attacker changed amount from 500 to {tampered_tx['amount']}")

    is_tampered_valid = verify_transaction(tampered_tx, signature, alice_pub)
    print(f"\n[CHECK 2] Verifying TAMPERED transaction (same old signature)...")
    print(f"Result: {'VALID' if is_tampered_valid else 'INVALID (tampering detected!)'}")

    # 6. ATTACK SIMULATION: someone tries to forge Alice's signature using
    #    a random OTHER private key (impersonation attempt)
    print(f"\n--- Simulating an impersonation attempt ---")
    attacker_priv, attacker_pub, attacker_address = generate_wallet()
    forged_signature = sign_transaction(tx, attacker_priv)
    is_forged_valid = verify_transaction(tx, forged_signature, alice_pub)
    print(f"Attacker tries to sign Alice's transaction with THEIR OWN key...")
    print(f"\n[CHECK 3] Verifying forged signature against Alice's public key...")
    print(f"Result: {'VALID' if is_forged_valid else 'INVALID (forgery detected!)'}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Genuine transaction:      {'PASSED' if is_valid else 'FAILED'}")
    print(f"Tampering detection:      {'PASSED' if not is_tampered_valid else 'FAILED'}")
    print(f"Forgery detection:        {'PASSED' if not is_forged_valid else 'FAILED'}")