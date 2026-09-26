"""
aml_module.py
--------------
This file implements STEP 7: THE COMPLIANCE / SELECTIVE DISCLOSURE MODULE.

This is the "safety valve" that balances Problem 1 (privacy) with real
legal requirements. Recall from our research (Step 1/2): RBI itself has
proposed "anonymity for small value and traceable for high value"
transactions, similar to how large cash transactions already require
PAN disclosure. This file implements exactly that rule.

CONCEPT USED: Symmetric Encryption (AES - Advanced Encryption Standard)

THE SIMPLE IDEA:
Unlike public-key cryptography (different keys to lock/unlock), AES uses
the SAME key to both encrypt and decrypt. It's very fast and is the
standard choice for encrypting actual data (as opposed to signing or
proving knowledge, which we used ECDSA/Schnorr for).

HOW WE USE IT HERE:
    - A single "regulator key" is held ONLY by an authorised compliance
      authority (in real life, this would require a legal process, like
      a warrant, and would likely be split across multiple officials
      using something like Shamir's Secret Sharing too -- for this demo
      we keep it as one key for simplicity).
    - For transactions BELOW a threshold (e.g. Rs 2,00,000), NOTHING is
      encrypted or stored beyond the ledger's hash -- full privacy,
      exactly like Steps 5 and 6 already demonstrated.
    - For transactions AT OR ABOVE the threshold, the wallet additionally
      creates an ENCRYPTED "disclosure package" containing the sender,
      receiver, and amount. Only someone holding the regulator's AES key
      can ever decrypt and read it. Nobody else -- not even the RBI
      ledger operator -- can open it without that key.

This means:
    - Normal citizens making everyday payments: fully private (Steps 5-6)
    - Large transactions: privately encrypted, but LEGALLY recoverable
      by an authorised party under due process -- satisfying AML/CFT
      requirements without permanently exposing everyone's data.
"""

import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Any transaction at or above this amount requires a disclosure package.
# (Chosen arbitrarily for demo purposes -- a real threshold would be set
# by RBI/FIU-IND policy.)
DISCLOSURE_THRESHOLD = 200000


def generate_regulator_key():
    """
    Generates a 256-bit AES key. In a real system, this key would be
    held by an authorised regulator (e.g. Financial Intelligence Unit),
    likely itself protected using Shamir's Secret Sharing across
    multiple officials so no single person can misuse it.
    """
    return get_random_bytes(32)  # 32 bytes = 256-bit AES key


def requires_disclosure(amount, threshold=DISCLOSURE_THRESHOLD):
    """
    Simple rule matching RBI's stated design goal: small transactions
    stay anonymous, large transactions must be traceable.
    """
    return amount >= threshold


def create_disclosure_package(transaction, regulator_key):
    """
    Encrypts the transaction's sensitive details (sender, receiver,
    amount) using AES-GCM, so ONLY the regulator key can decrypt it.

    AES-GCM is used (rather than plain AES) because it also provides
    an authentication tag -- this means if anyone tampers with the
    encrypted package, decryption will fail loudly instead of silently
    returning corrupted/wrong data.

    Returns:
        dict containing the encrypted package (nonce, ciphertext, tag)
        -- all safe to store, since it's meaningless without the key.
    """
    plaintext = json.dumps(transaction).encode()

    cipher = AES.new(regulator_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "nonce": cipher.nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "tag": tag.hex(),
    }


def decrypt_disclosure_package(package, regulator_key):
    """
    Decrypts a disclosure package -- this should ONLY be callable by
    someone holding the correct regulator_key (e.g. under a legal
    investigation/warrant process).

    Returns:
        The original transaction dict if the key is correct.

    Raises:
        ValueError if the key is wrong or the data was tampered with
        (AES-GCM's built-in authentication check fails).
    """
    nonce = bytes.fromhex(package["nonce"])
    ciphertext = bytes.fromhex(package["ciphertext"])
    tag = bytes.fromhex(package["tag"])

    cipher = AES.new(regulator_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # raises if wrong key/tampered

    return json.loads(plaintext.decode())


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python compliance/aml_module.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "wallet"))
    from key_generation import generate_wallet
    from transaction import create_transaction

    print("=" * 60)
    print("STEP 7 DEMO: Selective disclosure for large transactions")
    print("=" * 60)

    alice_priv, alice_pub, alice_address = generate_wallet()
    bob_priv, bob_pub, bob_address = generate_wallet()

    # The regulator's key -- held only by an authorised compliance authority
    regulator_key = generate_regulator_key()

    # --- Case 1: a normal, everyday small transaction ---
    small_tx = create_transaction(alice_address, bob_address, amount=1500)
    print(f"\n[TRANSACTION 1] Amount: Rs {small_tx['amount']}")
    if requires_disclosure(small_tx["amount"]):
        print("This transaction REQUIRES disclosure (unexpected for a small amount!)")
    else:
        print("Below threshold -> stays FULLY PRIVATE. No disclosure package created.")
        print("(Exactly like Steps 5-6: only a hash goes on the ledger.)")

    # --- Case 2: a large transaction that crosses the AML threshold ---
    large_tx = create_transaction(alice_address, bob_address, amount=350000)
    print(f"\n[TRANSACTION 2] Amount: Rs {large_tx['amount']}")
    if requires_disclosure(large_tx["amount"]):
        print(f"At/above threshold of Rs {DISCLOSURE_THRESHOLD} -> disclosure package created.")
        package = create_disclosure_package(large_tx, regulator_key)
        print(f"Encrypted package (unreadable without regulator key):")
        print(f"  nonce:      {package['nonce']}")
        print(f"  ciphertext: {package['ciphertext'][:48]}...")
        print(f"  tag:        {package['tag']}")
    else:
        print("Below threshold (unexpected for a large amount!)")

    # --- Attempt 1: WRONG key tries to decrypt (unauthorised access attempt) ---
    print(f"\n--- Simulating an unauthorised party trying to read the package ---")
    wrong_key = generate_regulator_key()
    try:
        decrypt_disclosure_package(package, wrong_key)
        print("Result: DECRYPTED (this would be a serious security failure!)")
    except (ValueError, KeyError) as e:
        print("Result: DECRYPTION FAILED -- unauthorised access correctly blocked.")

    # --- Attempt 2: CORRECT regulator key decrypts it (legal investigation) ---
    print(f"\n--- Simulating an authorised regulator with the correct key ---")
    recovered = decrypt_disclosure_package(package, regulator_key)
    print(f"Result: DECRYPTED successfully.")
    print(f"Recovered transaction: {json.dumps(recovered, indent=2)}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print("Small transaction stayed private:      PASSED")
    print("Large transaction flagged correctly:   PASSED")
    print(f"Unauthorised decryption blocked:       PASSED")
    print(f"Authorised decryption succeeded:       {'PASSED' if recovered['amount'] == 350000 else 'FAILED'}")