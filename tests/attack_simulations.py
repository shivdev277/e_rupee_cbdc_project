"""
attack_simulations.py
-----------------------
This file implements STEP 8: THREAT TESTING.

This is the file you demo LIVE in your presentation -- it runs every
attack from your threat model in one go, against the actual modules
you built in Steps 3-7, and prints a clear PASS/FAIL report.

THREAT MODEL COVERAGE (matches your architecture diagram):
    1. Man-in-the-Middle (MITM) tampering       -> Step 4 (signatures)
    2. Impersonation / forged signature         -> Step 4 (signatures)
    3. Forged zero-knowledge proof               -> Step 5 (ZKP)
    4. Double-spend (replay attack)              -> Step 6 (ledger)
    5. Wallet key loss / device compromise       -> Step 3 (Shamir)
    6. Ledger privacy leak / surveillance risk   -> Step 6 (hash-only ledger)
    7. Insider / unauthorised AML access         -> Step 7 (AES compliance)

Each test below deliberately tries to BREAK the system in one specific
way. A "PASSED" result means the attack was correctly detected and
blocked -- exactly what we want.
"""

import sys
import os
import json

# Import every module built in Steps 3-7
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "wallet"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "zkp"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ledger"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "compliance"))

from key_generation import generate_wallet
from shamir_secret_sharing import (
    split_secret, reconstruct_secret,
    private_key_hex_to_int, int_to_private_key_hex,
)
from transaction import create_transaction, sign_transaction, verify_transaction
from schnorr_proof import generate_zkp_keypair, create_proof, verify_proof
from mock_ledger import init_ledger, submit_transaction, view_ledger, DB_PATH
from aml_module import (
    generate_regulator_key, requires_disclosure,
    create_disclosure_package, decrypt_disclosure_package,
)

results = {}  # test_name -> True/False


def test_mitm_tampering():
    """Attack 1: attacker intercepts and changes the transaction amount."""
    alice_priv, alice_pub, alice_addr = generate_wallet()
    bob_priv, bob_pub, bob_addr = generate_wallet()

    tx = create_transaction(alice_addr, bob_addr, amount=500)
    signature = sign_transaction(tx, alice_priv)

    tampered_tx = dict(tx)
    tampered_tx["amount"] = 99999  # attacker changes the amount

    is_valid = verify_transaction(tampered_tx, signature, alice_pub)
    passed = (is_valid is False)  # we WANT this to be rejected
    results["1. MITM tampering detection"] = passed
    return passed


def test_impersonation():
    """Attack 2: attacker signs a transaction with their OWN key, pretending to be Alice."""
    alice_priv, alice_pub, alice_addr = generate_wallet()
    bob_priv, bob_pub, bob_addr = generate_wallet()
    attacker_priv, attacker_pub, attacker_addr = generate_wallet()

    tx = create_transaction(alice_addr, bob_addr, amount=500)
    forged_signature = sign_transaction(tx, attacker_priv)  # signed with WRONG key

    is_valid = verify_transaction(tx, forged_signature, alice_pub)  # checked against Alice's key
    passed = (is_valid is False)
    results["2. Impersonation / forged signature"] = passed
    return passed


def test_forged_zkp():
    """Attack 3: attacker guesses random values instead of proving real knowledge."""
    secret_x, public_y = generate_zkp_keypair()
    import random
    fake_proof = {"t": random.randrange(1, 2**256), "s": random.randrange(1, 2**256)}

    is_valid = verify_proof(public_y, fake_proof)
    passed = (is_valid is False)
    results["3. Forged zero-knowledge proof"] = passed
    return passed


def test_double_spend():
    """Attack 4: the exact same valid transaction is replayed to the ledger twice."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_ledger()

    alice_priv, alice_pub, alice_addr = generate_wallet()
    bob_priv, bob_pub, bob_addr = generate_wallet()
    zkp_secret, zkp_public = generate_zkp_keypair()

    tx = create_transaction(alice_addr, bob_addr, amount=800)
    signature = sign_transaction(tx, alice_priv)
    proof = create_proof(zkp_secret, zkp_public)

    accepted_1, _ = submit_transaction(tx, signature, alice_pub, zkp_public, proof)
    accepted_2, _ = submit_transaction(tx, signature, alice_pub, zkp_public, proof)  # replay

    passed = (accepted_1 is True) and (accepted_2 is False)
    results["4. Double-spend / replay attack"] = passed
    return passed


def test_key_recovery():
    """Attack 5: simulate losing 2 of 5 key shares (e.g. lost phone) and still recovering."""
    private_key_hex, public_key_hex, address = generate_wallet()
    secret_int = private_key_hex_to_int(private_key_hex)

    shares = split_secret(secret_int, threshold=3, total_shares=5)
    surviving_shares = [shares[1], shares[3], shares[4]]  # lost shares[0] and shares[2]

    recovered_int = reconstruct_secret(surviving_shares)
    recovered_hex = int_to_private_key_hex(recovered_int)

    passed = (recovered_hex == private_key_hex)
    results["5. Wallet key-loss recovery (Shamir)"] = passed
    return passed


def test_ledger_privacy():
    """
    Attack 6: an 'insider' with full access to the ledger tries to learn
    the sender, receiver, or amount just from what's stored.
    """
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_ledger()

    alice_priv, alice_pub, alice_addr = generate_wallet()
    bob_priv, bob_pub, bob_addr = generate_wallet()
    zkp_secret, zkp_public = generate_zkp_keypair()

    tx = create_transaction(alice_addr, bob_addr, amount=42424)
    signature = sign_transaction(tx, alice_priv)
    proof = create_proof(zkp_secret, zkp_public)
    submit_transaction(tx, signature, alice_pub, zkp_public, proof)

    rows = view_ledger()
    tx_hash, status, recorded_at = rows[0]

    # The insider has full access to this row -- check that NONE of the
    # sensitive values appear anywhere in what's stored.
    leaked = (
        str(tx["amount"]) in tx_hash
        or alice_addr in tx_hash
        or bob_addr in tx_hash
    )
    passed = (leaked is False)
    results["6. Ledger privacy (insider/surveillance)"] = passed
    return passed


def test_unauthorised_disclosure_access():
    """Attack 7: someone without the regulator key tries to read a large transaction's details."""
    alice_priv, alice_pub, alice_addr = generate_wallet()
    bob_priv, bob_pub, bob_addr = generate_wallet()

    regulator_key = generate_regulator_key()
    attacker_key = generate_regulator_key()  # a different, wrong key

    large_tx = create_transaction(alice_addr, bob_addr, amount=500000)
    assert requires_disclosure(large_tx["amount"])

    package = create_disclosure_package(large_tx, regulator_key)

    try:
        decrypt_disclosure_package(package, attacker_key)
        passed = False  # if this succeeds, that's a serious failure
    except Exception:
        passed = True  # correctly blocked

    results["7. Unauthorised AML access blocked"] = passed
    return passed


# ----------------------------------------------------------------------
# RUN ALL TESTS AND PRINT A SUMMARY REPORT
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 65)
    print("STEP 8: FULL THREAT MODEL TEST SUITE")
    print("Running every attack scenario against Steps 3-7...")
    print("=" * 65)

    test_mitm_tampering()
    test_impersonation()
    test_forged_zkp()
    test_double_spend()
    test_key_recovery()
    test_ledger_privacy()
    test_unauthorised_disclosure_access()

    print()
    for name, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        marker = "[OK]  " if passed else "[FAIL]"
        print(f"{marker} {name:<45} {status}")

    total = len(results)
    passed_count = sum(1 for v in results.values() if v)

    print("\n" + "=" * 65)
    print(f"RESULT: {passed_count}/{total} threat tests passed")
    if passed_count == total:
        print("All attacks were correctly detected and blocked.")
    else:
        print("WARNING: one or more attacks were NOT blocked -- review the code above.")
    print("=" * 65)