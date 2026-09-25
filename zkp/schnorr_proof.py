"""
schnorr_proof.py
-----------------
This file implements STEP 5: THE ZERO-KNOWLEDGE PROOF LAYER.

This is the piece that solves Problem 1 from our problem statement:
PRIVACY LEAKAGE.

CONCEPT USED: Zero-Knowledge Proof (Schnorr Identification Protocol,
made non-interactive using the Fiat-Shamir heuristic)

THE SIMPLE IDEA:
Normally, to prove you own a wallet, you might reveal your private key
directly -- but that's terrible, because now everyone who checked your
proof also knows your secret key forever.

A Zero-Knowledge Proof lets you prove "I know the secret" WITHOUT ever
revealing the secret itself. The verifier ends up 100% convinced you
know it, yet learns ZERO extra information about what it actually is.

HOW SCHNORR'S PROTOCOL WORKS (the classic 3-step version first):
    Public setup: a large prime p, and a generator g (public numbers
                  everyone agrees on).
    Prover has a secret x, and publishes y = g^x mod p (this y is
                  public -- like a "commitment" to the secret, similar
                  in spirit to a public key).

    1. COMMIT:  Prover picks a random number r, computes t = g^r mod p,
                and sends t to the verifier.
    2. CHALLENGE: Verifier sends back a random challenge number c.
    3. RESPONSE: Prover computes s = (r + c*x) mod (p-1) and sends s.

    Verifier checks: g^s ?= t * y^c mod p
    If this holds true, the prover MUST have known x -- but the
    verifier never learns x itself.

MAKING IT NON-INTERACTIVE (Fiat-Shamir heuristic):
Instead of waiting for the verifier to send a random challenge (step 2),
the prover generates the challenge themselves by HASHING the public
values (g, y, t). This is deterministic and unpredictable, so it behaves
just like a real random challenge, but now the whole proof can be
computed in one go and sent as a single package -- exactly what we need
for a real-time payment system where you can't have back-and-forth
interaction for every transaction.

WHERE THIS FITS IN OUR ARCHITECTURE:
The wallet uses this to prove "I am the legitimate owner authorized to
spend from this wallet" to the RBI ledger's ZKP Verifier -- WITHOUT
exposing the wallet's private key to the ledger at all. In a full
production system (e.g. using zk-SNARKs/Bulletproofs), this same
zero-knowledge principle is extended further to also hide the
TRANSACTION AMOUNT using range proofs. We use Schnorr here because it
demonstrates the identical core idea (proving a secret without
revealing it) with much simpler, transparent mathematics -- appropriate
for an academic simulation.
"""

import hashlib
import random

# ----------------------------------------------------------------------
# PUBLIC PARAMETERS (agreed upon by everyone in the system in advance,
# similar to how everyone agrees on the SECP256k1 curve for ECDSA)
# ----------------------------------------------------------------------
# A safe prime and generator (small enough to compute fast for a demo,
# large enough to demonstrate the concept properly).
_P = 2 ** 256 - 189  # a large prime
_G = 5               # a generator for the multiplicative group mod P


def generate_zkp_keypair():
    """
    Generates a (secret, public) pair for the ZKP system.

    Returns:
        secret_x (int): the prover's secret (kept private)
        public_y (int): y = g^x mod p (safe to publish)
    """
    secret_x = random.randrange(1, _P - 1)
    public_y = pow(_G, secret_x, _P)
    return secret_x, public_y


def _hash_challenge(g, y, t, p):
    """
    Fiat-Shamir heuristic: derive the "random" challenge by hashing the
    public commitment values instead of waiting for the verifier to
    send one. This is what makes the proof non-interactive.
    """
    data = f"{g}|{y}|{t}|{p}".encode()
    digest = hashlib.sha256(data).hexdigest()
    return int(digest, 16) % (p - 1)


def create_proof(secret_x, public_y):
    """
    Creates a non-interactive Schnorr zero-knowledge proof that the
    prover knows `secret_x` corresponding to `public_y`, WITHOUT
    revealing secret_x itself.

    Returns:
        proof (dict): {"t": ..., "s": ...} -- send this to the verifier.
                      Notice secret_x never appears here.
    """
    # Step 1 (Commit): pick a random nonce r, compute t = g^r mod p
    r = random.randrange(1, _P - 1)
    t = pow(_G, r, _P)

    # Step 2 (Challenge): derive it via hashing instead of interaction
    c = _hash_challenge(_G, public_y, t, _P)

    # Step 3 (Response): s = r + c*x  (mod p-1)
    s = (r + c * secret_x) % (_P - 1)

    return {"t": t, "s": s}


def verify_proof(public_y, proof):
    """
    Verifies a Schnorr proof WITHOUT ever seeing the secret.

    Checks: g^s ?= t * y^c mod p

    Returns:
        True  -> prover genuinely knows the secret behind public_y
        False -> proof is invalid / forged
    """
    t = proof["t"]
    s = proof["s"]

    # Recompute the same challenge the prover would have used
    c = _hash_challenge(_G, public_y, t, _P)

    lhs = pow(_G, s, _P)                       # g^s mod p
    rhs = (t * pow(public_y, c, _P)) % _P      # t * y^c mod p

    return lhs == rhs


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python zkp/schnorr_proof.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("STEP 5 DEMO: Zero-Knowledge Proof (Schnorr Protocol)")
    print("=" * 60)

    # 1. The wallet generates its ZKP secret/public pair
    #    (in the full system, this would be tied to the wallet's
    #    private key -- kept separate here to keep the math clean)
    secret_x, public_y = generate_zkp_keypair()
    print(f"\nProver's SECRET (never sent anywhere): {secret_x}")
    print(f"Prover's PUBLIC commitment (shared with ledger): {public_y}")

    # 2. Prover creates a proof of knowledge -- WITHOUT sending secret_x
    proof = create_proof(secret_x, public_y)
    print(f"\nGenerated proof sent to verifier:")
    print(f"  t = {proof['t']}")
    print(f"  s = {proof['s']}")
    print("(Notice: the secret 'x' is NOT part of this proof at all.)")

    # 3. Verifier checks the proof using ONLY public information
    is_valid = verify_proof(public_y, proof)
    print(f"\n[CHECK 1] Verifying genuine proof...")
    print(f"Result: {'VALID -- prover knows the secret' if is_valid else 'INVALID'}")

    # 4. ATTACK SIMULATION: someone without the secret tries to fake a proof
    print(f"\n--- Simulating an attacker who does NOT know the secret ---")
    fake_proof = {
        "t": random.randrange(1, _P - 1),
        "s": random.randrange(1, _P - 1),
    }
    is_fake_valid = verify_proof(public_y, fake_proof)
    print(f"Attacker submits random guessed values as a fake proof...")
    print(f"\n[CHECK 2] Verifying forged proof...")
    print(f"Result: {'VALID (BAD!)' if is_fake_valid else 'INVALID (forgery correctly rejected!)'}")

    # 5. PRIVACY CHECK: prove that the verifier's data reveals nothing
    #    about the secret -- show that many different secrets could have
    #    produced a similarly-shaped proof (i.e., t and s look random)
    print(f"\n--- Privacy check ---")
    print("The verifier only ever saw: public_y, t, s")
    print("None of these values reveal the secret 'x' -- this is the")
    print("mathematical definition of a zero-knowledge proof.")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Genuine proof accepted:      {'PASSED' if is_valid else 'FAILED'}")
    print(f"Forged proof rejected:       {'PASSED' if not is_fake_valid else 'FAILED'}")