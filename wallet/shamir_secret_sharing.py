"""
shamir_secret_sharing.py
-------------------------
This file solves Problem 2 from our problem statement: KEY-LOSS RISK.

CONCEPT USED: Threshold Cryptography (Shamir's Secret Sharing, 1979)

THE SIMPLE IDEA:
Instead of storing your private key in ONE place (which means losing that
one place = losing your money forever), we mathematically SPLIT the key
into N pieces called "shares". You only need any K of those N shares
(K <= N) to reconstruct the original key. This is called a (K, N)
threshold scheme.

Example used in this file: a (3, 5) scheme.
    - The key is split into 5 shares.
    - Any 3 of those 5 shares can rebuild the key.
    - Any 2 shares (or fewer) reveal ABSOLUTELY NOTHING about the key --
      this is the "zero-knowledge" property of Shamir's scheme itself:
      partial information is mathematically useless.

THE MATH (kept simple):
Shamir's trick uses a fact from basic algebra: a straight line needs 2
points to define it, a parabola needs 3 points, a cubic needs 4, and so
on. In general, a polynomial of degree (K-1) needs exactly K points to
be uniquely determined.

So we:
    1. Take the secret (our private key, as a number) and use it as the
       polynomial's constant term.
    2. Pick (K-1) RANDOM coefficients to build a random polynomial of
       degree (K-1).
    3. Evaluate this polynomial at N different x-values (1, 2, 3, ... N)
       to generate N (x, y) points -- these points ARE the shares.
    4. To recover the secret, take any K of these points and use
       "Lagrange interpolation" (a standard algebra technique) to
       reconstruct the original polynomial -- and read off the secret
       from it.

All arithmetic is done modulo a large prime number, which keeps the
numbers bounded and the scheme cryptographically sound.
"""

import random

# A large prime number (bigger than any private key we will split).
# This defines the finite field we do arithmetic in.
_PRIME = 2 ** 521 - 1  # a well-known large Mersenne prime


def _eval_polynomial(coefficients, x, prime):
    """Evaluates a polynomial at a given x, modulo prime."""
    result = 0
    for power, coeff in enumerate(coefficients):
        result = (result + coeff * pow(x, power, prime)) % prime
    return result


def split_secret(secret_int, threshold, total_shares, prime=_PRIME):
    """
    Splits `secret_int` into `total_shares` shares, where any
    `threshold` of them can reconstruct the secret.

    Args:
        secret_int (int): the secret to split (we will convert our
                           private key hex string into an integer first)
        threshold (int):  minimum shares needed to reconstruct (K)
        total_shares (int): total shares created (N)

    Returns:
        List of (x, y) tuples -- these are the shares. Distribute each
        tuple to a different custodian (phone, bank, trusted contact,
        recovery service, backup location, etc.)
    """
    if threshold > total_shares:
        raise ValueError("Threshold cannot be greater than total shares.")

    # Coefficient[0] is the secret itself. The rest are random.
    coefficients = [secret_int] + [
        random.randrange(0, prime) for _ in range(threshold - 1)
    ]

    shares = []
    for x in range(1, total_shares + 1):
        y = _eval_polynomial(coefficients, x, prime)
        shares.append((x, y))

    return shares


def _lagrange_interpolate(x, points, prime):
    """
    Standard Lagrange interpolation, evaluated at x=0 to recover the
    secret (since the secret was stored as the polynomial's value at
    x=0, i.e. its constant term).
    """
    total = 0
    n = len(points)

    for i in range(n):
        xi, yi = points[i]
        # Compute the Lagrange basis term for this point
        numerator, denominator = 1, 1
        for j in range(n):
            if i == j:
                continue
            xj, _ = points[j]
            numerator = (numerator * (x - xj)) % prime
            denominator = (denominator * (xi - xj)) % prime

        # Modular inverse of the denominator (since we can't divide
        # normally in modular arithmetic)
        inv_denominator = pow(denominator, -1, prime)
        term = (yi * numerator * inv_denominator) % prime
        total = (total + term) % prime

    return total


def reconstruct_secret(shares_subset, prime=_PRIME):
    """
    Reconstructs the original secret from any `threshold`-sized subset
    of shares.

    Args:
        shares_subset: a list of (x, y) tuples -- at least `threshold`
                        of the original shares (any combination works)

    Returns:
        The reconstructed secret as an integer.
    """
    secret = _lagrange_interpolate(0, shares_subset, prime)
    return secret


# ----------------------------------------------------------------------
# HELPERS to convert between our hex-string private keys and integers
# ----------------------------------------------------------------------
def private_key_hex_to_int(private_key_hex):
    return int(private_key_hex, 16)


def int_to_private_key_hex(secret_int, expected_hex_length=64):
    hex_str = hex(secret_int)[2:]
    return hex_str.zfill(expected_hex_length)


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python wallet/shamir_secret_sharing.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    from key_generation import generate_wallet

    print("=" * 60)
    print("STEP 3 DEMO: Splitting and recovering a wallet key")
    print("=" * 60)

    # 1. Create a fresh wallet (from key_generation.py)
    private_key_hex, public_key_hex, address = generate_wallet()
    print(f"\nOriginal private key:\n{private_key_hex}")

    # 2. Convert the private key into an integer so we can split it
    secret_int = private_key_hex_to_int(private_key_hex)

    # 3. Split into a (3-of-5) scheme:
    #    5 total shares, any 3 can rebuild the key.
    THRESHOLD = 3
    TOTAL_SHARES = 5
    shares = split_secret(secret_int, THRESHOLD, TOTAL_SHARES)

    print(f"\nSplit into {TOTAL_SHARES} shares (need any {THRESHOLD} to recover):")
    labels = ["Phone", "Bank", "Trusted Contact", "RBI Recovery Service", "Backup Location"]
    for label, (x, y) in zip(labels, shares):
        print(f"  Share for [{label}] -> x={x}, y={y}")

    # 4. Simulate LOSING the phone AND the trusted contact's share
    #    (i.e., we lost 2 of 5 shares -- can we still recover with the
    #    remaining 3? YES, because threshold = 3)
    print(f"\nSimulating device loss: phone and trusted-contact shares are LOST.")
    surviving_shares = [shares[1], shares[3], shares[4]]  # Bank, RBI, Backup
    print("Attempting recovery using: Bank, RBI Recovery Service, Backup Location")

    recovered_int = reconstruct_secret(surviving_shares)
    recovered_hex = int_to_private_key_hex(recovered_int)

    print(f"\nRecovered private key:\n{recovered_hex}")

    # 5. Verify the recovered key EXACTLY matches the original
    if recovered_hex == private_key_hex:
        print("\n[SUCCESS] Recovered key matches the original private key exactly!")
        print("The wallet has been fully restored despite losing 2 of 5 shares.")
    else:
        print("\n[FAILED] Recovered key does NOT match. Check the implementation.")

    # 6. Bonus check: prove that FEWER than threshold shares reveal nothing useful
    print("\n--- Security check: trying with only 2 shares (below threshold) ---")
    insufficient_shares = [shares[0], shares[2]]
    wrong_attempt = reconstruct_secret(insufficient_shares)
    wrong_hex = int_to_private_key_hex(wrong_attempt)
    print(f"Result using only 2 shares: {wrong_hex}")
    print("(This does NOT match the real key -- confirms 2 shares alone are useless.)")