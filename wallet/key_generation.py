"""
key_generation.py
------------------
This file represents the USER'S WALLET in our Digital Rupee (e-Rupee) simulation.

CONCEPT USED: Public-Key Cryptography (Asymmetric Cryptography)
- Every wallet has TWO mathematically linked keys:
    1. PRIVATE KEY -> secret, never shared. Proves you own the wallet.
                       Used to SIGN transactions.
    2. PUBLIC KEY  -> safe to share, like an account number.
                       Used by others to VERIFY your signature.

We use the SECP256k1 curve (the same elliptic curve used by Bitcoin) via
the 'ecdsa' library, which implements ECDSA (Elliptic Curve Digital
Signature Algorithm).

Why this matters for the project:
Owning "digital rupees" = owning the private key. If you lose this key,
you lose access to your money forever (this is exactly Problem 2 from
our problem statement -- the key-loss risk). Step 4 (Shamir's Secret
Sharing) will fix this by splitting the private key into recoverable
pieces.
"""

from ecdsa import SigningKey, SECP256k1
import hashlib


def generate_wallet():
    """
    Creates a new wallet: a fresh private/public key pair.

    Returns:
        private_key_hex (str): the SECRET key, in hex format (keep safe!)
        public_key_hex (str):  the PUBLIC key, in hex format (safe to share)
        wallet_address (str):  a short ID derived from the public key,
                                similar to how a bank account number is
                                derived from your identity (here we just
                                hash the public key with SHA-256)
    """
    # Step 1: Generate a private key using the SECP256k1 elliptic curve
    private_key = SigningKey.generate(curve=SECP256k1)

    # Step 2: Derive the matching public key (this is done automatically --
    # you can always compute the public key FROM the private key, but never
    # the reverse. That one-way relationship is what makes this secure.)
    public_key = private_key.get_verifying_key()

    # Step 3: Convert both to hex strings so they are easy to store/print
    private_key_hex = private_key.to_string().hex()
    public_key_hex = public_key.to_string().hex()

    # Step 4: Create a short "wallet address" by hashing the public key
    # (SHA-256), similar in spirit to how crypto wallets derive addresses.
    wallet_address = hashlib.sha256(public_key.to_string()).hexdigest()[:20]

    return private_key_hex, public_key_hex, wallet_address


def load_private_key(private_key_hex):
    """
    Rebuilds a usable private key object from a stored hex string.
    Used later when a user wants to sign a transaction with an
    already-existing wallet (not a brand-new one).
    """
    return SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)


def load_public_key(public_key_hex):
    """
    Rebuilds a usable public key object from a stored hex string.
    Used later by the verifier to check someone else's signature.
    """
    from ecdsa import VerifyingKey
    return VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)


# ----------------------------------------------------------------------
# DEMO / TEST -- runs only if you execute this file directly
# (python wallet/key_generation.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 60)
    print("STEP 3 DEMO: Creating a new e-Rupee wallet")
    print("=" * 60)

    priv, pub, address = generate_wallet()

    print(f"\nPrivate Key (SECRET - never share this):\n{priv}")
    print(f"\nPublic Key (safe to share):\n{pub}")
    print(f"\nWallet Address (derived from public key):\n{address}")

    # Sanity check: can we reload the keys from their hex strings?
    reloaded_priv = load_private_key(priv)
    reloaded_pub = load_public_key(pub)
    print("\n[OK] Keys successfully reloaded from storage format.")
    print("This confirms the wallet can be saved and restored correctly.")



    