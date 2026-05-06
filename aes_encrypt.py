"""
=============================================================
  Author : Esther
  Course : Cryptology and Coding Theory
=============================================================

Library Used : PyCryptodome

"""

import os
import base64

# ── PyCryptodome imports 
from Crypto.Cipher import AES          # The AES cipher class
from Crypto.Util.Padding import pad, unpad  # PKCS7 padding utilities
from Crypto.Random import get_random_bytes  # Cryptographically secure random bytes


#  FUNCTION 1 — generate_key

def generate_key(key_size_bits: int = 128) -> bytes:
    """
    Generates a cryptographically secure random AES key.

    EXPLANATION:
      get_random_bytes(n) uses the operating system's secure random
      number generator (os.urandom internally) to produce 'n' bytes
      of truly random data. This is NOT the same as Python's
      random module, it is cryptographically secure.

      AES supports three key lengths:
        128-bit  →  16 bytes   (minimum required by this assignment)
        192-bit  →  24 bytes
        256-bit  →  32 bytes

    Args:
        key_size_bits: Desired key size in bits. Default is 128.

    Returns:
        bytes: A random key of the specified length.
    """
    key_size_bytes = key_size_bits // 8
    if key_size_bytes not in (16, 24, 32):
        raise ValueError("Key size must be 128, 192, or 256 bits.")
    return get_random_bytes(key_size_bytes)


#  FUNCTION 2 — encrypt

def encrypt(plaintext: str, key: bytes) -> dict:
    """
    Encrypts a plaintext string using AES-CBC.

    EXPLANATION OF EACH STEP:

      Step 1 — Encode plaintext to bytes
        AES works on raw bytes, not strings. We encode the input
        string to bytes using UTF-8 encoding.

      Step 2 — Pad the plaintext (PKCS7)
        AES is a block cipher: it can only encrypt data that is
        exactly a multiple of 16 bytes. If the plaintext is 20 bytes,
        we pad it to 32 bytes. PKCS7 padding adds 'n' bytes each
        with value 'n' to reach the next block boundary.
        Example: "HELLO" (5 bytes) → padded to 16 bytes.

      Step 3 — Generate Initialisation Vector (IV)
        The IV is a random 16-byte value used in CBC mode to ensure
        that encrypting the same plaintext twice gives different
        ciphertexts. It does NOT need to be secret — it is sent
        alongside the ciphertext.

      Step 4 — Create AES cipher in CBC mode
        AES.new(key, AES.MODE_CBC, iv) creates a cipher object
        configured for CBC mode. In CBC mode, each plaintext block
        is XORed with the previous ciphertext block before being
        encrypted, making each block dependent on all previous ones.

      Step 5 — Encrypt
        cipher.encrypt(padded) performs the actual AES encryption,
        returning the ciphertext as raw bytes.

      Step 6 — Base64 encode for display
        The ciphertext is binary data. We encode it in Base64
        so it can be safely printed and stored as text.

    Args:
        plaintext: The message to encrypt (string).
        key: The AES secret key (bytes, 16/24/32 bytes).

    Returns:
        dict with keys: 'ciphertext_b64', 'iv_b64', 'key_b64'
    """
    # Step 1: Encode string to bytes
    plaintext_bytes = plaintext.encode("utf-8")

    # Step 2: Pad plaintext to 16-byte block boundary (PKCS7)
    padded_plaintext = pad(plaintext_bytes, AES.block_size)

    # Step 3: Generate a random 16-byte Initialisation Vector
    iv = get_random_bytes(AES.block_size)  # AES.block_size = 16

    # Step 4: Create AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Step 5: Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)

    # Step 6: Return all components encoded in Base64 for readability
    return {
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "iv_b64":         base64.b64encode(iv).decode("utf-8"),
        "key_b64":        base64.b64encode(key).decode("utf-8"),
    }


#  FUNCTION 3 — decrypt

def decrypt(ciphertext_b64: str, iv_b64: str, key: bytes) -> str:
    """
    Decrypts AES-CBC ciphertext back to the original plaintext.

    EXPLANATION OF EACH STEP:

      Step 1 — Decode from Base64
        We reverse the Base64 encoding from encryption to recover
        the raw bytes of the ciphertext and IV.

      Step 2 — Recreate the AES cipher object
        We create a NEW AES.new() object using the SAME key and SAME iv
        that were used during encryption. The iv is essential — without
        it, decryption of the first block will produce garbage.

      Step 3 — Decrypt
        cipher.decrypt(ciphertext) reverses the AES-CBC process:
        each block is decrypted then XORed with the previous
        ciphertext block to recover the padded plaintext.

      Step 4 — Remove padding (unpad)
        unpad() removes the PKCS7 padding bytes that were added
        during encryption, recovering the exact original byte sequence.

      Step 5 — Decode bytes to string
        We decode the bytes back to a UTF-8 string.

    Args:
        ciphertext_b64: Base64-encoded ciphertext string.
        iv_b64: Base64-encoded IV string.
        key: The same AES secret key used for encryption (bytes).

    Returns:
        str: The original decrypted plaintext message.
    """
    # Step 1: Decode Base64 back to raw bytes
    ciphertext = base64.b64decode(ciphertext_b64)
    iv         = base64.b64decode(iv_b64)

    # Step 2: Recreate the AES cipher with the same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Step 3: Decrypt the ciphertext
    padded_plaintext = cipher.decrypt(ciphertext)

    # Step 4: Remove PKCS7 padding
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)

    # Step 5: Decode bytes back to UTF-8 string
    return plaintext_bytes.decode("utf-8")


#  MAIN — Interactive demonstration

def main():
    print("=" * 60)
    print("   AES Encryption & Decryption — CSC 2214 Coursework 1")
    print("   Author: Esther | Victoria University, Kampala")
    print("=" * 60)
    print()

    # ── Step 1: Accept plaintext from user 
    print("STEP 1 — Enter your plaintext message")
    print("-" * 40)
    plaintext = input("Plaintext: ").strip()
    if not plaintext:
        print("Error: Plaintext cannot be empty.")
        return

    # ── Step 2: Key selection 
    print()
    print("STEP 2 — Choose key option")
    print("-" * 40)
    print("  [1] Generate a random 128-bit key (recommended)")
    print("  [2] Generate a random 256-bit key")
    print("  [3] Enter your own key (will be hashed to 16 bytes)")
    choice = input("Choice [1/2/3]: ").strip()

    if choice == "2":
        key = generate_key(256)
        print(f"  Generated 256-bit key: {base64.b64encode(key).decode()}")
    elif choice == "3":
        from hashlib import sha256
        raw = input("  Enter your key passphrase: ").strip()
        # Hash the passphrase to produce exactly 16 bytes (128-bit key)
        # sha256 produces 32 bytes; we take the first 16
        key = sha256(raw.encode("utf-8")).digest()[:16]
        print(f"  Derived 128-bit key (sha256 of passphrase, first 16 bytes): {base64.b64encode(key).decode()}")
    else:
        key = generate_key(128)
        print(f"  Generated 128-bit key: {base64.b64encode(key).decode()}")

    # ── Step 3: Encrypt
    print()
    print("STEP 3 — Encrypting...")
    print("-" * 40)
    result = encrypt(plaintext, key)

    print(f"  Ciphertext (Base64) : {result['ciphertext_b64']}")
    print(f"  IV (Base64)         : {result['iv_b64']}")
    print(f"  Key (Base64)        : {result['key_b64']}")

    # ── Step 4: Decrypt 
    print()
    print("STEP 4 — Decrypting...")
    print("-" * 40)
    recovered = decrypt(result["ciphertext_b64"], result["iv_b64"], key)
    print(f"  Recovered plaintext : {recovered}")

    # ── Step 5: Verify 
    print()
    print("STEP 5 — Verification")
    print("-" * 40)
    if recovered == plaintext:
        print("  SUCCESS: Decrypted message matches original plaintext.")
    else:
        print("  FAILURE: Mismatch detected.")

    print()
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Mode             : AES-CBC")
    print(f"  Key size         : {len(key) * 8} bits")
    print(f"  Block size       : {AES.block_size * 8} bits (128 bits always)")
    print(f"  Padding scheme   : PKCS7")
    print(f"  Original message : {plaintext}")
    print(f"  Ciphertext       : {result['ciphertext_b64']}")
    print(f"  Decrypted        : {recovered}")
    print("=" * 60)


if __name__ == "__main__":
    main()
