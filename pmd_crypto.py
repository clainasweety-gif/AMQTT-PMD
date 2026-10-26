"""
pmd_crypto.py
-------------
Real (non-simulated) implementation of the AMQTT-PMD framework's two
cryptographic components, matching the paper's Section 3:

  1. PMD key agreement  (Sec. 3.1.1 / 3.1.5)
     Real Elliptic-Curve Diffie-Hellman (ECDH) on SECP256R1, replacing
     the toy q=97 walkthrough with an actual hard instance (q > 2^256,
     as the paper's Security Mechanism Analysis claims).

  2. Advanced Smart Encryption / Decryption  (Algorithm 1 / Algorithm 2)
     A real 40-round substitution-permutation network:
       - Initial Vernam (XOR) mixing of plaintext||HMAC-SHA3 with K0
       - 40 rounds of: AES S-box substitution -> byte permutation ->
         XOR with a round key
       - Hash-based (SHA3-256) round-key evolution each round
         ("PQC-inspired" key schedule, as described in the paper)

No step here is simulated or hand-typed; every number this module
produces (ciphertext bytes, timings) comes from actually running the
algorithm.
"""

import hashlib
import hmac
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------
# AES S-box, reused as the paper's Sec. 3.2.1.1 explicitly says the
# design borrows AES's S-box ("S-boxes used in AES, but more
# lightweight or customized for embedded systems"). Using the real
# AES S-box gives genuine, well-studied non-linearity rather than an
# ad-hoc substitution table.
# ---------------------------------------------------------------------
AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])
INV_SBOX = bytes(AES_SBOX.index(i) for i in range(256))

ROUNDS = 40


# ---------------------------------------------------------------------
# 1. PMD key agreement (real ECDH, SECP256R1 -> q > 2^256)
# ---------------------------------------------------------------------
def pmd_key_agreement():
    """
    Runs one full PMD session: client and server each generate an
    ephemeral EC keypair, exchange public values, and independently
    derive the same shared session key K0 via ECDH + HKDF-SHA3-256.
    Returns (K0_client, K0_server) -- these must be equal.
    """
    client_priv = ec.generate_private_key(ec.SECP256R1())
    server_priv = ec.generate_private_key(ec.SECP256R1())

    client_pub = client_priv.public_key()
    server_pub = server_priv.public_key()

    # Client side: shared secret from (client private, server public)
    client_shared = client_priv.exchange(ec.ECDH(), server_pub)
    # Server side: shared secret from (server private, client public)
    server_shared = server_priv.exchange(ec.ECDH(), client_pub)

    hkdf = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"PMD-session-key")
    k0_client = hkdf.derive(client_shared)

    hkdf2 = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=None, info=b"PMD-session-key")
    k0_server = hkdf2.derive(server_shared)

    return k0_client, k0_server


# ---------------------------------------------------------------------
# 2. Advanced Smart Encryption / Decryption (real 40-round SPN)
# ---------------------------------------------------------------------
def _sbox_bytes(data: bytes) -> bytes:
    return bytes(AES_SBOX[b] for b in data)


def _inv_sbox_bytes(data: bytes) -> bytes:
    return bytes(INV_SBOX[b] for b in data)


def _permute(data: bytes) -> bytes:
    """Byte-wise permutation for diffusion (fixed pseudo-random
    permutation seeded by the block length, reversible)."""
    n = len(data)
    perm = _permutation_indices(n)
    return bytes(data[perm[i]] for i in range(n))


def _inv_permute(data: bytes) -> bytes:
    n = len(data)
    perm = _permutation_indices(n)
    out = bytearray(n)
    for i in range(n):
        out[perm[i]] = data[i]
    return bytes(out)


def _permutation_indices(n: int):
    # Deterministic, reversible permutation derived from a fixed
    # seed so encrypt/decrypt agree without transmitting extra state.
    seed = hashlib.sha3_256(f"perm-{n}".encode()).digest()
    idx = list(range(n))
    # Fisher-Yates using the seed as a stream of pseudo-random bytes
    stream = seed
    si = 0
    for i in range(n - 1, 0, -1):
        if si >= len(stream):
            stream = hashlib.sha3_256(stream).digest()
            si = 0
        j = stream[si] % (i + 1)
        si += 1
        idx[i], idx[j] = idx[j], idx[i]
    return idx


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _keystream(key: bytes, length: int) -> bytes:
    """Expand a 32-byte key into a keystream of arbitrary length via
    SHA3-256 counter mode (used for the initial Vernam/XOR mixing)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha3_256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return bytes(out[:length])


def _update_key(round_key: bytes) -> bytes:
    """Hash-based ('PQC-inspired') round-key evolution: SHA3-256(Ki)."""
    return hashlib.sha3_256(round_key).digest()


def encrypt(plaintext: bytes, k0: bytes, hmac_key: bytes) -> bytes:
    """Algorithm 1: Advanced Smart Encryption with HMAC Integration."""
    mac = hmac.new(hmac_key, plaintext, hashlib.sha3_256).digest()
    merged = plaintext + mac                                  # M = P || MAC
    state = _xor(merged, _keystream(k0, len(merged)))          # Vernam mixing
    round_key = k0
    for _ in range(ROUNDS):
        state = _sbox_bytes(state)
        state = _permute(state)
        round_key = _update_key(round_key)
        state = _xor(state, _keystream(round_key, len(state)))
    return state


def decrypt(ciphertext: bytes, k0: bytes, hmac_key: bytes, plaintext_len: int):
    """Algorithm 2: Advanced Smart Decryption with HMAC Verification.
    Returns (plaintext, integrity_ok: bool)."""
    # Recompute the full round-key schedule (forward), then reverse it
    round_keys = [k0]
    for _ in range(ROUNDS):
        round_keys.append(_update_key(round_keys[-1]))
    round_keys = round_keys[::-1]  # last round's key first

    state = ciphertext
    for i in range(ROUNDS):
        rk = round_keys[i]
        state = _xor(state, _keystream(rk, len(state)))
        state = _inv_permute(state)
        state = _inv_sbox_bytes(state)

    merged = _xor(state, _keystream(k0, len(state)))
    plaintext = merged[:plaintext_len]
    received_mac = merged[plaintext_len:]
    computed_mac = hmac.new(hmac_key, plaintext, hashlib.sha3_256).digest()
    ok = hmac.compare_digest(computed_mac, received_mac)
    return plaintext, ok


if __name__ == "__main__":
    # Self-test: round-trip correctness
    k0c, k0s = pmd_key_agreement()
    assert k0c == k0s, "PMD key agreement mismatch!"
    hmac_key = os.urandom(32)
    msg = b"HELLO I AM CLAINA"
    ct = encrypt(msg, k0c, hmac_key)
    pt, ok = decrypt(ct, k0s, hmac_key, len(msg))
    assert pt == msg and ok, "Encrypt/decrypt round-trip failed!"
    print("Self-test passed: PMD key agreement + 40-round cipher round-trip OK.")
    print("Session key (K0):", k0c.hex())
    print("Ciphertext (64B msg):", ct.hex())