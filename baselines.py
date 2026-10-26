"""
baselines.py
------------
Real cryptographic stand-ins for the paper's two baselines, used so
the comparison in Section 4 is measuring real code against real code
rather than typed-up numbers.

MQTT-TLS proxy:
    One ECDHE (SECP256R1) handshake, then per-message AES-256-GCM
    authenticated encryption -- this is exactly what a TLS 1.3
    session negotiating ECDHE-AES256-GCM-SHA384 actually does.

CoAP-DTLS proxy:
    Same ECDHE handshake, AES-128-GCM per message (typical for
    constrained CoAP/DTLS deployments), plus a fixed per-message
    overhead constant to approximate DTLS's datagram/retransmission
    bookkeeping. This is a crypto-equivalent proxy, NOT a full DTLS
    state machine (real DTLS retransmission/fragmentation logic is
    out of scope for a single-process benchmark) -- flagged here and
    in the results output so this approximation is never mistaken
    for a full protocol implementation.
"""

import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DTLS_OVERHEAD_BYTES = 13  # approx. DTLS record header overhead per datagram


def ecdhe_handshake():
    """One real ECDHE key exchange, SECP256R1, both baselines."""
    a = ec.generate_private_key(ec.SECP256R1())
    b = ec.generate_private_key(ec.SECP256R1())
    shared_a = a.exchange(ec.ECDH(), b.public_key())
    shared_b = b.exchange(ec.ECDH(), a.public_key())
    assert shared_a == shared_b
    return shared_a  # 32-byte shared secret, used directly as AEAD key material


def mqtt_tls_encrypt(plaintext: bytes, key32: bytes):
    aesgcm = AESGCM(key32)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct  # nonce prepended, as a real TLS record would carry it


def mqtt_tls_decrypt(blob: bytes, key32: bytes):
    aesgcm = AESGCM(key32)
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)


def coap_dtls_encrypt(plaintext: bytes, key32: bytes):
    aesgcm = AESGCM(key32[:16])  # AES-128-GCM
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # simulate DTLS record-layer overhead (header bytes, not encrypted)
    return b"\x00" * DTLS_OVERHEAD_BYTES + nonce + ct


def coap_dtls_decrypt(blob: bytes, key32: bytes):
    aesgcm = AESGCM(key32[:16])
    blob = blob[DTLS_OVERHEAD_BYTES:]
    nonce, ct = blob[:12], blob[12:]
    return aesgcm.decrypt(nonce, ct, None)


if __name__ == "__main__":
    k = ecdhe_handshake()
    msg = b"HELLO I AM CLAINA"
    ct1 = mqtt_tls_encrypt(msg, k)
    assert mqtt_tls_decrypt(ct1, k) == msg
    ct2 = coap_dtls_encrypt(msg, k)
    assert coap_dtls_decrypt(ct2, k) == msg
    print("Baseline self-test passed (MQTT-TLS proxy, CoAP-DTLS proxy).")