"""
energy_benchmark.py
--------------------
Real energy measurement via Intel RAPL (Running Average Power Limit)
hardware counters, using pyRAPL.

NOT RUNNABLE in this sandboxed container -- RAPL requires reading
/sys/class/powercap/intel-rapl on real hardware with the right
permissions (typically root, or a machine where powercap is exposed
to your user). Run this on your own Linux machine with an Intel CPU.

Install:
    pip install pyRAPL cryptography

Usage:
    sudo python3 energy_benchmark.py
    (root is usually required to read RAPL counters)

This measures actual joules consumed by the PMD-AMQTT cipher and
each baseline over N_TRIALS runs at 64B and 2048B payloads -- the
real equivalent of the paper's "Energy at 64B payload (J)" claim,
which nothing in the paper or this repo has actually measured yet.
"""

import os

try:
    import pyRAPL
except ImportError:
    raise SystemExit(
        "pyRAPL not installed. Run: pip install pyRAPL\n"
        "Then re-run this script (as root, or wherever RAPL is readable) "
        "on real Intel hardware -- it cannot run in a sandboxed container."
    )

import pmd_crypto as pmd
import baselines as bl

pyRAPL.setup()

N_TRIALS = 30
PAYLOAD_SIZES = [64, 2048]


def measure_energy(fn, payload, n_trials):
    from pyRAPL import Measurement
    joules = []
    for _ in range(n_trials):
        meas = Measurement('trial')
        meas.begin()
        fn(payload)
        meas.end()
        # pyRAPL reports microjoules per socket/DRAM domain; sum package domains
        result = meas.result
        total_uj = sum(result.pkg) if result.pkg else 0
        joules.append(total_uj / 1e6)
    return joules


def pmd_op(payload):
    k0c, k0s = pmd.pmd_key_agreement()
    hmac_key = os.urandom(32)
    ct = pmd.encrypt(payload, k0c, hmac_key)
    pmd.decrypt(ct, k0s, hmac_key, len(payload))


def tls_op(payload):
    k = bl.ecdhe_handshake()
    ct = bl.mqtt_tls_encrypt(payload, k)
    bl.mqtt_tls_decrypt(ct, k)


def dtls_op(payload):
    k = bl.ecdhe_handshake()
    ct = bl.coap_dtls_encrypt(payload, k)
    bl.coap_dtls_decrypt(ct, k)


if __name__ == "__main__":
    import statistics
    for size in PAYLOAD_SIZES:
        payload = os.urandom(size)
        print(f"\n=== Energy @ {size}B payload, {N_TRIALS} trials ===")
        for name, fn in [("PMD-AMQTT", pmd_op), ("MQTT-TLS", tls_op), ("CoAP-DTLS", dtls_op)]:
            vals = measure_energy(fn, payload, N_TRIALS)
            m = statistics.mean(vals)
            sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
            print(f"{name}: mean={m:.6f} J, sd={sd:.6f} J")