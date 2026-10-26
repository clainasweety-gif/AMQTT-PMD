"""
energy_manual.py
-----------------
For measuring energy via an external power-logging tool (Intel Power
Gadget or HWiNFO) instead of pyRAPL, since pyRAPL only works on Linux.

Each method runs in a tight loop for DURATION_SEC seconds, with a
clear "START"/"END" timestamp printed to the console so you can line
this window up against your power log's timestamps.

WORKFLOW:
1. Open Intel Power Gadget or HWiNFO and start logging to CSV.
2. Let it log a few seconds of IDLE power first (don't touch anything)
   -- this gives you a baseline to subtract later.
3. Run this script:  python energy_manual.py
4. When it finishes, stop the power log.
5. In the CSV, find the time windows this script printed for each
   method, average the "Package Power (Watts)" column over that
   window, then:
       Energy (J) = (avg_power_during_window - idle_baseline_power) * DURATION_SEC
   Do this once per method (PMD-AMQTT, MQTT-TLS, CoAP-DTLS).
"""

import os
import time

import pmd_crypto as pmd
import baselines as bl

DURATION_SEC = 20   # each method runs this long -- long enough for a
                     # ~1 Hz power logger to get several clean samples
PAYLOAD_SIZE = 64    # bytes; change to 2048 to also test that size


def run_pmd_loop(payload, duration):
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        k0c, k0s = pmd.pmd_key_agreement()
        hmac_key = os.urandom(32)
        ct = pmd.encrypt(payload, k0c, hmac_key)
        pmd.decrypt(ct, k0s, hmac_key, len(payload))
        count += 1
    return count


def run_tls_loop(payload, duration):
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        k = bl.ecdhe_handshake()
        ct = bl.mqtt_tls_encrypt(payload, k)
        bl.mqtt_tls_decrypt(ct, k)
        count += 1
    return count


def run_dtls_loop(payload, duration):
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        k = bl.ecdhe_handshake()
        ct = bl.coap_dtls_encrypt(payload, k)
        bl.coap_dtls_decrypt(ct, k)
        count += 1
    return count


def announce(label):
    now = time.strftime("%H:%M:%S")
    print(f"\n[{now}] START: {label}  <-- mark this time in your power log")


def finish(label, count, duration):
    now = time.strftime("%H:%M:%S")
    print(f"[{now}] END:   {label}  (completed {count} operations in {duration}s)")


if __name__ == "__main__":
    payload = os.urandom(PAYLOAD_SIZE)

    print(f"Payload size: {PAYLOAD_SIZE} bytes")
    print(f"Each method runs for {DURATION_SEC} seconds.")
    print("Make sure your power logger is already running and has captured")
    print("a few seconds of idle baseline BEFORE you press Enter.")
    input("Press Enter when your power log is running and ready...")

    print("\n>>> Sit still and don't touch the machine during the runs below <<<")
    time.sleep(2)

    announce("IDLE (baseline) -- do nothing for 5 seconds")
    time.sleep(5)
    finish("IDLE baseline", 0, 5)

    announce("PMD-AMQTT")
    c = run_pmd_loop(payload, DURATION_SEC)
    finish("PMD-AMQTT", c, DURATION_SEC)

    announce("MQTT-TLS proxy")
    c = run_tls_loop(payload, DURATION_SEC)
    finish("MQTT-TLS proxy", c, DURATION_SEC)

    announce("CoAP-DTLS proxy")
    c = run_dtls_loop(payload, DURATION_SEC)
    finish("CoAP-DTLS proxy", c, DURATION_SEC)

    print("\nDone. Stop your power log now.")
    print("In the CSV: average 'Package Power (Watts)' over each labeled")
    print("window above, subtract the idle baseline average, then multiply")
    print(f"by {DURATION_SEC} seconds to get Joules for that method.")