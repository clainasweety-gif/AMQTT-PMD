"""
energy_manual_v3.py
--------------------
Same manual power-logging workflow as energy_manual.py, but testing
the CORRECTED v3 cipher (10 rounds + real mixing, Sec. 3.2.1.2)
instead of the original flawed v1 design.

WORKFLOW (identical to before):
1. Open HWiNFO -> Sensors, start logging to CSV (1-second interval).
2. Let it log a few seconds of IDLE power first (don't touch anything).
3. Run this script:  python energy_manual_v3.py
4. When it finishes, stop the power log.
5. In the CSV, average "CPU Package Power [W]" over each labeled
   window this script prints, then:
       Energy (J) = (avg_power_during_window - idle_baseline_power) * DURATION_SEC
   Divide by the operation count printed for that window to get
   Joules per message.
"""

import os
import time

import pmd_crypto_v3 as pmd
import baselines as bl

DURATION_SEC = 20
PAYLOAD_SIZE = 64


def run_v3_loop(payload, duration):
    k0c, k0s = pmd.pmd_key_agreement()
    round_keys_client = pmd.derive_round_keys(k0c)
    round_keys_server = pmd.derive_round_keys(k0s)
    hmac_key = os.urandom(32)
    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        ct = pmd.encrypt(payload, round_keys_client, hmac_key)
        pmd.decrypt(ct, round_keys_server, hmac_key, len(payload))
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

    print(f"Payload size: {PAYLOAD_SIZE} bytes -- testing CORRECTED v3 cipher (10 rounds + mixing)")
    print(f"Each method runs for {DURATION_SEC} seconds.")
    print("Make sure your power logger is already running and has captured")
    print("a few seconds of idle baseline BEFORE you press Enter.")
    input("Press Enter when your power log is running and ready...")

    print("\n>>> Sit still and don't touch the machine during the runs below <<<")
    time.sleep(2)

    announce("IDLE (baseline) -- do nothing for 5 seconds")
    time.sleep(5)
    finish("IDLE baseline", 0, 5)

    announce("PMD-AMQTT v3 (corrected cipher)")
    c = run_v3_loop(payload, DURATION_SEC)
    finish("PMD-AMQTT v3", c, DURATION_SEC)

    announce("MQTT-TLS proxy")
    c = run_tls_loop(payload, DURATION_SEC)
    finish("MQTT-TLS proxy", c, DURATION_SEC)

    announce("CoAP-DTLS proxy")
    c = run_dtls_loop(payload, DURATION_SEC)
    finish("CoAP-DTLS proxy", c, DURATION_SEC)

    print("\nDone. Stop your power log now.")
    print("In the CSV: average 'CPU Package Power [W]' over each labeled")
    print("window above, subtract the idle baseline average, then multiply")
    print(f"by {DURATION_SEC} seconds to get Joules for that method.")