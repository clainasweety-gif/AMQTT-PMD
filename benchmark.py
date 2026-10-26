"""
benchmark_raw_v4.py
-------------------
30-trial latency/throughput benchmark of the AMQTT-PMD cipher (v4, or v3 if
v4 is not present; their output is byte-identical) against the MQTT-TLS and
CoAP-DTLS baselines (baselines.py).

Unlike the earlier benchmark.py this script
  * uses the session-keyed API: round keys are derived ONCE per session
    (derive_round_keys), then encrypt()/decrypt() are timed per message;
  * SAVES EVERY RAW PER-TRIAL VALUE to raw_latencies_v4.json;
  * reports mean, SD, median, 5th-95th percentile, a t-based 95% CI and a
    bootstrap 95% CI (the t interval can fall below zero when the data are
    right-skewed, as they are for the baselines at 64 B);
  * runs Welch's t-test and the non-parametric Mann-Whitney U test.

Run (same folder as pmd_crypto.py, baselines.py, pmd_crypto_v4.py):
    python benchmark_raw_v4.py
"""
import os, sys, time, json, random, statistics
from scipy import stats

try:
    import pmd_crypto_v4 as pmd
    CIPHER = "v4"
except ImportError:
    import pmd_crypto_v3 as pmd
    CIPHER = "v3"
import pmd_crypto as pmd0            # pmd_key_agreement lives here
import baselines as bl

N_TRIALS = 30
MSGS_PER_TRIAL = 200                 # messages timed per trial for throughput
WARMUP = 50                          # untimed calls so caches/JIT-free paths are warm
SIZES = (64, 2048)
random.seed(1)


def pmd_session():
    k0c, k0s = pmd0.pmd_key_agreement()
    return pmd.derive_round_keys(k0c), pmd.derive_round_keys(k0s), os.urandom(32)


def pmd_roundtrip(payload, sess):
    rk_c, rk_s, hk = sess
    ct = pmd.encrypt(payload, rk_c, hk)
    pt, ok = pmd.decrypt(ct, rk_s, hk, len(payload))
    assert ok and pt == payload
    return len(ct) - len(payload)


def tls_session():
    return bl.ecdhe_handshake()


def tls_roundtrip(payload, k):
    ct = bl.mqtt_tls_encrypt(payload, k)
    assert bl.mqtt_tls_decrypt(ct, k) == payload
    return len(ct) - len(payload)


def dtls_roundtrip(payload, k):
    ct = bl.coap_dtls_encrypt(payload, k)
    assert bl.coap_dtls_decrypt(ct, k) == payload
    return len(ct) - len(payload)


METHODS = {
    "PMD-AMQTT": (pmd_session, pmd_roundtrip),
    "MQTT-TLS": (tls_session, tls_roundtrip),
    "CoAP-DTLS": (tls_session, dtls_roundtrip),
}


def summarise(v):
    v = sorted(v)
    n = len(v)
    m = statistics.mean(v)
    sd = statistics.stdev(v)
    tcrit = stats.t.ppf(0.975, n - 1)
    half = tcrit * sd / n ** 0.5
    boots = sorted(statistics.mean(random.choices(v, k=n)) for _ in range(10000))
    q = lambda p: v[min(n - 1, max(0, int(round(p * (n - 1)))))]
    return {
        "n": n, "mean": m, "sd": sd, "median": statistics.median(v),
        "p05": q(0.05), "p95": q(0.95), "min": v[0], "max": v[-1],
        "ci95_t": [m - half, m + half],
        "ci95_bootstrap": [boots[249], boots[9749]],
    }


def latency(size):
    payload = os.urandom(size)
    raw = {k: [] for k in METHODS}
    overhead = {}
    for _ in range(WARMUP):                      # warm-up, not recorded
        for name, (mk, rt) in METHODS.items():
            rt(payload, mk())
    for _ in range(N_TRIALS):
        for name, (mk, rt) in METHODS.items():
            sess = mk()                          # fresh session per trial, NOT timed
            t0 = time.perf_counter()
            ovh = rt(payload, sess)              # one encrypt + decrypt
            raw[name].append((time.perf_counter() - t0) * 1000.0)
            overhead[name] = ovh
    out = {"payload_bytes": size, "raw_ms": raw, "overhead_bytes": overhead, "summary": {}}
    for name, v in raw.items():
        out["summary"][name] = summarise(v)
    for base in ("MQTT-TLS", "CoAP-DTLS"):
        t, p = stats.ttest_ind(raw["PMD-AMQTT"], raw[base], equal_var=False)
        u, pu = stats.mannwhitneyu(raw["PMD-AMQTT"], raw[base], alternative="greater")
        out["summary"]["welch_vs_" + base] = {"t": t, "p": p}
        out["summary"]["mannwhitney_vs_" + base] = {"U": u, "p": pu}
    return out


def throughput(size=64, with_handshake=False):
    """with_handshake=False: session reused, only encrypt+decrypt is timed (steady state).
    with_handshake=True : a fresh key agreement/handshake is included for EVERY message
    (this is what the original benchmark.py measured, and it is why the baselines
    were near 4,000 msg/s -- an ECDHE handshake costs about 0.2 ms)."""
    payload = os.urandom(size)
    raw = {k: [] for k in METHODS}
    for name, (mk, rt) in METHODS.items():
        for _ in range(N_TRIALS):
            sess = mk()
            t0 = time.perf_counter()
            for _ in range(MSGS_PER_TRIAL):
                if with_handshake:
                    sess = mk()
                rt(payload, sess)
            raw[name].append(MSGS_PER_TRIAL / (time.perf_counter() - t0))
    return {"with_handshake_per_message": with_handshake, "raw_msgs_per_s": raw,
            "summary": {k: summarise(v) for k, v in raw.items()}}


def show(title, summ):
    print(f"\n{title}")
    print(f"{'method':<11}{'mean':>10}{'SD':>10}{'median':>10}{'p05':>10}{'p95':>10}   95% CI (t)            95% CI (bootstrap)")
    for k in METHODS:
        s = summ[k]
        print(f"{k:<11}{s['mean']:>10.4f}{s['sd']:>10.4f}{s['median']:>10.4f}{s['p05']:>10.4f}{s['p95']:>10.4f}"
              f"   [{s['ci95_t'][0]:.4f}, {s['ci95_t'][1]:.4f}]   [{s['ci95_bootstrap'][0]:.4f}, {s['ci95_bootstrap'][1]:.4f}]")
    for key, v in summ.items():
        if key.startswith(("welch", "mannwhitney")):
            print(f"  {key}: {v}")


if __name__ == "__main__":
    print(f"cipher module: {CIPHER}   python {sys.version.split()[0]}   trials={N_TRIALS}")
    res = {"cipher": CIPHER, "n_trials": N_TRIALS, "latency": {}, "throughput_64B_session_reused": None, "throughput_64B_handshake_per_message": None}
    for size in SIZES:
        res["latency"][str(size)] = r = latency(size)
        show(f"Latency @ {size} B (ms)   overhead bytes: {r['overhead_bytes']}", r["summary"])
    res["throughput_64B_session_reused"] = th = throughput(64, False)
    show("Throughput @ 64 B (msg/s), session reused (steady state)", th["summary"])
    res["throughput_64B_handshake_per_message"] = th2 = throughput(64, True)
    show("Throughput @ 64 B (msg/s), fresh handshake for every message", th2["summary"])
    with open("raw_latencies_v4.json", "w") as f:
        json.dump(res, f, indent=2)
    print("\nAll raw per-trial values saved to raw_latencies_v4.json")