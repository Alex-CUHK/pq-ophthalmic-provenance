from pathlib import Path
from collections import defaultdict, Counter
import csv
import statistics
import random
import math

HOME = Path.home()

RAW = HOME / "pq_ophthalmology/results/raw/benchmark"
OUT = HOME / "pq_ophthalmology/results/processed/formal_v1"

OUT.mkdir(parents=True, exist_ok=True)

TIMINGS = RAW / "formal_v1_timings.csv"
KEYGEN = RAW / "formal_v1_keygen.csv"

BOOTSTRAP_REPS = 10000
BOOTSTRAP_SEED = 20260815

ALGS = [
    "ECDSA_P256_SHA256",
    "ML_DSA_65",
]


def percentile(values, p):
    values = sorted(values)

    if not values:
        return float("nan")

    if len(values) == 1:
        return values[0]

    x = (len(values) - 1) * p
    lo = math.floor(x)
    hi = math.ceil(x)

    if lo == hi:
        return values[lo]

    return (
        values[lo] * (hi - x)
        + values[hi] * (x - lo)
    )


def iqr(values):
    return (
        percentile(values, 0.25),
        percentile(values, 0.75),
    )


def bootstrap_median_ci(values, seed):
    rng = random.Random(seed)

    n = len(values)
    boot = []

    for _ in range(BOOTSTRAP_REPS):
        sample = [
            values[rng.randrange(n)]
            for _ in range(n)
        ]

        boot.append(statistics.median(sample))

    return (
        percentile(boot, 0.025),
        percentile(boot, 0.975),
    )


def summarize(values, seed=BOOTSTRAP_SEED):
    q1, q3 = iqr(values)
    lo, hi = bootstrap_median_ci(values, seed)

    return {
        "n": len(values),
        "median": statistics.median(values),
        "q1": q1,
        "q3": q3,
        "mean": statistics.mean(values),
        "ci_low": lo,
        "ci_high": hi,
    }


# -------------------------------------------------
# LOAD TIMINGS
# -------------------------------------------------

with TIMINGS.open(
    newline="",
    encoding="utf-8"
) as f:
    rows = list(csv.DictReader(f))


groups = defaultdict(list)

for r in rows:
    key = (
        int(r["block"]),
        r["algorithm"],
    )

    groups[key].append(r)


block_results = []


for block in range(1, 31):

    for alg in ALGS:

        rs = groups[(block, alg)]

        sign_ns = [
            int(r["sign_ns"])
            for r in rs
        ]

        verify_ns = [
            int(r["verify_ns"])
            for r in rs
        ]

        sig_bytes = [
            int(r["signature_bytes"])
            for r in rs
        ]

        order_position = int(
            rs[0]["order_position"]
        )

        sign_q1, sign_q3 = iqr(sign_ns)
        verify_q1, verify_q3 = iqr(verify_ns)

        block_results.append({
            "block": block,
            "algorithm": alg,
            "order_position": order_position,

            "sign_median_ns":
                statistics.median(sign_ns),

            "sign_mean_ns":
                statistics.mean(sign_ns),

            "sign_q1_ns": sign_q1,
            "sign_q3_ns": sign_q3,

            "verify_median_ns":
                statistics.median(verify_ns),

            "verify_mean_ns":
                statistics.mean(verify_ns),

            "verify_q1_ns": verify_q1,
            "verify_q3_ns": verify_q3,

            "sign_throughput_ops_s":
                1e9 / statistics.mean(sign_ns),

            "verify_throughput_ops_s":
                1e9 / statistics.mean(verify_ns),

            "signature_mean_bytes":
                statistics.mean(sig_bytes),

            "signature_median_bytes":
                statistics.median(sig_bytes),
        })


block_csv = (
    OUT /
    "formal_v1_block_summary.csv"
)

with block_csv.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fieldnames = list(block_results[0].keys())

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(block_results)


# -------------------------------------------------
# BLOCK-LEVEL SUMMARIES
# -------------------------------------------------

by_alg = defaultdict(list)

for r in block_results:
    by_alg[r["algorithm"]].append(r)


summary_lines = []

summary_lines.append(
    "========== FORMAL V1 PERFORMANCE RESULTS =========="
)

summary_lines.append("")


for alg_i, alg in enumerate(ALGS):

    rs = by_alg[alg]

    sign_med = [
        r["sign_median_ns"]
        for r in rs
    ]

    verify_med = [
        r["verify_median_ns"]
        for r in rs
    ]

    sign_tp = [
        r["sign_throughput_ops_s"]
        for r in rs
    ]

    verify_tp = [
        r["verify_throughput_ops_s"]
        for r in rs
    ]

    s = summarize(
        sign_med,
        BOOTSTRAP_SEED + alg_i
    )

    v = summarize(
        verify_med,
        BOOTSTRAP_SEED + 100 + alg_i
    )

    st = summarize(
        sign_tp,
        BOOTSTRAP_SEED + 200 + alg_i
    )

    vt = summarize(
        verify_tp,
        BOOTSTRAP_SEED + 300 + alg_i
    )

    summary_lines.append(f"Algorithm: {alg}")

    summary_lines.append(
        "  Signing latency "
        f"(block medians): "
        f"{s['median']/1000:.3f} us "
        f"[IQR {s['q1']/1000:.3f}–{s['q3']/1000:.3f}], "
        f"95% CI {s['ci_low']/1000:.3f}–{s['ci_high']/1000:.3f}"
    )

    summary_lines.append(
        "  Verification latency "
        f"(block medians): "
        f"{v['median']/1000:.3f} us "
        f"[IQR {v['q1']/1000:.3f}–{v['q3']/1000:.3f}], "
        f"95% CI {v['ci_low']/1000:.3f}–{v['ci_high']/1000:.3f}"
    )

    summary_lines.append(
        "  Signing throughput: "
        f"{st['median']:.1f} ops/s "
        f"[IQR {st['q1']:.1f}–{st['q3']:.1f}], "
        f"95% CI {st['ci_low']:.1f}–{st['ci_high']:.1f}"
    )

    summary_lines.append(
        "  Verification throughput: "
        f"{vt['median']:.1f} ops/s "
        f"[IQR {vt['q1']:.1f}–{vt['q3']:.1f}], "
        f"95% CI {vt['ci_low']:.1f}–{vt['ci_high']:.1f}"
    )

    summary_lines.append("")


# -------------------------------------------------
# PAIRED BLOCK RATIOS
# -------------------------------------------------

block_lookup = {
    (r["block"], r["algorithm"]): r
    for r in block_results
}

sign_ratios = []
verify_ratios = []

for block in range(1, 31):

    e = block_lookup[
        (block, "ECDSA_P256_SHA256")
    ]

    m = block_lookup[
        (block, "ML_DSA_65")
    ]

    sign_ratios.append(
        m["sign_median_ns"]
        / e["sign_median_ns"]
    )

    verify_ratios.append(
        m["verify_median_ns"]
        / e["verify_median_ns"]
    )


sr = summarize(
    sign_ratios,
    BOOTSTRAP_SEED + 400
)

vr = summarize(
    verify_ratios,
    BOOTSTRAP_SEED + 500
)


summary_lines.append(
    "========== PAIRED BLOCK RATIOS =========="
)

summary_lines.append(
    "ML-DSA-65 / ECDSA signing latency ratio: "
    f"{sr['median']:.3f}x "
    f"[IQR {sr['q1']:.3f}–{sr['q3']:.3f}], "
    f"95% CI {sr['ci_low']:.3f}–{sr['ci_high']:.3f}"
)

summary_lines.append(
    "ML-DSA-65 / ECDSA verification latency ratio: "
    f"{vr['median']:.3f}x "
    f"[IQR {vr['q1']:.3f}–{vr['q3']:.3f}], "
    f"95% CI {vr['ci_low']:.3f}–{vr['ci_high']:.3f}"
)

summary_lines.append("")


# -------------------------------------------------
# SIGNATURE SIZE
# -------------------------------------------------

summary_lines.append(
    "========== SIGNATURE SIZE =========="
)


for alg in ALGS:

    sizes = [
        int(r["signature_bytes"])
        for r in rows
        if r["algorithm"] == alg
    ]

    q1, q3 = iqr(sizes)

    summary_lines.append(
        f"{alg}: "
        f"mean {statistics.mean(sizes):.3f} bytes; "
        f"median {statistics.median(sizes):.1f}; "
        f"IQR {q1:.1f}–{q3:.1f}; "
        f"range {min(sizes)}–{max(sizes)}"
    )


ecdsa_sizes = [
    int(r["signature_bytes"])
    for r in rows
    if r["algorithm"] == "ECDSA_P256_SHA256"
]

mldsa_sizes = [
    int(r["signature_bytes"])
    for r in rows
    if r["algorithm"] == "ML_DSA_65"
]


mean_size_ratio = (
    statistics.mean(mldsa_sizes)
    / statistics.mean(ecdsa_sizes)
)

summary_lines.append(
    "ML-DSA-65 / ECDSA mean signature-size ratio: "
    f"{mean_size_ratio:.3f}x"
)

summary_lines.append("")


# -------------------------------------------------
# STORAGE PROJECTIONS
# -------------------------------------------------

summary_lines.append(
    "========== SIGNATURE-ONLY STORAGE PROJECTIONS =========="
)

for n in [1000, 100000, 1000000]:

    e_bytes = statistics.mean(ecdsa_sizes) * n
    m_bytes = statistics.mean(mldsa_sizes) * n

    summary_lines.append(
        f"{n:,} records:"
    )

    summary_lines.append(
        f"  ECDSA: {e_bytes / (1024**2):.3f} MiB"
    )

    summary_lines.append(
        f"  ML-DSA-65: {m_bytes / (1024**2):.3f} MiB"
    )

    summary_lines.append(
        f"  Additional: {(m_bytes-e_bytes)/(1024**2):.3f} MiB"
    )

summary_lines.append("")


# -------------------------------------------------
# KEYGEN
# -------------------------------------------------

with KEYGEN.open(
    newline="",
    encoding="utf-8"
) as f:
    keyrows = list(csv.DictReader(f))


summary_lines.append(
    "========== KEY GENERATION =========="
)


for alg_i, alg in enumerate(ALGS):

    vals = [
        int(r["keygen_ns"])
        for r in keyrows
        if r["algorithm"] == alg
    ]

    s = summarize(
        vals,
        BOOTSTRAP_SEED + 600 + alg_i
    )

    summary_lines.append(
        f"{alg}: "
        f"{s['median']/1000:.3f} us "
        f"[IQR {s['q1']/1000:.3f}–{s['q3']/1000:.3f}], "
        f"95% CI {s['ci_low']/1000:.3f}–{s['ci_high']/1000:.3f}"
    )


summary_lines.append("")


# -------------------------------------------------
# ORDER SENSITIVITY
# -------------------------------------------------

summary_lines.append(
    "========== ORDER SENSITIVITY =========="
)


for alg in ALGS:

    for pos in [1, 2]:

        rs = [
            r for r in block_results
            if r["algorithm"] == alg
            and r["order_position"] == pos
        ]

        sign = [
            r["sign_median_ns"]
            for r in rs
        ]

        verify = [
            r["verify_median_ns"]
            for r in rs
        ]

        summary_lines.append(
            f"{alg}, position {pos}: "
            f"n={len(rs)}, "
            f"sign median={statistics.median(sign)/1000:.3f} us, "
            f"verify median={statistics.median(verify)/1000:.3f} us"
        )


summary_lines.append("")
summary_lines.append(
    "NOTE: Record-level operations are not treated as independent experimental replicates."
)


summary_text = "\n".join(summary_lines)

summary_path = (
    OUT /
    "formal_v1_summary.txt"
)

summary_path.write_text(
    summary_text,
    encoding="utf-8"
)

print(summary_text)

print()
print("Saved:")
print(block_csv)
print(summary_path)
