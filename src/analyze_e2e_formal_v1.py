from pathlib import Path
from collections import defaultdict
import csv
import statistics
import random
import math

HOME = Path.home()

RAW = (
    HOME /
    "pq_ophthalmology/results/raw/benchmark/"
    "e2e_formal_v1_e2e_timings.csv"
)

OUT = (
    HOME /
    "pq_ophthalmology/results/processed/e2e_formal_v1"
)

OUT.mkdir(parents=True, exist_ok=True)

ALGS = [
    "ECDSA_P256_SHA256",
    "ML_DSA_65",
]

BOOTSTRAP_REPS = 10000
SEED = 20260815


def percentile(values, p):
    x = sorted(values)

    if len(x) == 1:
        return x[0]

    pos = (len(x) - 1) * p
    lo = math.floor(pos)
    hi = math.ceil(pos)

    if lo == hi:
        return x[lo]

    return (
        x[lo] * (hi - pos)
        + x[hi] * (pos - lo)
    )


def iqr(values):
    return (
        percentile(values, 0.25),
        percentile(values, 0.75),
    )


def bootstrap_median_ci(values):
    rng = random.Random(SEED)

    n = len(values)
    boot = []

    for _ in range(BOOTSTRAP_REPS):

        sample = [
            values[rng.randrange(n)]
            for _ in range(n)
        ]

        boot.append(
            statistics.median(sample)
        )

    return (
        percentile(boot, 0.025),
        percentile(boot, 0.975),
    )


def summarize(values):

    q1, q3 = iqr(values)

    lo, hi = bootstrap_median_ci(
        values
    )

    return {
        "median": statistics.median(values),
        "q1": q1,
        "q3": q3,
        "mean": statistics.mean(values),
        "ci_low": lo,
        "ci_high": hi,
    }


with RAW.open(
    newline="",
    encoding="utf-8"
) as f:

    rows = list(csv.DictReader(f))


groups = defaultdict(list)

for row in rows:

    groups[
        (
            int(row["block"]),
            row["algorithm"],
        )
    ].append(row)


block_results = []


for block in range(1, 31):

    for alg in ALGS:

        rs = groups[
            (block, alg)
        ]

        hash_ns = [
            int(r["hash_ns"])
            for r in rs
        ]

        construct_ns = [
            int(r["construct_ns"])
            for r in rs
        ]

        sign_ns = [
            int(r["sign_ns"])
            for r in rs
        ]

        e2e_ns = [
            int(r["e2e_ns"])
            for r in rs
        ]

        block_results.append({

            "block": block,
            "algorithm": alg,

            "order_position":
                int(rs[0]["order_position"]),

            "hash_median_ns":
                statistics.median(hash_ns),

            "construct_median_ns":
                statistics.median(construct_ns),

            "sign_median_ns":
                statistics.median(sign_ns),

            "e2e_median_ns":
                statistics.median(e2e_ns),

            "e2e_mean_ns":
                statistics.mean(e2e_ns),
        })


BLOCK_OUT = (
    OUT /
    "e2e_formal_v1_block_summary.csv"
)

with BLOCK_OUT.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=list(
            block_results[0].keys()
        )
    )

    writer.writeheader()
    writer.writerows(block_results)


by_alg = defaultdict(list)

for r in block_results:
    by_alg[r["algorithm"]].append(r)


lines = []

lines.append(
    "========== FORMAL END-TO-END RESULTS =========="
)

lines.append("")


METRICS = [
    ("hash_median_ns", "Image hashing latency"),
    ("construct_median_ns", "Provenance construction latency"),
    ("sign_median_ns", "Signing latency within pipeline"),
    ("e2e_median_ns", "Total end-to-end latency"),
]


for alg in ALGS:

    lines.append(
        f"Algorithm: {alg}"
    )

    rs = by_alg[alg]

    for field, label in METRICS:

        values = [
            r[field]
            for r in rs
        ]

        s = summarize(values)

        lines.append(
            f"  {label}: "
            f"{s['median']/1000:.3f} us "
            f"[IQR {s['q1']/1000:.3f}–"
            f"{s['q3']/1000:.3f}], "
            f"95% CI "
            f"{s['ci_low']/1000:.3f}–"
            f"{s['ci_high']/1000:.3f}"
        )

    lines.append("")


lookup = {
    (r["block"], r["algorithm"]): r
    for r in block_results
}


e2e_ratios = []

for block in range(1, 31):

    e = lookup[
        (
            block,
            "ECDSA_P256_SHA256"
        )
    ]

    m = lookup[
        (
            block,
            "ML_DSA_65"
        )
    ]

    e2e_ratios.append(
        m["e2e_median_ns"]
        /
        e["e2e_median_ns"]
    )


ratio_summary = summarize(
    e2e_ratios
)


lines.append(
    "========== PAIRED E2E RATIO =========="
)

lines.append(
    "ML-DSA-65 / ECDSA total end-to-end latency ratio: "
    f"{ratio_summary['median']:.3f}x "
    f"[IQR "
    f"{ratio_summary['q1']:.3f}–"
    f"{ratio_summary['q3']:.3f}], "
    f"95% CI "
    f"{ratio_summary['ci_low']:.3f}–"
    f"{ratio_summary['ci_high']:.3f}"
)

lines.append("")


lines.append(
    "========== ORDER SENSITIVITY =========="
)


for alg in ALGS:

    for position in [1, 2]:

        vals = [
            r["e2e_median_ns"]
            for r in block_results
            if r["algorithm"] == alg
            and r["order_position"] == position
        ]

        lines.append(
            f"{alg}, position {position}: "
            f"n={len(vals)}, "
            f"E2E median="
            f"{statistics.median(vals)/1000:.3f} us"
        )


lines.append("")

lines.append(
    "NOTE: Record-level operations are not treated as independent experimental replicates."
)


text = "\n".join(lines)


SUMMARY_OUT = (
    OUT /
    "e2e_formal_v1_summary.txt"
)

SUMMARY_OUT.write_text(
    text,
    encoding="utf-8"
)


print(text)

print()
print("Saved:")
print(BLOCK_OUT)
print(SUMMARY_OUT)
