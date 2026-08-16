from pathlib import Path
import csv
import json
import hashlib

HOME = Path.home()
BASE = HOME / "pq_ophthalmology"

PROV_MANIFEST = (
    BASE /
    "data/derived/provenance/provenance_manifest.csv"
)

PROV_DIR = (
    BASE /
    "data/derived/provenance/all"
)

RAW_IMAGES = (
    BASE /
    "data/raw/HYGD_v1.1.0/Images"
)

TAMPERED_IMAGES = (
    BASE /
    "data/derived/tampering/formal_v1/image"
)

TAMPER_MANIFEST = (
    BASE /
    "data/derived/tampering/formal_v1/"
    "tampering_manifest.csv"
)

OUT = (
    BASE /
    "results/raw/tampering/formal_v1/"
    "formal_image_tampering.csv"
)


def sha256_file(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


with PROV_MANIFEST.open(
    newline="",
    encoding="utf-8"
) as f:
    prov_rows = list(csv.DictReader(f))


with TAMPER_MANIFEST.open(
    newline="",
    encoding="utf-8"
) as f:
    tamper_rows = list(csv.DictReader(f))


tamper_lookup = {
    r["image_name"]: r
    for r in tamper_rows
}


results = []

original_binding_ok_count = 0
tampering_detected_count = 0
manifest_match_count = 0
technical_errors = 0


for index, row in enumerate(prov_rows, 1):

    try:

        prov_path = (
            PROV_DIR /
            row["provenance_file"]
        )

        provenance = json.loads(
            prov_path.read_text(
                encoding="utf-8"
            )
        )

        image_name = (
            provenance["image_name"]
        )

        signed_expected_hash = (
            provenance["image_sha256"]
        )

        original_path = (
            RAW_IMAGES /
            image_name
        )

        tampered_path = (
            TAMPERED_IMAGES /
            image_name
        )

        original_hash = sha256_file(
            original_path
        )

        tampered_hash = sha256_file(
            tampered_path
        )

        original_binding_ok = (
            original_hash ==
            signed_expected_hash
        )

        tampering_detected = (
            tampered_hash !=
            signed_expected_hash
        )

        tm = tamper_lookup[
            image_name
        ]

        manifest_match = (
            tm["original_image_sha256"]
                == original_hash
            and
            tm["tampered_image_sha256"]
                == tampered_hash
        )

        if original_binding_ok:
            original_binding_ok_count += 1

        if tampering_detected:
            tampering_detected_count += 1

        if manifest_match:
            manifest_match_count += 1

        results.append({
            "record_index": index,
            "image_name": image_name,
            "signed_expected_sha256":
                signed_expected_hash,
            "original_actual_sha256":
                original_hash,
            "tampered_actual_sha256":
                tampered_hash,
            "original_binding_ok":
                int(original_binding_ok),
            "tampering_detected":
                int(tampering_detected),
            "manifest_hashes_match":
                int(manifest_match),
            "technical_error": 0,
        })

    except Exception as e:

        technical_errors += 1

        results.append({
            "record_index": index,
            "image_name":
                row.get("image_name", ""),
            "signed_expected_sha256": "",
            "original_actual_sha256": "",
            "tampered_actual_sha256": "",
            "original_binding_ok": 0,
            "tampering_detected": 0,
            "manifest_hashes_match": 0,
            "technical_error": 1,
        })

        print(
            f"ERROR record {index}: {e}"
        )


with OUT.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fieldnames = list(
        results[0].keys()
    )

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(results)


print(
    "========== IMAGE HASH-BINDING VALIDATION =========="
)

print(
    "Records:",
    len(results)
)

print(
    "Original image bound to signed hash:",
    original_binding_ok_count,
    "/ 747"
)

print(
    "Tampered image hash mismatch detected:",
    tampering_detected_count,
    "/ 747"
)

print(
    "Generation manifest hash consistency:",
    manifest_match_count,
    "/ 747"
)

print(
    "Technical errors:",
    technical_errors
)


all_ok = (
    len(results) == 747
    and original_binding_ok_count == 747
    and tampering_detected_count == 747
    and manifest_match_count == 747
    and technical_errors == 0
)


print()
print("===============================")

print(
    "FINAL IMAGE VALIDATION:",
    "PASS" if all_ok else "FAIL"
)

print("===============================")

print()
print("Raw results:")
print(OUT)
