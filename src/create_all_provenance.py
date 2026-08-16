from pathlib import Path
import csv
import json
import hashlib

home = Path.home()

manifest_path = (
    home /
    "pq_ophthalmology/data/derived/HYGD_v1.1.0_manifest.csv"
)

output_dir = (
    home /
    "pq_ophthalmology/data/derived/provenance/all"
)

summary_path = (
    home /
    "pq_ophthalmology/data/derived/provenance/provenance_manifest.csv"
)

output_dir.mkdir(parents=True, exist_ok=True)

records = []

with manifest_path.open(
    newline="",
    encoding="utf-8"
) as f:

    reader = csv.DictReader(f)

    for row in reader:

        provenance = {
            "dataset": "HYGD",
            "dataset_version": "1.1.0",
            "hash_algorithm": "SHA-256",
            "image_name": row["image_name"],
            "image_sha256": row["image_sha256"],
            "label": row["label"],
            "patient_id": row["patient_id"],
            "provenance_schema": "oph-pq-provenance-v1",
            "quality_score": row["quality_score"],
        }

        canonical_json = json.dumps(
            provenance,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        canonical_bytes = canonical_json.encode("utf-8")

        filename = (
            Path(row["image_name"]).stem +
            ".provenance.json"
        )

        output_file = output_dir / filename
        output_file.write_bytes(canonical_bytes)

        provenance_sha256 = hashlib.sha256(
            canonical_bytes
        ).hexdigest()

        records.append({
            "image_name": row["image_name"],
            "provenance_file": filename,
            "provenance_sha256": provenance_sha256,
            "provenance_size_bytes": len(canonical_bytes),
        })

with summary_path.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fieldnames = [
        "image_name",
        "provenance_file",
        "provenance_sha256",
        "provenance_size_bytes",
    ]

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(records)

print("========== COMPLETE ==========")
print("Provenance records:", len(records))
print("Output directory:", output_dir)
print("Summary manifest:", summary_path)
