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
    "pq_ophthalmology/data/derived/provenance"
)

output_dir.mkdir(parents=True, exist_ok=True)

# Read the first manifest record
with manifest_path.open(
    newline="",
    encoding="utf-8"
) as f:
    reader = csv.DictReader(f)
    row = next(reader)

# Construct a deterministic provenance object.
# Numeric-looking values are deliberately retained as strings
# to avoid floating-point serialization ambiguity.
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

# Deterministic serialization:
# - keys sorted
# - no optional whitespace
# - UTF-8 encoding
canonical_json = json.dumps(
    provenance,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
)

canonical_bytes = canonical_json.encode("utf-8")

output_file = output_dir / "0_0.provenance.json"
output_file.write_bytes(canonical_bytes)

record_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

hash_file = output_dir / "0_0.provenance.sha256"
hash_file.write_text(
    f"{record_sha256}  {output_file.name}\n",
    encoding="utf-8"
)

print("========== PROVENANCE RECORD ==========")
print(canonical_json)
print()
print("Record bytes:", len(canonical_bytes))
print("Record SHA-256:", record_sha256)
print()
print("Saved to:")
print(output_file)
