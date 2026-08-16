from pathlib import Path
from decimal import Decimal
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

IMAGE_DIR = (
    BASE /
    "data/raw/HYGD_v1.1.0/Images"
)

OUT = (
    BASE /
    "data/derived/tampering/formal_v1"
)

IMAGE_OUT = OUT / "image"
LABEL_OUT = OUT / "label"
QUALITY_OUT = OUT / "quality"
IDENTIFIER_OUT = OUT / "identifier"

for d in [
    IMAGE_OUT,
    LABEL_OUT,
    QUALITY_OUT,
    IDENTIFIER_OUT,
]:
    d.mkdir(parents=True, exist_ok=True)

MANIFEST_OUT = OUT / "tampering_manifest.csv"


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(obj):
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


with PROV_MANIFEST.open(
    newline="",
    encoding="utf-8"
) as f:
    manifest_rows = list(csv.DictReader(f))


results = []


for index, m in enumerate(manifest_rows, 1):

    prov_path = PROV_DIR / m["provenance_file"]

    original_bytes = prov_path.read_bytes()

    original_prov_hash = sha256_bytes(
        original_bytes
    )

    if original_prov_hash != m["provenance_sha256"]:
        raise RuntimeError(
            f"Original provenance hash mismatch: {prov_path}"
        )

    record = json.loads(
        original_bytes.decode("utf-8")
    )

    image_name = record["image_name"]

    # =================================================
    # Confirm original image hash binding
    # =================================================

    image_path = IMAGE_DIR / image_name

    image_bytes = image_path.read_bytes()

    actual_image_hash = sha256_bytes(
        image_bytes
    )

    if actual_image_hash != record["image_sha256"]:
        raise RuntimeError(
            f"Original image hash mismatch: {image_name}"
        )

    # =================================================
    # Scenario 1: image file tampering
    # =================================================

    tampered_image = bytearray(image_bytes)

    if len(tampered_image) == 0:
        raise RuntimeError(
            f"Empty image file: {image_name}"
        )

    byte_offset = len(tampered_image) // 2

    before_byte = tampered_image[byte_offset]

    tampered_image[byte_offset] ^= 0x01

    after_byte = tampered_image[byte_offset]

    image_tampered_path = (
        IMAGE_OUT /
        image_name
    )

    image_tampered_path.write_bytes(
        tampered_image
    )

    tampered_image_hash = sha256_bytes(
        tampered_image
    )

    if tampered_image_hash == actual_image_hash:
        raise RuntimeError(
            f"Image tampering failed: {image_name}"
        )

    # =================================================
    # Scenario 2: label tampering
    # =================================================

    label_record = dict(record)

    original_label = label_record["label"]

    if original_label == "GON+":
        tampered_label = "GON-"
    elif original_label == "GON-":
        tampered_label = "GON+"
    else:
        raise RuntimeError(
            f"Unexpected label: {original_label}"
        )

    label_record["label"] = tampered_label

    label_bytes = canonical_bytes(
        label_record
    )

    label_path = (
        LABEL_OUT /
        m["provenance_file"]
    )

    label_path.write_bytes(label_bytes)

    # =================================================
    # Scenario 3: quality-score tampering
    # =================================================

    quality_record = dict(record)

    original_quality_string = (
        quality_record["quality_score"]
    )

    original_quality = Decimal(
        original_quality_string
    )

    decimal_places = max(
        0,
        -original_quality.as_tuple().exponent
    )

    tampered_quality = (
        original_quality +
        Decimal("0.01")
    )

    tampered_quality_string = (
        f"{tampered_quality:.{decimal_places}f}"
    )

    quality_record["quality_score"] = (
        tampered_quality_string
    )

    quality_bytes = canonical_bytes(
        quality_record
    )

    quality_path = (
        QUALITY_OUT /
        m["provenance_file"]
    )

    quality_path.write_bytes(
        quality_bytes
    )

    # =================================================
    # Scenario 4: image identifier tampering
    # =================================================

    identifier_record = dict(record)

    original_identifier = (
        identifier_record["image_name"]
    )

    tampered_identifier = (
        "tampered_" +
        original_identifier
    )

    identifier_record["image_name"] = (
        tampered_identifier
    )

    identifier_bytes = canonical_bytes(
        identifier_record
    )

    identifier_path = (
        IDENTIFIER_OUT /
        m["provenance_file"]
    )

    identifier_path.write_bytes(
        identifier_bytes
    )

    # =================================================
    # Sanity checks
    # =================================================

    if label_bytes == original_bytes:
        raise RuntimeError(
            f"Label case unchanged: {image_name}"
        )

    if quality_bytes == original_bytes:
        raise RuntimeError(
            f"Quality case unchanged: {image_name}"
        )

    if identifier_bytes == original_bytes:
        raise RuntimeError(
            f"Identifier case unchanged: {image_name}"
        )

    results.append({
        "record_index": index,
        "image_name": image_name,
        "provenance_file": m["provenance_file"],

        "original_provenance_sha256":
            original_prov_hash,

        "original_image_sha256":
            actual_image_hash,

        "tampered_image_sha256":
            tampered_image_hash,

        "image_byte_offset":
            byte_offset,

        "image_byte_before":
            before_byte,

        "image_byte_after":
            after_byte,

        "original_label":
            original_label,

        "tampered_label":
            tampered_label,

        "original_quality":
            original_quality_string,

        "tampered_quality":
            tampered_quality_string,

        "original_identifier":
            original_identifier,

        "tampered_identifier":
            tampered_identifier,

        "label_tampered_provenance_sha256":
            sha256_bytes(label_bytes),

        "quality_tampered_provenance_sha256":
            sha256_bytes(quality_bytes),

        "identifier_tampered_provenance_sha256":
            sha256_bytes(identifier_bytes),
    })


with MANIFEST_OUT.open(
    "w",
    newline="",
    encoding="utf-8"
) as f:

    fieldnames = list(results[0].keys())

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames
    )

    writer.writeheader()
    writer.writerows(results)


print("========== TAMPERING CASE GENERATION ==========")
print("Records:", len(results))
print("Tampering scenarios per record: 4")
print("Total record-scenario cases:", len(results) * 4)
print()
print("Image cases:", len(results))
print("Label cases:", len(results))
print("Quality cases:", len(results))
print("Identifier cases:", len(results))
print()
print("Manifest:")
print(MANIFEST_OUT)
