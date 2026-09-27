#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()

MANIFEST_NAME = "freeze-manifest.json"
SIDECAR_NAME = "freeze-manifest.json.sha256"

EXPECTED_PACKAGE_FILES = {
    "README.md",
    "acceptance-email.txt",
    "classification-protocol.txt",
    "freeze-manifest.json",
    "freeze-manifest.json.sha256",
    "intake-protocol.txt",
    "reviewer-procedure.txt",
    "reviewer-reply-template.txt",
    "verify-freeze-manifest.py",
}

EXPECTED_CLAIM_BOUNDARY = [
    "Agreement \u2260 Correctness",
    (
        "Byte-identical evidence-chain reproduction "
        "\u2260 cryptographic correctness"
    ),
    (
        "ER-1 external MATCH "
        "\u2260 independent cryptographic execution"
    ),
    "ER-1 \u2260 NIST validation",
    "ER-1 \u2260 FIPS 204 certification",
    "ER-1 \u2260 complete FIPS 204 conformance",
    "ER-1 \u2260 complete sigVer coverage",
    "ER-1 \u2260 universal ML-DSA correctness",
    "ER-1 \u2260 vulnerability absence",
    "ER-1 \u2260 system-wide quantum safety",
    "ER-1 \u2260 formal verifier correctness",
    "ER-1 \u2260 organizational endorsement",
    "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false",
]

EXPECTED_ARTIFACTS = [
    {
        "artifact_id": "reviewer_procedure",
        "filename": "reviewer-procedure.txt",
        "byte_length": 5336,
        "sha256":
            "9373d22c26b5a5bc9fb5d2188352de5981f2e1f22326f4c48d300dee9a9245b9",
        "encoding": "UTF-8",
        "newline_policy": "LF",
        "bom_policy": "absent",
        "trailing_newline_policy": "absent",
        "canonicalization_mode": "exact_file_bytes",
        "canonical_source_provenance_class":
            "recovered_original_hash_generation_preimage",
    },
    {
        "artifact_id": "acceptance_email",
        "filename": "acceptance-email.txt",
        "byte_length": 870,
        "sha256":
            "e50d5cd6301082f76659e5f3a8ff485a128379d5f78bdb0975b8e95bdb69cb7e",
        "encoding": "UTF-8",
        "newline_policy": "LF",
        "bom_policy": "absent",
        "trailing_newline_policy": "absent",
        "canonicalization_mode":
            "file_bytes_equal_subject_lf_lf_body",
        "canonical_source_provenance_class":
            "recovered_original_hash_generation_preimage",
        "subject":
            "QSV ER-1 evidence-chain reproduction procedure",
    },
    {
        "artifact_id": "reviewer_reply_template",
        "filename": "reviewer-reply-template.txt",
        "byte_length": 388,
        "sha256":
            "90d0b964ee78d34f62fd44152bbe0644c581cdcc34d6894eba866dc032e4eede",
        "encoding": "UTF-8",
        "newline_policy": "LF",
        "bom_policy": "absent",
        "trailing_newline_policy": "absent",
        "canonicalization_mode": "exact_file_bytes",
        "canonical_source_provenance_class":
            "recovered_original_hash_generation_preimage",
    },
    {
        "artifact_id": "classification_protocol",
        "filename": "classification-protocol.txt",
        "byte_length": 2981,
        "sha256":
            "81b025299a8bdd5407c81130dea0224b267c22077b7cd682d0c2fd5a6b1d8f9b",
        "encoding": "UTF-8",
        "newline_policy": "LF",
        "bom_policy": "absent",
        "trailing_newline_policy": "absent",
        "canonicalization_mode": "exact_file_bytes",
        "canonical_source_provenance_class":
            "recovered_original_hash_generation_preimage",
    },
    {
        "artifact_id": "intake_protocol",
        "filename": "intake-protocol.txt",
        "byte_length": 5951,
        "sha256":
            "fe3cd66b80d6474e53a1c98a255f0933c007bb759ee578d0c8e5012c1e68d1c8",
        "encoding": "UTF-8",
        "newline_policy": "LF",
        "bom_policy": "absent",
        "trailing_newline_policy": "absent",
        "canonicalization_mode": "exact_file_bytes",
        "canonical_source_provenance_class":
            "recovered_original_hash_generation_preimage",
    },
]

EXPECTED_SERIALIZATION = {
    "encoding": "UTF-8",
    "newline_policy": "LF",
    "bom_policy": "absent",
    "trailing_newline_policy": "absent",
    "json_rule":
        "sort_keys=true;ensure_ascii=false;separators=(',',':');no_trailing_newline",
}

EXPECTED_SELF_INTEGRITY = {
    "algorithm": "SHA-256",
    "filename": MANIFEST_NAME,
    "sidecar_filename": SIDECAR_NAME,
    "sidecar_format":
        "<sha256><two spaces>freeze-manifest.json<LF>",
}

EXPECTED_TRUTH_BOUNDARIES = {
    "new_crypto_execution_performed": False,
    "openssl_executed": False,
    "circl_executed": False,
    "mldsa_executed": False,
    "workflow_dispatch_performed": False,
    "workflow_rerun_performed": False,
    "independent_cryptographic_execution_reproduction": False,
    "source_bound_acceptance_gate_implemented": False,
    "consumer_lineage_schema_changed": False,
    "runner_adapter_implemented": False,
}

EXPECTED_MANIFEST = {
    "schema":
        "qsv.er1.self-contained-freeze-manifest.v0.1.1",
    "package_version": "v0.1.1",
    "package_purpose":
        "packaging_serialization_reproducibility_repair_only",
    "historical_predecessor": "v0.1-final",
    "pinned_repository":
        "https://github.com/mokkunsuzuki-code/"
        "qsv-mldsa-interoperability-corpus.git",
    "pinned_commit":
        "d49dee4bac243684666d502173c6e11dbef91298",
    "pinned_tree":
        "e480a638b655de4e9c3b1712f1895e7943994129",
    "external_er1_count": 0,
    "claim_boundary": EXPECTED_CLAIM_BOUNDARY,
    "artifacts": EXPECTED_ARTIFACTS,
    "serialization": EXPECTED_SERIALIZATION,
    "manifest_self_integrity": EXPECTED_SELF_INTEGRITY,
    "truth_boundaries": EXPECTED_TRUTH_BOUNDARIES,
}


def fail(reason):
    print(
        "QSV_ER1_V0_1_1_FREEZE_VERIFIER=FAIL"
    )
    print(
        "FAILURE_REASON="
        + reason
    )
    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )
    raise SystemExit(1)


if not ROOT.is_dir():
    fail("package_root_not_directory")

actual_entries = {
    path.name
    for path in ROOT.iterdir()
}

if actual_entries != EXPECTED_PACKAGE_FILES:
    fail("package_fileset_not_exact")

manifest_path = ROOT / MANIFEST_NAME
sidecar_path = ROOT / SIDECAR_NAME

if not manifest_path.is_file():
    fail("manifest_missing")

if not sidecar_path.is_file():
    fail("manifest_sidecar_missing")

manifest_raw = manifest_path.read_bytes()

if manifest_raw.startswith(
    b"\xef\xbb\xbf"
):
    fail("manifest_bom_present")

if b"\r" in manifest_raw:
    fail("manifest_cr_or_crlf_present")

if manifest_raw.endswith(
    b"\n"
):
    fail("manifest_trailing_newline_present")

try:
    manifest_text = manifest_raw.decode(
        "utf-8"
    )
except UnicodeDecodeError:
    fail("manifest_invalid_utf8")

try:
    manifest = json.loads(
        manifest_text
    )
except Exception:
    fail("manifest_json_parse_failure")

canonical_manifest_raw = json.dumps(
    manifest,
    sort_keys=True,
    ensure_ascii=False,
    separators=(",", ":"),
).encode("utf-8")

if canonical_manifest_raw != manifest_raw:
    fail("manifest_serialization_not_deterministic")

if manifest != EXPECTED_MANIFEST:
    fail("manifest_semantics_or_authority_mismatch")

manifest_sha = hashlib.sha256(
    manifest_raw
).hexdigest()

expected_sidecar = (
    manifest_sha
    + "  "
    + MANIFEST_NAME
    + "\n"
).encode("utf-8")

sidecar_raw = sidecar_path.read_bytes()

if sidecar_raw != expected_sidecar:
    fail("manifest_sidecar_mismatch")

artifact_names = {
    item["filename"]
    for item in manifest["artifacts"]
}

expected_artifact_names = {
    item["filename"]
    for item in EXPECTED_ARTIFACTS
}

if artifact_names != expected_artifact_names:
    fail("artifact_set_mismatch")

txt_files = {
    path.name
    for path in ROOT.glob("*.txt")
    if path.is_file()
}

if txt_files != expected_artifact_names:
    fail("unexpected_canonical_txt_artifact")

all_lengths_match = True
all_hashes_match = True
utf8_policy_pass = True
lf_policy_pass = True
bom_policy_pass = True
trailing_policy_pass = True

observed = {}

for item in EXPECTED_ARTIFACTS:
    path = ROOT / item["filename"]

    if not path.is_file():
        fail(
            "artifact_missing:"
            + item["filename"]
        )

    raw = path.read_bytes()
    digest = hashlib.sha256(
        raw
    ).hexdigest()

    try:
        raw.decode("utf-8")
        utf8_valid = True
    except UnicodeDecodeError:
        utf8_valid = False

    bom_absent = not raw.startswith(
        b"\xef\xbb\xbf"
    )

    cr_absent = b"\r" not in raw

    trailing_newline_absent = not raw.endswith(
        b"\n"
    )

    length_match = (
        len(raw)
        == item["byte_length"]
    )

    hash_match = (
        digest
        == item["sha256"]
    )

    all_lengths_match = (
        all_lengths_match
        and length_match
    )

    all_hashes_match = (
        all_hashes_match
        and hash_match
    )

    utf8_policy_pass = (
        utf8_policy_pass
        and utf8_valid
    )

    lf_policy_pass = (
        lf_policy_pass
        and cr_absent
    )

    bom_policy_pass = (
        bom_policy_pass
        and bom_absent
    )

    trailing_policy_pass = (
        trailing_policy_pass
        and trailing_newline_absent
    )

    observed[
        item["artifact_id"]
    ] = {
        "byte_length": len(raw),
        "sha256_match": hash_match,
    }

    if not (
        length_match
        and hash_match
        and utf8_valid
        and bom_absent
        and cr_absent
        and trailing_newline_absent
    ):
        fail(
            "artifact_integrity_failure:"
            + item["filename"]
        )

email_raw = (
    ROOT
    / "acceptance-email.txt"
).read_bytes()

email_subject = (
    "QSV ER-1 evidence-chain reproduction procedure"
)

if not email_raw.startswith(
    (
        email_subject
        + "\n\n"
    ).encode("utf-8")
):
    fail(
        "acceptance_email_subject_binding_failure"
    )

if manifest["external_er1_count"] != 0:
    fail("external_er1_count_not_zero")

if (
    manifest["pinned_commit"]
    != "d49dee4bac243684666d502173c6e11dbef91298"
):
    fail("pinned_commit_mismatch")

if (
    manifest["pinned_tree"]
    != "e480a638b655de4e9c3b1712f1895e7943994129"
):
    fail("pinned_tree_mismatch")

if (
    manifest["claim_boundary"]
    != EXPECTED_CLAIM_BOUNDARY
):
    fail("claim_boundary_mismatch")

print(
    "QSV_ER1_V0_1_1_FREEZE_VERIFIER=PASS"
)
print(
    "PACKAGE_VERSION=v0.1.1"
)
print(
    "PACKAGE_FILESET_EXACT=YES"
)
print(
    "MANIFEST_SELF_INTEGRITY=PASS"
)
print(
    "MANIFEST_SHA256="
    + manifest_sha
)
print(
    "PINNED_COMMIT="
    + manifest["pinned_commit"]
)
print(
    "PINNED_TREE="
    + manifest["pinned_tree"]
)
print(
    "PINNED_AUTHORITY_METADATA_PRESENT=YES"
)
print(
    "CLAIM_BOUNDARY=PASS"
)
print(
    "EXPECTED_ARTIFACT_COUNT=5"
)
print(
    "ACTUAL_ARTIFACT_COUNT="
    + str(
        len(
            manifest["artifacts"]
        )
    )
)

print(
    "REVIEWER_PROCEDURE_BYTE_LENGTH="
    + str(
        observed[
            "reviewer_procedure"
        ][
            "byte_length"
        ]
    )
)
print(
    "REVIEWER_PROCEDURE_SHA256_MATCH="
    + (
        "YES"
        if observed[
            "reviewer_procedure"
        ][
            "sha256_match"
        ]
        else "NO"
    )
)

print(
    "ACCEPTANCE_EMAIL_BYTE_LENGTH="
    + str(
        observed[
            "acceptance_email"
        ][
            "byte_length"
        ]
    )
)
print(
    "ACCEPTANCE_EMAIL_SHA256_MATCH="
    + (
        "YES"
        if observed[
            "acceptance_email"
        ][
            "sha256_match"
        ]
        else "NO"
    )
)
print(
    "ACCEPTANCE_EMAIL_SUBJECT_EMBEDDED=YES"
)

print(
    "REVIEWER_REPLY_TEMPLATE_BYTE_LENGTH="
    + str(
        observed[
            "reviewer_reply_template"
        ][
            "byte_length"
        ]
    )
)
print(
    "REVIEWER_REPLY_TEMPLATE_SHA256_MATCH="
    + (
        "YES"
        if observed[
            "reviewer_reply_template"
        ][
            "sha256_match"
        ]
        else "NO"
    )
)

print(
    "CLASSIFICATION_PROTOCOL_BYTE_LENGTH="
    + str(
        observed[
            "classification_protocol"
        ][
            "byte_length"
        ]
    )
)
print(
    "CLASSIFICATION_PROTOCOL_SHA256_MATCH="
    + (
        "YES"
        if observed[
            "classification_protocol"
        ][
            "sha256_match"
        ]
        else "NO"
    )
)

print(
    "INTAKE_PROTOCOL_BYTE_LENGTH="
    + str(
        observed[
            "intake_protocol"
        ][
            "byte_length"
        ]
    )
)
print(
    "INTAKE_PROTOCOL_SHA256_MATCH="
    + (
        "YES"
        if observed[
            "intake_protocol"
        ][
            "sha256_match"
        ]
        else "NO"
    )
)

print(
    "ALL_ARTIFACT_BYTE_LENGTHS_MATCH="
    + (
        "YES"
        if all_lengths_match
        else "NO"
    )
)
print(
    "ALL_ARTIFACT_SHA256_MATCH="
    + (
        "YES"
        if all_hashes_match
        else "NO"
    )
)
print(
    "UTF8_POLICY="
    + (
        "PASS"
        if utf8_policy_pass
        else "FAIL"
    )
)
print(
    "LF_POLICY="
    + (
        "PASS"
        if lf_policy_pass
        else "FAIL"
    )
)
print(
    "BOM_POLICY="
    + (
        "PASS"
        if bom_policy_pass
        else "FAIL"
    )
)
print(
    "TRAILING_NEWLINE_POLICY="
    + (
        "PASS"
        if trailing_policy_pass
        else "FAIL"
    )
)

print(
    "HIDDEN_AUTHOR_INPUT_REQUIRED=NO"
)
print(
    "VERIFIER_NETWORK_ACCESS=NO"
)
print(
    "VERIFIER_EXTERNAL_DEPENDENCY_REQUIRED=NO"
)
print(
    "SELF_CONTAINED_FREEZE_REPRODUCIBILITY=YES"
)
print(
    "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
)
print(
    "EXTERNAL_ER1_COUNT=0"
)
