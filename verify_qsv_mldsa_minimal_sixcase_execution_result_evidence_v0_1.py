#!/usr/bin/env python3

import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()


EVIDENCE_REL = (
    "results/"
    "qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.json"
)

SIDECAR_REL = (
    EVIDENCE_REL
    + ".sha256"
)

EXPECTED_EVIDENCE_SHA256 = (
    "1f73e8d2570063811bb065ae6fbabb34deae12d10d1778dcdee67a8245d1058c"
)


evidence_path = ROOT / EVIDENCE_REL
sidecar_path = ROOT / SIDECAR_REL


assert evidence_path.is_file()
assert sidecar_path.is_file()


raw = evidence_path.read_bytes()

actual_sha = hashlib.sha256(
    raw
).hexdigest()


assert (
    actual_sha
    == EXPECTED_EVIDENCE_SHA256
)


assert sidecar_path.read_text(
    encoding="utf-8"
) == (
    EXPECTED_EVIDENCE_SHA256
    + "  "
    + EVIDENCE_REL
    + "\n"
)


data = json.loads(
    raw.decode("utf-8")
)


assert set(
    data.keys()
) == {
    "schema",
    "source_execution_candidate_provenance",
    "runtime_authority",
    "nist_vector_authority",
    "implementation_provenance",
    "execution_scope",
    "results",
    "summary",
    "material_boundary",
    "truth_boundaries",
}


assert data[
    "schema"
] == (
    "qsv.mldsa.minimal-sixcase-execution-result-evidence.v0.1"
)


source = data[
    "source_execution_candidate_provenance"
]


assert source == {
    "schema":
        "qsv.mldsa.minimal-sixcase-execution-result-candidate.v0.1",

    "sha256":
        "06696a961958601f8310bd84e247997c00460726bac6b7a1baa812d5c991e756",

    "sidecar_file_sha256":
        "3cb98dff6c136498d99d1e4e6573ca4875b33a66454d1b1921347a7c26f8c838",

    "fail_closed_audit": {
        "semantic_mutation_count":
            28,

        "sidecar_mutation_count":
            4,

        "unexpected_file_mutation_count":
            1,

        "total_mutation_count":
            33,

        "total_rejected_count":
            33,

        "unexpected_accept_count":
            0,
    },
}


assert data[
    "runtime_authority"
] == {
    "commit":
        "fd892bd79478fb5250a4e4dfa53705dd58d8b173",

    "tree":
        "37e27a32534381fc43affdeae7bcf9050ee990a2",
}


assert data[
    "nist_vector_authority"
] == {
    "commit":
        "975de31eb83d87039ec88934fdc47d8c312b892d",

    "tree":
        "a6b81add7faf8a8b647afcdc54268615decde9b5",

    "prompt_sha256":
        "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",

    "expected_results_sha256":
        "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
}


openssl = data[
    "implementation_provenance"
][
    "openssl"
]


assert openssl[
    "runtime_version"
] == (
    "OpenSSL 3.6.3 9 Jun 2026 "
    "(Library: OpenSSL 3.6.3 9 Jun 2026)"
)

assert openssl[
    "ephemeral_harness_binary_sha256"
] == (
    "477abe732f3f843b1b44d8b489345c91"
    "ab8130cb937609b0f157e2bad2248883"
)

assert openssl[
    "local_binary_source_commit_proven"
] is False

assert openssl[
    "local_binary_build_provenance_complete"
] is False


circl = data[
    "implementation_provenance"
][
    "circl"
]


assert circl[
    "source_commit"
] == (
    "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
)

assert circl[
    "source_tree"
] == (
    "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139"
)

assert circl[
    "ephemeral_harness_binary_sha256"
] == (
    "46aee7c438f8dc4bc9835b2b994ef8d69e259142"
    "88449a474e069d92cf5dea91"
)

assert circl[
    "go_version"
] == "go version go1.26.5 darwin/arm64"


assert data[
    "execution_scope"
] == {
    "operation":
        "sigVer",

    "revision":
        "FIPS204",

    "selected_case_count":
        6,

    "positive_case_count":
        3,

    "negative_case_count":
        3,

    "implementation_count":
        2,

    "implementation_execution_count":
        12,
}


expected_cases = [
    ("ML-DSA-44", 1, 1, False),
    ("ML-DSA-44", 1, 3, True),
    ("ML-DSA-65", 3, 31, False),
    ("ML-DSA-65", 3, 33, True),
    ("ML-DSA-87", 5, 61, False),
    ("ML-DSA-87", 5, 63, True),
]


assert len(
    data["results"]
) == 6


hex64 = re.compile(
    r"^[0-9a-f]{64}$"
)


for item, expected in zip(
    data["results"],
    expected_cases,
):

    (
        parameter_set,
        tg_id,
        tc_id,
        expected_valid,
    ) = expected

    assert item[
        "parameter_set"
    ] == parameter_set

    assert item[
        "tg_id"
    ] == tg_id

    assert item[
        "tc_id"
    ] == tc_id

    assert item[
        "expected_valid"
    ] is expected_valid

    for implementation in (
        "openssl",
        "circl",
    ):

        result = item[
            implementation
        ]

        assert result[
            "return_code"
        ] == 0

        assert result[
            "actual_valid"
        ] is expected_valid

        assert result[
            "expectation_match"
        ] is True

        assert result[
            "status"
        ] == "pass"

        assert hex64.fullmatch(
            result[
                "output_sha256"
            ]
        )

    assert item[
        "cross_implementation_agreement"
    ] is True


assert data[
    "summary"
] == {
    "openssl_result_count":
        6,

    "circl_result_count":
        6,

    "openssl_expectation_match_count":
        6,

    "circl_expectation_match_count":
        6,

    "cross_implementation_agreement_count":
        6,

    "operational_error_count":
        0,

    "expectation_mismatch_count":
        0,

    "execution_error_count":
        0,

    "decision":
        "minimal_six_case_sigver_execution_pass",
}


assert data[
    "material_boundary"
] == {
    "raw_runtime_payload_persisted":
        False,

    "raw_runtime_payload_deleted_before_candidate_creation":
        True,

    "nist_source_worktree_persisted":
        False,

    "private_key_material_required":
        False,

    "secret_key_material_required":
        False,
}


assert data[
    "truth_boundaries"
] == {
    "result_implies_nist_validation":
        False,

    "result_implies_fips_204_certification":
        False,

    "result_implies_complete_fips_204_conformance":
        False,

    "result_implies_complete_sigver_coverage":
        False,

    "cross_implementation_agreement_implies_correctness":
        False,

    "six_case_result_is_only_a_minimal_known_answer_gate":
        True,
}


for forbidden in (
    "role",
    "candidate_is_authority",
    "candidate_published",
    "publication_state",
    "execution_state",
    "results_state",
):
    assert forbidden not in data


forbidden_raw_keys = {
    "pk",
    "message",
    "context",
    "signature",
    "private_key",
    "secret_key",
    "seed",
    "raw_payload",
}


def walk(value):

    if isinstance(value, dict):

        assert not (
            forbidden_raw_keys
            & set(value.keys())
        )

        for child in value.values():
            walk(child)

    elif isinstance(value, list):

        for child in value:
            walk(child)


walk(data)


print(
    "QSV_MLDSA_STATIC_RESULT_EVIDENCE_VERIFICATION=PASS"
)

print(
    "EXECUTION_CASE_COUNT=6"
)

print(
    "IMPLEMENTATION_EXECUTION_COUNT=12"
)

print(
    "OPENSSL_EXPECTATION_MATCH_COUNT=6"
)

print(
    "CIRCL_EXPECTATION_MATCH_COUNT=6"
)

print(
    "CROSS_IMPLEMENTATION_AGREEMENT_COUNT=6"
)

print(
    "OPERATIONAL_ERROR_COUNT=0"
)

print(
    "EXPECTATION_MISMATCH_COUNT=0"
)

print(
    "EXECUTION_ERROR_COUNT=0"
)

print(
    "MUTABLE_PUBLICATION_STATE_PRESENT=NO"
)

print(
    "RAW_VECTOR_FIELDS_PRESENT=NO"
)
