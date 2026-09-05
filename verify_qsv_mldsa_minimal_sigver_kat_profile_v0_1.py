#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent

PROFILE = (
    ROOT
    / "profiles"
    / "qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

PROFILE_SIDECAR = Path(
    str(PROFILE) + ".sha256"
)

SELF = (
    ROOT
    / "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py"
)

SELF_SIDECAR = Path(
    str(SELF) + ".sha256"
)

checks = 0
failures = []


def check(name, condition):
    global checks

    checks += 1

    if not condition:
        failures.append(name)


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


data = json.loads(
    PROFILE.read_text(
        encoding="utf-8"
    )
)

expected_top_keys = {
    "schema",
    "version",
    "status",
    "role",
    "qsv_source_authority",
    "nist_source_authority",
    "source_inputs",
    "execution_surface",
    "selected_cases",
    "selected_prompt_field_names",
    "material_boundary",
    "execution_policy",
    "excluded_from_v0_1",
    "truth_boundaries",
    "execution_state",
}

check(
    "top-level key set exact",
    set(data.keys()) == expected_top_keys,
)

check(
    "profile identity exact",
    (
        data["schema"]
        == "qsv.mldsa.nist-acvp-known-answer-execution-profile.v0.1"
        and data["version"] == "0.1"
        and data["status"]
        == "profile_candidate_defined_execution_not_performed"
        and data["role"]
        == "minimal_public_sigver_known_answer_execution_precondition"
    ),
)

check(
    "QSV source authority exact",
    data["qsv_source_authority"]
    == {
        "repository":
            "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
        "commit":
            "b29e9dd057a892084a1f2c88eec92cc81de560d5",
        "tree":
            "eff50217e3eaa437ae530af6e5ae4fa28b67f257",
    },
)

check(
    "NIST source authority exact",
    data["nist_source_authority"]
    == {
        "repository":
            "https://github.com/usnistgov/ACVP-Server.git",
        "tag_label":
            "v1.1.0.43",
        "tag_label_is_authority":
            False,
        "exact_commit":
            "975de31eb83d87039ec88934fdc47d8c312b892d",
        "exact_tree":
            "a6b81add7faf8a8b647afcdc54268615decde9b5",
    },
)

check(
    "source inputs exact",
    data["source_inputs"]
    == [
        {
            "path":
                "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json",
            "sha256":
                "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
        },
        {
            "path":
                "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json",
            "sha256":
                "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
        },
    ],
)

check(
    "execution surface exact",
    data["execution_surface"]
    == {
        "algorithm":
            "ML-DSA",
        "mode":
            "sigVer",
        "revision":
            "FIPS204",
        "test_type":
            "AFT",
        "signature_interface":
            "external",
        "pre_hash":
            "pure",
        "parameter_sets": [
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
        ],
        "selected_case_count":
            6,
        "positive_case_count":
            3,
        "negative_case_count":
            3,
    },
)

expected_cases = [
    {
        "parameter_set":
            "ML-DSA-44",
        "tg_id":
            1,
        "tc_id":
            1,
        "expected_valid":
            False,
        "case_role":
            "negative",
    },
    {
        "parameter_set":
            "ML-DSA-44",
        "tg_id":
            1,
        "tc_id":
            3,
        "expected_valid":
            True,
        "case_role":
            "positive",
    },
    {
        "parameter_set":
            "ML-DSA-65",
        "tg_id":
            3,
        "tc_id":
            31,
        "expected_valid":
            False,
        "case_role":
            "negative",
    },
    {
        "parameter_set":
            "ML-DSA-65",
        "tg_id":
            3,
        "tc_id":
            33,
        "expected_valid":
            True,
        "case_role":
            "positive",
    },
    {
        "parameter_set":
            "ML-DSA-87",
        "tg_id":
            5,
        "tc_id":
            61,
        "expected_valid":
            False,
        "case_role":
            "negative",
    },
    {
        "parameter_set":
            "ML-DSA-87",
        "tg_id":
            5,
        "tc_id":
            63,
        "expected_valid":
            True,
        "case_role":
            "positive",
    },
]

check(
    "selected six cases exact",
    data["selected_cases"]
    == expected_cases,
)

expected_fields = {
    "tg1-tc1": [
        "context",
        "message",
        "pk",
        "signature",
    ],
    "tg1-tc3": [
        "context",
        "message",
        "pk",
        "signature",
    ],
    "tg3-tc31": [
        "context",
        "message",
        "pk",
        "signature",
    ],
    "tg3-tc33": [
        "context",
        "message",
        "pk",
        "signature",
    ],
    "tg5-tc61": [
        "context",
        "message",
        "pk",
        "signature",
    ],
    "tg5-tc63": [
        "context",
        "message",
        "pk",
        "signature",
    ],
}

check(
    "selected prompt field names exact",
    data["selected_prompt_field_names"]
    == expected_fields,
)

check(
    "material boundary exact",
    data["material_boundary"]
    == {
        "private_key_required":
            False,
        "seed_required":
            False,
        "secret_key_required":
            False,
        "siggen_private_material_required":
            False,
        "vector_payload_persisted_in_corpus":
            False,
        "selected_runtime_data_ephemeral_only":
            True,
    },
)

check(
    "execution policy exact",
    data["execution_policy"]
    == {
        "fetch_exact_nist_commit_at_runtime":
            True,
        "verify_source_sha256_before_case_extraction":
            True,
        "extract_only_selected_six_cases":
            True,
        "run_each_case_against_openssl":
            True,
        "run_each_case_against_circl":
            True,
        "require_each_implementation_to_match_expected_validity":
            True,
        "require_cross_implementation_agreement":
            True,
        "unexpected_accept_is_failure":
            True,
        "unexpected_reject_is_failure":
            True,
        "unsupported_selected_case_is_failure":
            True,
        "partial_execution_is_failure":
            True,
        "fail_closed":
            True,
    },
)

check(
    "excluded surface exact",
    data["excluded_from_v0_1"]
    == {
        "key_gen":
            True,
        "sig_gen":
            True,
        "pre_hash_sigver":
            True,
        "internal_interface_sigver":
            True,
        "external_mu_sigver":
            True,
        "full_acvp_vector_execution":
            True,
    },
)

check(
    "truth boundaries exact",
    data["truth_boundaries"]
    == {
        "profile_pass_implies_nist_validation":
            False,
        "profile_pass_implies_fips_204_certification":
            False,
        "profile_pass_implies_complete_fips_204_conformance":
            False,
        "profile_pass_implies_complete_sigver_coverage":
            False,
        "cross_implementation_agreement_implies_correctness":
            False,
        "six_case_execution_is_only_a_minimal_known_answer_gate":
            True,
        "known_external_vector_coverage_limitations_may_exist":
            True,
    },
)

check(
    "execution state exact",
    data["execution_state"]
    == {
        "cryptographic_fixture_generation_performed":
            False,
        "cryptographic_fixture_execution_performed":
            False,
        "fixture_results_published":
            False,
    },
)

canonical = json.dumps(
    data,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")

check(
    "canonical profile digest exact",
    hashlib.sha256(
        canonical
    ).hexdigest()
    == "acb84ee1b8dafd1ed84273f4820349ab2e40f3f5c1bd2e0cd0f5e482b78a2646",
)

forbidden_payload_keys = {
    "pk",
    "signature",
    "message",
    "context",
    "sk",
    "seed",
    "secretKey",
    "privateKey",
}


def collect_dictionary_keys(value):
    keys = set()

    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key)

            keys.update(
                collect_dictionary_keys(
                    child
                )
            )

    elif isinstance(value, list):
        for child in value:
            keys.update(
                collect_dictionary_keys(
                    child
                )
            )

    return keys


check(
    "no embedded vector payload keys",
    collect_dictionary_keys(
        data
    ).isdisjoint(
        forbidden_payload_keys
    ),
)

expected_profile_sidecar_text = (
    sha256(PROFILE)
    + "  "
    + "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
    + "\n"
)

check(
    "profile sidecar exact declaration",
    PROFILE_SIDECAR.read_text(
        encoding="utf-8"
    )
    == expected_profile_sidecar_text,
)

check(
    "self sidecar exists",
    SELF_SIDECAR.is_file(),
)

if SELF_SIDECAR.is_file():
    expected_self_sidecar_text = (
        sha256(SELF)
        + "  "
        + "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py"
        + "\n"
    )

    check(
        "self exact sidecar declaration",
        SELF_SIDECAR.read_text(
            encoding="utf-8"
        )
        == expected_self_sidecar_text,
    )

else:
    check(
        "self exact sidecar declaration",
        False,
    )

print(
    "qsv_mldsa_minimal_kat_profile_check_count="
    + str(checks)
)

print(
    "qsv_mldsa_minimal_kat_profile_pass_count="
    + str(
        checks - len(failures)
    )
)

print(
    "qsv_mldsa_minimal_kat_profile_failure_count="
    + str(len(failures))
)

if failures:
    for name in failures:
        print(
            "FAIL: " + name
        )

    raise SystemExit(1)

print(
    "QSV_MLDSA_MINIMAL_SIGVER_KAT_PROFILE_VERIFICATION=PASS"
)
