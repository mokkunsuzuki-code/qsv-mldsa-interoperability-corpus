#!/usr/bin/env python3

import hashlib
import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parent

SOURCE_REL = (
    "vectors/bindings/"
    "qsv-mldsa-wycheproof-vector-source-v0.1.json"
)

PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json"
)

PROVENANCE_REL = (
    "provenance/bindings/"
    "qsv-mldsa-stage393-triage-provenance-v0.1.json"
)

OBSERVATION_REL = (
    "results/"
    "qsv_mldsa_stage393_ninecase_historical_observation_evidence_v0_1.json"
)

CLAIM_REL = (
    "claims/"
    "qsv_mldsa_stage393_ninecase_historical_claim_table_v0_1.json"
)

CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-interoperability-corpus-v0.1.json"
)

SELF_REL = (
    "verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py"
)

EXPECTED_SHA256 = {
    SOURCE_REL:
        "7e15181e7bce4b6b3b8748bcc4d53d8c9a6277a3ba6104f19adfe4b08aec2295",
    PROFILE_REL:
        "7ce3fffa2284ddd3076cfbeaf5d7e009fa3b02b4064738ecf1d8b1d0d4e49fbe",
    PROVENANCE_REL:
        "1375d4927dc3b2d9dbe3befb745c9c10191a45be09fb6be5169bcd03f7241c9a",
    OBSERVATION_REL:
        "afdab2eed9329378a839d64e755435fa355147f9d0d17ddaff330e492c08ccb4",
    CLAIM_REL:
        "521c9909f93290dae6ddd16b06f5a810f76e720b3a40fde1c090a09f9280e8bf",
    CONTRACT_REL:
        "7f2e9903cee09136d1db497aa5bbeb205a0ba014dd5e761916d2d2c9c6a7f09c",
}

EXPECTED_CASE_IDS = {
    "QSV-MLDSA-WYCHEPROOF-44-0052",
    "QSV-MLDSA-WYCHEPROOF-44-0053",
    "QSV-MLDSA-WYCHEPROOF-44-0084",
    "QSV-MLDSA-WYCHEPROOF-65-0056",
    "QSV-MLDSA-WYCHEPROOF-65-0057",
    "QSV-MLDSA-WYCHEPROOF-65-0091",
    "QSV-MLDSA-WYCHEPROOF-87-0047",
    "QSV-MLDSA-WYCHEPROOF-87-0048",
    "QSV-MLDSA-WYCHEPROOF-87-0082",
}

EXPECTED_REQUIRED_CLAIM_FIELDS = [
    "claim_id",
    "fixture_id",
    "implementation",
    "implementation_lineage",
    "exact_command",
    "inputs",
    "output",
    "exit_status",
    "artifact_hashes",
    "environment",
]

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


def load_json(rel):
    return json.loads(
        (ROOT / rel).read_text(
            encoding="utf-8"
        )
    )


def check_sidecar(rel):
    target = ROOT / rel
    sidecar = ROOT / (rel + ".sha256")

    check(
        rel + " exists",
        target.is_file(),
    )

    check(
        rel + " sidecar exists",
        sidecar.is_file(),
    )

    if not target.is_file() or not sidecar.is_file():
        return

    digest = sha256(target)

    check(
        rel + " SHA256 exact",
        digest == EXPECTED_SHA256[rel],
    )

    check(
        rel + " sidecar exact",
        sidecar.read_text(
            encoding="utf-8"
        )
        == (
            digest
            + "  "
            + target.name
            + "\n"
        ),
    )


# Static-only verifier: fail closed if the crypto execution gate is present.
check(
    "QSV_EXECUTE_CRYPTO absent",
    os.environ.get("QSV_EXECUTE_CRYPTO") is None,
)

for rel in (
    SOURCE_REL,
    PROFILE_REL,
    PROVENANCE_REL,
    OBSERVATION_REL,
    CLAIM_REL,
):
    check_sidecar(rel)

contract_path = ROOT / CONTRACT_REL

check(
    "contract exists",
    contract_path.is_file(),
)

if contract_path.is_file():
    check(
        "contract SHA256 exact",
        sha256(contract_path)
        == EXPECTED_SHA256[CONTRACT_REL],
    )

source = load_json(SOURCE_REL)
profile = load_json(PROFILE_REL)
provenance = load_json(PROVENANCE_REL)
observations = load_json(OBSERVATION_REL)
claims = load_json(CLAIM_REL)
contract = load_json(CONTRACT_REL)

# ----- Wycheproof source binding -----

check(
    "Wycheproof source schema",
    source["schema"]
    == "qsv.mldsa.wycheproof-vector-source-binding.v0.1",
)

check(
    "Wycheproof commit exact",
    source["source_authority"]["selected_commit"]
    == "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166",
)

check(
    "Wycheproof tree deliberately unrecorded",
    (
        source["source_authority"]["selected_tree"] is None
        and source["source_authority"][
            "selected_tree_not_recorded_in_stage393_binding"
        ] is True
    ),
)

check(
    "six source files selected",
    source["selected_vector_surface"]["file_count"] == 6,
)

check(
    "raw vector payload not copied",
    source["execution_state"][
        "wycheproof_vector_payload_copied_to_corpus"
    ] is False,
)

# ----- Neutral nine-case profile -----

selected_cases = profile["selected_cases"]
profile_case_ids = {
    case["case_id"]
    for case in selected_cases
}

check(
    "nine profile cases",
    len(selected_cases) == 9,
)

check(
    "nine profile identities exact",
    profile_case_ids == EXPECTED_CASE_IDS,
)

check(
    "all profile expected results reject",
    all(
        case["expected_result"] == "reject"
        for case in selected_cases
    ),
)

check(
    "profile operation sign",
    profile["execution_surface"]["operation"] == "sign",
)

check(
    "profile performs no QSV crypto",
    profile["execution_state"][
        "qsv_cryptographic_execution_performed"
    ] is False,
)

# ----- Stage393 / triage provenance -----

difference = provenance["difference_summary"]

check(
    "historical difference count nine",
    difference["difference_count"] == 9,
)

check(
    "CIRCL historical difference count six",
    difference["circl_observed_difference_count"] == 6,
)

check(
    "OpenSSL historical difference count three",
    difference["openssl_observed_difference_count"] == 3,
)

check(
    "root cause classification incomplete",
    difference["root_cause_classification_complete"] is False,
)

check(
    "root cause default unknown",
    difference["root_cause_default"] == "unknown",
)

check(
    "no confirmed FIPS204 nonconformance",
    difference["confirmed_fips204_nonconformance"] is False,
)

check(
    "no confirmed implementation bug",
    difference["confirmed_implementation_bug"] is False,
)

check(
    "no confirmed security vulnerability",
    difference["confirmed_security_vulnerability"] is False,
)

check(
    "Stage393 not reexecuted",
    provenance["execution_boundary"][
        "stage393_reexecuted"
    ] is False,
)

check(
    "QSV crypto not executed",
    provenance["execution_boundary"][
        "qsv_cryptographic_execution_performed"
    ] is False,
)

# ----- Historical observation evidence -----

observation_cases = observations["cases"]
observation_case_ids = {
    case["case_id"]
    for case in observation_cases
}

check(
    "nine historical observation cases",
    len(observation_cases) == 9,
)

check(
    "historical observation identities exact",
    observation_case_ids == EXPECTED_CASE_IDS,
)

check(
    "each case has CIRCL and OpenSSL observation",
    all(
        set(case["observations"].keys())
        == {"circl", "openssl"}
        for case in observation_cases
    ),
)

check(
    "all observation root causes unknown",
    all(
        case["root_cause"] == "unknown"
        for case in observation_cases
    ),
)

obs_summary = observations["summary"]

check(
    "CIRCL observation count nine",
    obs_summary[
        "circl_historical_observation_count"
    ] == 9,
)

check(
    "OpenSSL observation count nine",
    obs_summary[
        "openssl_historical_observation_count"
    ] == 9,
)

check(
    "CIRCL expectation difference six",
    obs_summary[
        "circl_expectation_difference_count"
    ] == 6,
)

check(
    "OpenSSL expectation difference three",
    obs_summary[
        "openssl_expectation_difference_count"
    ] == 3,
)

check(
    "historical evidence is not new QSV execution",
    observations["execution_boundary"][
        "new_qsv_cryptographic_execution"
    ] is False,
)

# ----- Historical machine-readable claims -----

claim_records = claims["claims"]

check(
    "eighteen historical claims",
    len(claim_records) == 18,
)

check(
    "eighteen unique claim IDs",
    len({
        claim["claim_id"]
        for claim in claim_records
    }) == 18,
)

check(
    "claim table covers nine neutral cases",
    {
        claim["case_id"]
        for claim in claim_records
    } == EXPECTED_CASE_IDS,
)

check(
    "nine CIRCL claims",
    sum(
        1
        for claim in claim_records
        if claim["implementation"] == "circl"
    ) == 9,
)

check(
    "nine OpenSSL claims",
    sum(
        1
        for claim in claim_records
        if claim["implementation"] == "openssl"
    ) == 9,
)

check(
    "no claim is runtime-contract-complete",
    all(
        claim["runtime_contract_complete"] is False
        for claim in claim_records
    ),
)

check(
    "no missing runtime metadata reconstructed",
    all(
        (
            claim["fixture_id"] is None
            and claim["exact_command"] is None
            and claim["inputs"] is None
            and claim["exit_status"] is None
            and claim["environment"] is None
        )
        for claim in claim_records
    ),
)

check(
    "no historical claim is new QSV execution",
    all(
        claim["new_qsv_execution"] is False
        for claim in claim_records
    ),
)

check(
    "all claim root causes unknown",
    all(
        claim["root_cause"] == "unknown"
        for claim in claim_records
    ),
)

claim_summary = claims["summary"]

check(
    "claim summary 18",
    claim_summary["historical_claim_count"] == 18,
)

check(
    "claim summary runtime complete zero",
    claim_summary[
        "runtime_contract_complete_claim_count"
    ] == 0,
)

check(
    "claim summary CIRCL differences six",
    claim_summary[
        "circl_expectation_difference_count"
    ] == 6,
)

check(
    "claim summary OpenSSL differences three",
    claim_summary[
        "openssl_expectation_difference_count"
    ] == 3,
)

# ----- Existing contract boundary -----

check(
    "contract required claim fields unchanged",
    contract["claim_record_required_fields"]
    == EXPECTED_REQUIRED_CLAIM_FIELDS,
)

check(
    "claim table binds exact contract hash",
    claims["contract_binding"]["sha256"]
    == EXPECTED_SHA256[CONTRACT_REL],
)

check(
    "historical records explicitly runtime incomplete",
    claims["contract_binding"][
        "historical_records_runtime_contract_complete"
    ] is False,
)

# ----- Cross-artifact hash bindings -----

check(
    "profile binds exact Wycheproof source SHA",
    profile["source_binding"]["sha256"]
    == EXPECTED_SHA256[SOURCE_REL],
)

check(
    "provenance binds exact profile SHA",
    provenance["qsv_artifacts"]["ninecase_profile"]["sha256"]
    == EXPECTED_SHA256[PROFILE_REL],
)

check(
    "provenance binds exact source SHA",
    provenance["qsv_artifacts"]["wycheproof_source_binding"]["sha256"]
    == EXPECTED_SHA256[SOURCE_REL],
)

check(
    "observation binds exact profile SHA",
    observations["source_bindings"]["neutral_profile"]["sha256"]
    == EXPECTED_SHA256[PROFILE_REL],
)

check(
    "observation binds exact provenance SHA",
    observations["source_bindings"][
        "stage393_triage_provenance"
    ]["sha256"]
    == EXPECTED_SHA256[PROVENANCE_REL],
)

check(
    "claim table binds exact observation SHA",
    claims["source_bindings"][
        "historical_observation_evidence"
    ]["sha256"]
    == EXPECTED_SHA256[OBSERVATION_REL],
)

# ----- Self sidecar -----

self_path = ROOT / SELF_REL
self_sidecar = ROOT / (SELF_REL + ".sha256")

check(
    "static verifier self exists",
    self_path.is_file(),
)

check(
    "static verifier self sidecar exists",
    self_sidecar.is_file(),
)

if self_path.is_file() and self_sidecar.is_file():
    self_sha = sha256(self_path)

    check(
        "static verifier self sidecar exact",
        self_sidecar.read_text(
            encoding="utf-8"
        )
        == (
            self_sha
            + "  "
            + self_path.name
            + "\n"
        ),
    )


if failures:
    print("QSV_MLDSA_STAGE393_NINECASE_STATIC_INTEGRATION=FAIL")
    print("CHECK_COUNT=" + str(checks))
    print("FAILURE_COUNT=" + str(len(failures)))

    for name in failures:
        print("FAIL: " + name)

    raise SystemExit(1)


print("QSV_MLDSA_STAGE393_NINECASE_STATIC_INTEGRATION=PASS")
print("CHECK_COUNT=" + str(checks))
print("FAILURE_COUNT=0")
print("IMPORTED_STAGE393_DIFFERENCE_CASE_COUNT=9")
print("ALL_NINE_CASE_IDENTITIES_PRESERVED=YES")
print("ALL_NINE_SOURCE_PROVENANCE_BOUND=YES")
print("ALL_ORIGINAL_FIXTURE_HASHES_PRESERVED=YES")
print("ALL_EXPECTED_RESULTS_PRESERVED=YES")
print("CIRCL_HISTORICAL_OBSERVATION_COUNT=9")
print("OPENSSL_HISTORICAL_OBSERVATION_COUNT=9")
print("CIRCL_EXPECTATION_DIFFERENCE_COUNT=6")
print("OPENSSL_EXPECTATION_DIFFERENCE_COUNT=3")
print("HISTORICAL_CLAIM_COUNT=18")
print("RUNTIME_CONTRACT_COMPLETE_CLAIM_COUNT=0")
print("MISSING_RUNTIME_METADATA_RECONSTRUCTED=NO")
print("ROOT_CAUSE_CLASSIFICATION_COMPLETE=NO")
print("ROOT_CAUSE_DEFAULT=unknown")
print("CONFIRMED_FIPS204_NONCONFORMANCE=NO")
print("CONFIRMED_IMPLEMENTATION_BUG=NO")
print("CONFIRMED_SECURITY_VULNERABILITY=NO")
print("CRYPTOGRAPHIC_REEXECUTION_PERFORMED=NO")
print("NEW_QSV_CRYPTOGRAPHIC_EXECUTION=NO")
