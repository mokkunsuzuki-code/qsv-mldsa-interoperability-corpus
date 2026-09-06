#!/usr/bin/env python3

import hashlib
import json
import sys
from pathlib import Path


root = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()


contract_rel = (
    "cross-platform/"
    "qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.json"
)

sidecar_rel = contract_rel + ".sha256"


contract_path = root / contract_rel
sidecar_path = root / sidecar_rel


assert contract_path.is_file()
assert sidecar_path.is_file()


raw = contract_path.read_bytes()

digest = hashlib.sha256(
    raw
).hexdigest()


assert sidecar_path.read_text(
    encoding="utf-8"
) == (
    digest
    + "  "
    + contract_rel
    + "\n"
)


data = json.loads(
    raw.decode("utf-8")
)


assert set(
    data.keys()
) == {
    "schema",
    "classification",
    "immutable_mac_baseline",
    "source_authorities",
    "target_execution_environment",
    "execution_scope",
    "openssl_linux_build_policy",
    "circl_linux_build_policy",
    "execution_gate",
    "required_result_evidence",
    "truth_boundaries",
}


assert data[
    "schema"
] == (
    "qsv.mldsa.cross-platform-clean-environment-reproduction-contract.v0.1"
)

assert data[
    "classification"
] == "cross_platform_clean_environment_reproduction"


baseline = data[
    "immutable_mac_baseline"
]


assert baseline[
    "published_commit"
] == "717337adbbcc493ed3de328411b287328b9290dd"

assert baseline[
    "published_tree"
] == "854ed1fdc516c49420474d42c0660b07368d2aca"

assert baseline[
    "static_result_evidence_sha256"
] == "1f73e8d2570063811bb065ae6fbabb34deae12d10d1778dcdee67a8245d1058c"

assert baseline[
    "platform"
] == "macos-arm64"

assert baseline[
    "selected_case_count"
] == 6

assert baseline[
    "openssl_expectation_match_count"
] == 6

assert baseline[
    "circl_expectation_match_count"
] == 6

assert baseline[
    "cross_implementation_agreement_count"
] == 6

assert baseline[
    "operational_error_count"
] == 0

assert baseline[
    "decision"
] == "minimal_six_case_sigver_execution_pass"


authorities = data[
    "source_authorities"
]


assert authorities[
    "qsv_runtime_authority"
] == {
    "commit":
        "fd892bd79478fb5250a4e4dfa53705dd58d8b173",

    "tree":
        "37e27a32534381fc43affdeae7bcf9050ee990a2",
}


assert authorities[
    "nist_acvp"
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


assert authorities[
    "circl"
] == {
    "commit":
        "cfa7c70defd831ffb0792ab2af560bfef43d60ca",

    "tree":
        "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",
}


assert authorities[
    "openssl"
] == {
    "version":
        "3.6.3",

    "commit":
        "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",

    "tree":
        "a8a306c000bc2426afd3264b2c41bc7223728475",
}


target = data[
    "target_execution_environment"
]


assert target[
    "provider"
] == "github_actions"

assert target[
    "runner_label"
] == "ubuntu-24.04"

assert target[
    "expected_os_family"
] == "linux"

assert target[
    "expected_architecture"
] == "x86_64"

assert target[
    "clean_ephemeral_environment_required"
] is True

assert target[
    "third_party_independent_reproduction"
] is False


scope = data[
    "execution_scope"
]


assert scope[
    "operation"
] == "sigVer"

assert scope[
    "revision"
] == "FIPS204"

assert scope[
    "selected_case_count"
] == 6

assert scope[
    "positive_case_count"
] == 3

assert scope[
    "negative_case_count"
] == 3


expected_cases = [
    ("ML-DSA-44", 1, 1, False),
    ("ML-DSA-44", 1, 3, True),
    ("ML-DSA-65", 3, 31, False),
    ("ML-DSA-65", 3, 33, True),
    ("ML-DSA-87", 5, 61, False),
    ("ML-DSA-87", 5, 63, True),
]


actual_cases = [
    (
        case["parameter_set"],
        case["tg_id"],
        case["tc_id"],
        case["expected_valid"],
    )
    for case in scope["cases"]
]


assert actual_cases == expected_cases


openssl_policy = data[
    "openssl_linux_build_policy"
]


assert openssl_policy[
    "exact_source_commit_required"
] is True

assert openssl_policy[
    "exact_source_tree_required"
] is True

assert openssl_policy[
    "detached_checkout_required"
] is True

assert openssl_policy[
    "configure_target"
] == "linux-x86_64"

assert openssl_policy[
    "configure_options"
] == ["no-shared"]

assert openssl_policy[
    "runtime_version_must_equal"
] == "3.6.3"

assert openssl_policy[
    "source_and_build_recipe_provenance_required"
] is True

assert openssl_policy[
    "absolute_build_provenance_complete_claim_allowed"
] is False


circl_policy = data[
    "circl_linux_build_policy"
]


assert circl_policy[
    "exact_source_commit_required"
] is True

assert circl_policy[
    "exact_source_tree_required"
] is True

assert circl_policy[
    "detached_checkout_required"
] is True

assert circl_policy[
    "existing_upstream_go_mod_required"
] is True

assert circl_policy[
    "go_mod_init_allowed"
] is False

assert circl_policy[
    "go_mod_sum_mutation_allowed"
] is False


gate = data[
    "execution_gate"
]


assert gate[
    "qsv_execute_crypto_parent_environment_allowed"
] is False

assert gate[
    "qsv_execute_crypto_yes_allowed_only_in_isolated_execution_subprocesses"
] is True

assert gate[
    "raw_vector_payload_location"
] == "ephemeral_tmp_only"

assert gate[
    "raw_vector_payload_persistence_allowed"
] is False

assert gate[
    "openssl_linux_result_count_required"
] == 6

assert gate[
    "circl_linux_result_count_required"
] == 6

assert gate[
    "openssl_linux_expectation_match_count_required"
] == 6

assert gate[
    "circl_linux_expectation_match_count_required"
] == 6

assert gate[
    "linux_cross_implementation_agreement_count_required"
] == 6

assert gate[
    "mac_linux_openssl_behavior_agreement_count_required"
] == 6

assert gate[
    "mac_linux_circl_behavior_agreement_count_required"
] == 6

assert gate[
    "operational_error_count_required"
] == 0

assert gate[
    "expectation_mismatch_count_required"
] == 0

assert gate[
    "execution_error_count_required"
] == 0

assert gate[
    "pass_decision"
] == "cross_platform_clean_environment_reproduction_pass"


required = data[
    "required_result_evidence"
]


for key in (
    "bind_mac_baseline_commit",
    "bind_mac_baseline_tree",
    "bind_mac_static_result_evidence_sha256",
    "bind_nist_commit_tree_and_file_hashes",
    "bind_runtime_authority_commit_tree",
    "bind_circl_commit_tree",
    "bind_openssl_commit_tree",
    "capture_linux_environment",
    "capture_openssl_build_recipe",
    "capture_openssl_built_binary_sha256",
    "capture_circl_built_binary_sha256",
    "capture_per_case_expected_and_actual_results",
    "capture_per_case_cross_implementation_agreement",
    "capture_per_case_mac_linux_behavior_agreement",
):
    assert required[key] is True


assert required[
    "raw_vector_payload_fields_allowed"
] is False


truth = data[
    "truth_boundaries"
]


for key in (
    "reproduction_implies_nist_validation",
    "reproduction_implies_fips_204_certification",
    "reproduction_implies_complete_fips_204_conformance",
    "reproduction_implies_complete_sigver_coverage",
    "cross_platform_agreement_implies_correctness",
    "github_hosted_execution_is_third_party_independent_verification",
    "github_runner_is_immutable_build_environment",
    "openssl_build_provenance_complete_before_execution_evidence",
    "current_six_case_mac_baseline_may_be_rewritten",
):
    assert truth[key] is False


for forbidden in (
    "publication_state",
    "execution_state",
    "results_state",
    "published",
    "completed",
):
    assert forbidden not in data


print(
    "QSV_MLDSA_CROSS_PLATFORM_REPRODUCTION_CONTRACT_VERIFICATION=PASS"
)

print(
    "IMMUTABLE_MAC_BASELINE_BOUND=YES"
)

print(
    "TARGET_PLATFORM=ubuntu-24.04-x86_64"
)

print(
    "OPENSSL_EXACT_SOURCE_REQUIRED=YES"
)

print(
    "CIRCL_EXACT_SOURCE_REQUIRED=YES"
)

print(
    "SELECTED_CASE_COUNT=6"
)

print(
    "MAC_LINUX_OPENSSL_AGREEMENT_REQUIRED=6"
)

print(
    "MAC_LINUX_CIRCL_AGREEMENT_REQUIRED=6"
)

print(
    "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false"
)

print(
    "ABSOLUTE_OPENSSL_BUILD_PROVENANCE_COMPLETE_CLAIM_ALLOWED=false"
)
