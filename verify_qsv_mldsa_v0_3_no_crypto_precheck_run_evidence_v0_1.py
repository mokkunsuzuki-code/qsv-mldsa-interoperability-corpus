#!/usr/bin/env python3
import hashlib
import json
import re
import sys
from pathlib import Path

EVIDENCE_FILE = "qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json"
EVIDENCE_SIDECAR_FILE = "qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json.sha256"
VERIFIER_FILE = "verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py"
VERIFIER_SIDECAR_FILE = "verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py.sha256"

EXPECTED_JSON = '{\n  "absolute_openssl_build_provenance_complete_claim_allowed": false,\n  "all_exact_runtime_yes_markers_absent": true,\n  "all_job_steps_success": true,\n  "all_nine_fail_closed_negative_gates": true,\n  "all_required_no_markers_present": true,\n  "artifact_type": "qsv_mldsa_no_crypto_precheck_run_evidence",\n  "cc_version": "cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0",\n  "circl_build_from_exact_commit": true,\n  "circl_exact_source_build": true,\n  "circl_go_mod_sum_unchanged": true,\n  "circl_harness_binary_sha256": "b53ca61dd665f628770a2d2326e3b335ea35bc2a18f5dbfd2a23374064c230c0",\n  "circl_harness_compiled_from_published_bytes": true,\n  "circl_negative_gate_rejected_count": 3,\n  "circl_source_commit": "cfa7c70defd831ffb0792ab2af560bfef43d60ca",\n  "circl_source_tree": "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",\n  "circl_verify_executed": false,\n  "compiler_environment_diagnostic_sha256": "c5d18f4aa5efab58d70c45417c79bbea9a0de74ccdb03744d85d650962a0e4cc",\n  "complete_fips_204_conformance_claim_allowed": false,\n  "complete_sigver_coverage_claim_allowed": false,\n  "cross_platform_no_crypto_precheck": true,\n  "cryptographic_execution_performed": false,\n  "cryptographic_signature_verification_performed": false,\n  "decision": "github_actions_cross_platform_no_crypto_precheck_forensically_verified",\n  "duplicate_identical_no_markers_allowed_semantically": true,\n  "exact_runtime_positive_count": 0,\n  "extracted_log_canonical_sha256": "b5a8c334cffc8cfd55ff045563489a29b43a24acde76f77c4eccf9f8d1845627",\n  "extracted_log_manifest_sha256": "67fa96dd8826aeb4f846b887bb94655827bec1359a30c9677c31da920a336494",\n  "extractor_negative_gate_rejected_count": 3,\n  "fips_204_certification_claim_allowed": false,\n  "forensic_hash_manifest_closure_v2_sha256": "02519e0d798290bbaa86edcfef0710f61fea571ac130416bd443bd939a10c0b5",\n  "forensic_runtime_summary_closure_v2_sha256": "e2d701fca658f5db854c98c9377b17c7233f958e28c170b124d08470cee64819",\n  "gcc_version": "gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0",\n  "gh_run_view_log_sha256": "763114102e9f1b47ec3ac7a085c740671c0034d9b0fde56b2cce9176103824a3",\n  "github_runner_immutable_build_environment": false,\n  "go_archive_sha256": "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",\n  "go_archive_sha256_runtime_verified": true,\n  "go_runtime_version": "go version go1.26.5 linux/amd64",\n  "go_toolchain_source": "official_go_archive_sha256_pinned",\n  "go_version_required": "1.26.5",\n  "job_id": 101623392974,\n  "job_step_count": 10,\n  "jobs_json_sha256": "fbfdce5031792fcc6bbed62701fcfcb8ee632a90c87c1c2a6dfdbdacbb0446e3",\n  "make_version": "GNU Make 4.3",\n  "minimal_sigver_profile_canonical_sha256": "acb84ee1b8dafd1ed84273f4820349ab2e40f3f5c1bd2e0cd0f5e482b78a2646",\n  "minimal_sigver_profile_sha256": "0807afb1b87b73d556ba43a07943f62313edb623d74c13024b83c7dfa132e98d",\n  "mutable_publication_state_present": false,\n  "nist_sigver_expected_results_sha256": "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",\n  "nist_sigver_prompt_sha256": "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",\n  "nist_source_commit": "975de31eb83d87039ec88934fdc47d8c312b892d",\n  "nist_source_tree": "a6b81add7faf8a8b647afcdc54268615decde9b5",\n  "nist_validation_claim_allowed": false,\n  "no_crypto_marker_multiplicity_closure_v2_sha256": "9268bda83ad2174f4333de6c04fa896338947332f8e72284e285b58fe1a24409",\n  "no_crypto_runtime_boundary_forensically_verified": true,\n  "openssl_built_binary_sha256": "9890f1d3c25a47542fe9b6af4cdf388bdeaf8e540da964250db9db07ae6f055e",\n  "openssl_built_libcrypto_sha256": "6a42bd54b99c5ad0c8edff083ae1f05b329f81cb10b125943b34a0510a36b769",\n  "openssl_configure_command": "./Configure linux-x86_64 no-shared --prefix=<ephemeral> --openssldir=<ephemeral>/ssl",\n  "openssl_evp_pkey_verify_executed": false,\n  "openssl_exact_source_build": true,\n  "openssl_harness_binary_sha256": "a9f7ed9184e98d203864fd68681ad65bac3e4bc34b8730151a91ac3174fa5fdf",\n  "openssl_harness_compiled_from_published_bytes": true,\n  "openssl_negative_gate_rejected_count": 3,\n  "openssl_runtime_version": "3.6.3",\n  "openssl_source_build_from_exact_commit": true,\n  "openssl_source_commit": "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",\n  "openssl_source_tree": "a8a306c000bc2426afd3264b2c41bc7223728475",\n  "perl_version": "v5.38.2",\n  "positive_marker_diagnostic_sha256": "a5cd72b4be2857ce4fa6fb60224086eef0deb7ef6298dd9a94df2886b9062ccd",\n  "possible_runtime_assignment_or_execution_count": 0,\n  "private_key_material_present": false,\n  "published_commit": "30e72a48f528ad350daec65bbc74da44eabd87d6",\n  "published_tree": "2484792d9cd9493b10e1f1c24fe954b6188ebf0f",\n  "python_version": "Python 3.12.3",\n  "qsv_execute_crypto_parent_environment": "ABSENT",\n  "qsv_execute_crypto_yes_literal_occurrence_count": 9,\n  "qsv_execute_crypto_yes_reference_only_count": 9,\n  "qsv_execute_crypto_yes_runtime_assignment_count": 0,\n  "qsv_execute_crypto_yes_runtime_execution_count": 0,\n  "qsv_execute_crypto_yes_set": false,\n  "qsv_execute_crypto_yes_stop_rejection_count": 9,\n  "raw_runtime_vector_payload_emitted": false,\n  "raw_vector_payload_in_candidate": false,\n  "repository": "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",\n  "root_verifier_sha256": "b614fe092edd03f09fe13b26e30a0f3889b3d133172305fcc589f3c6641bebdd",\n  "root_verifier_sidecar_file_sha256": "cd98f2657ec93c49bd7728e1041755fea3989342c1f1f33fecdbd7ed3d5b7f16",\n  "run_attempt": 1,\n  "run_conclusion": "success",\n  "run_created_at": "2026-09-07T04:34:32Z",\n  "run_event": "workflow_dispatch",\n  "run_id": 34083609487,\n  "run_json_sha256": "f1668fb11f083ba9a563288bdcb0d06dd8f1d749e585d0006c80857a6036e4e2",\n  "run_log_archive_sha256": "693a010ab3ba5e434bda8b44674e86d8b717630f84c923e7575e97fbd4b0d3aa",\n  "run_number": 1,\n  "run_status": "completed",\n  "run_updated_at": "2026-09-07T04:38:15Z",\n  "runner_arch": "X64",\n  "runner_image_os": "ubuntu24",\n  "runner_image_version": "20260831.293.1",\n  "runner_os": "Linux",\n  "runtime_binary_hashes_closure_v2_sha256": "54ecdaf07a0e1ae513ce2b61aa89f657692a2d34835b3462e62ed03deba0a4e7",\n  "runtime_environment_closure_v2_sha256": "2694ccc2100da075e0bd4d3aca9e8eef5aa02c122464a111d16a49ba0505c866",\n  "schema_version": "v0.1",\n  "selected_case_count": 6,\n  "semantic_positive_marker_decision_closure_v2_sha256": "0f557b3f406129eca62e130b1ec62fea998f45a8eb8e7dd60a71203717384165",\n  "semantic_positive_marker_false_positive_resolved": true,\n  "target_architecture": "x86_64",\n  "target_runner": "ubuntu-24.04",\n  "third_party_independent_reproduction": false,\n  "total_negative_gate_count": 9,\n  "total_negative_gate_rejected_count": 9,\n  "uname": "Linux runnervmejwal 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux",\n  "workflow_id": 351986290,\n  "workflow_path": ".github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml",\n  "workflow_sha256": "f4197f42e2ed6a76c66b12d9f10c069b2d1ef5d7f3653d46a3b80858c858cdc0",\n  "workflow_sidecar_file_sha256": "596ed58fcf00c1a4c2f9d0424027fb4c210acc95e7f59a62ec7d62ee0c59057c",\n  "workflow_verifier_sha256": "8c628a36cb0ae548d4f3a1a3da4033ceccd02fe6b60683b1183bd36dc58b3f18",\n  "workflow_verifier_sidecar_file_sha256": "d46df9192158facf25c43af9d8bd75d5c0963b8426138a5cac29a4fcc5a2d95c"\n}\n'


def fail(message):
    print("FAIL: " + message)
    raise SystemExit(1)


def sha256_file(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def check_sidecar(sidecar, target):
    expected = (
        sha256_file(target)
        + "  "
        + target.name
        + "\n"
    )

    actual = sidecar.read_text(
        encoding="utf-8"
    )

    if actual != expected:
        fail(
            "sidecar mismatch: "
            + sidecar.name
        )


root = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()

evidence = root / EVIDENCE_FILE
evidence_sidecar = root / EVIDENCE_SIDECAR_FILE
verifier = root / VERIFIER_FILE
verifier_sidecar = root / VERIFIER_SIDECAR_FILE

expected_files = {
    EVIDENCE_FILE,
    EVIDENCE_SIDECAR_FILE,
    VERIFIER_FILE,
    VERIFIER_SIDECAR_FILE,
}

actual_files = {
    p.name
    for p in root.iterdir()
    if p.is_file()
}

if actual_files != expected_files:
    fail("candidate fileset mismatch")

for path in [
    evidence,
    evidence_sidecar,
    verifier,
    verifier_sidecar,
]:
    if not path.is_file():
        fail("missing file: " + path.name)

check_sidecar(
    evidence_sidecar,
    evidence,
)

check_sidecar(
    verifier_sidecar,
    verifier,
)

try:
    data = json.loads(
        evidence.read_text(
            encoding="utf-8"
        )
    )
except Exception as exc:
    fail(
        "evidence JSON parse failed: "
        + str(exc)
    )

expected = json.loads(
    EXPECTED_JSON
)

if data != expected:
    fail("semantic evidence mismatch")

canonical = (
    json.dumps(
        data,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
    )
    + "\n"
)

if evidence.read_text(
    encoding="utf-8"
) != canonical:
    fail("evidence is not canonical JSON")

if data["total_negative_gate_count"] != 9:
    fail("negative gate count")

if data["total_negative_gate_rejected_count"] != 9:
    fail("negative rejected count")

if data["qsv_execute_crypto_yes_runtime_assignment_count"] != 0:
    fail("runtime assignment count")

if data["qsv_execute_crypto_yes_runtime_execution_count"] != 0:
    fail("runtime execution count")

if data["exact_runtime_positive_count"] != 0:
    fail("runtime positive count")

if data[
    "possible_runtime_assignment_or_execution_count"
] != 0:
    fail("possible runtime execution")

true_keys = [
    "all_job_steps_success",
    "go_archive_sha256_runtime_verified",
    "openssl_exact_source_build",
    "openssl_harness_compiled_from_published_bytes",
    "circl_exact_source_build",
    "circl_go_mod_sum_unchanged",
    "circl_harness_compiled_from_published_bytes",
    "all_nine_fail_closed_negative_gates",
    "all_required_no_markers_present",
    "all_exact_runtime_yes_markers_absent",
    "duplicate_identical_no_markers_allowed_semantically",
    "semantic_positive_marker_false_positive_resolved",
    "no_crypto_runtime_boundary_forensically_verified",
    "cross_platform_no_crypto_precheck",
    "openssl_source_build_from_exact_commit",
    "circl_build_from_exact_commit",
]

for key in true_keys:
    if data[key] is not True:
        fail("expected true: " + key)

false_keys = [
    "qsv_execute_crypto_yes_set",
    "openssl_evp_pkey_verify_executed",
    "circl_verify_executed",
    "cryptographic_execution_performed",
    "cryptographic_signature_verification_performed",
    "raw_runtime_vector_payload_emitted",
    "third_party_independent_reproduction",
    "github_runner_immutable_build_environment",
    "absolute_openssl_build_provenance_complete_claim_allowed",
    "nist_validation_claim_allowed",
    "fips_204_certification_claim_allowed",
    "complete_fips_204_conformance_claim_allowed",
    "complete_sigver_coverage_claim_allowed",
    "raw_vector_payload_in_candidate",
    "mutable_publication_state_present",
    "private_key_material_present",
]

for key in false_keys:
    if data[key] is not False:
        fail("expected false: " + key)

if data["qsv_execute_crypto_yes_literal_occurrence_count"] != 9:
    fail("positive literal count")

if data["qsv_execute_crypto_yes_stop_rejection_count"] != 9:
    fail("STOP rejection count")

if data["qsv_execute_crypto_yes_reference_only_count"] != 9:
    fail("reference-only count")

private_key_pattern = re.compile(
    rb"(?m)^-----BEGIN "
    rb"(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
    rb"PRIVATE KEY-----\r?$"
)

for path in [
    evidence,
    evidence_sidecar,
    verifier,
    verifier_sidecar,
]:
    if private_key_pattern.search(
        path.read_bytes()
    ):
        fail("private key material present")

print(
    "QSV_MLDSA_V0_3_NO_CRYPTO_RUN_EVIDENCE_VERIFICATION=PASS"
)
print("RUN_ID=" + str(data["run_id"]))
print("JOB_ID=" + str(data["job_id"]))
print("RUN_CONCLUSION=" + data["run_conclusion"])
print("TOTAL_NEGATIVE_GATE_COUNT=9")
print("TOTAL_NEGATIVE_GATE_REJECTED_COUNT=9")
print("ALL_NINE_FAIL_CLOSED_NEGATIVE_GATES=PASS")
print("QSV_EXECUTE_CRYPTO_YES_RUNTIME_ASSIGNMENT_COUNT=0")
print("QSV_EXECUTE_CRYPTO_YES_RUNTIME_EXECUTION_COUNT=0")
print("EXACT_RUNTIME_POSITIVE_COUNT=0")
print("CRYPTOGRAPHIC_EXECUTION_PERFORMED=NO")
print("CRYPTOGRAPHIC_SIGNATURE_VERIFICATION_PERFORMED=NO")
print("RAW_RUNTIME_VECTOR_PAYLOAD_EMITTED=NO")
print("NO_CRYPTO_RUNTIME_BOUNDARY_FORENSICALLY_VERIFIED=YES")
print("THIRD_PARTY_INDEPENDENT_REPRODUCTION=false")
print("NIST_VALIDATION_CLAIM_ALLOWED=false")
print("FIPS_204_CERTIFICATION_CLAIM_ALLOWED=false")
print("VERIFIER_SIDECAR_SELF_INTEGRITY_CHECK=PASS")
