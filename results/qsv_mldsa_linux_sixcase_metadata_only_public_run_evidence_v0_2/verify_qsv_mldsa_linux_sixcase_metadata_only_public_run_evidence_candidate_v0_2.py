#!/usr/bin/env python3
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else Path(__file__).resolve().parent
)

EVIDENCE_NAME = "qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_1.json"
EVIDENCE_SHA = "1d696fe026845b8a4c3c12d3e6ae1a97e643f56e72035c79cbd1caed7a345643"

VERIFIER_NAME = Path(__file__).name

EXPECTED_FILES = {
    EVIDENCE_NAME,
    EVIDENCE_NAME + ".sha256",
    VERIFIER_NAME,
    VERIFIER_NAME + ".sha256",
}

checks = 0
failures = []

def check(name, condition):
    global checks
    checks += 1

    if condition:
        print("PASS:", name)
    else:
        print("FAIL:", name)
        failures.append(name)

def sha256(path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)

            if not block:
                break

            h.update(block)

    return h.hexdigest()

actual_entries = {
    p.relative_to(ROOT).as_posix()
    for p in ROOT.rglob("*")
}

check(
    "exact recursive four-entry candidate set",
    actual_entries == EXPECTED_FILES,
)

check(
    "all expected candidate entries are regular non-symlink files",
    all(
        (ROOT / name).is_file()
        and not (ROOT / name).is_symlink()
        for name in EXPECTED_FILES
    ),
)

evidence_path = ROOT / EVIDENCE_NAME
evidence_sidecar = ROOT / (EVIDENCE_NAME + ".sha256")

verifier_path = ROOT / VERIFIER_NAME
verifier_sidecar = ROOT / (VERIFIER_NAME + ".sha256")

check(
    "evidence exists",
    evidence_path.is_file(),
)

check(
    "evidence sidecar exists",
    evidence_sidecar.is_file(),
)

check(
    "verifier sidecar exists",
    verifier_sidecar.is_file(),
)

if evidence_path.is_file():
    check(
        "evidence hash",
        sha256(evidence_path) == EVIDENCE_SHA,
    )

if evidence_sidecar.is_file():
    expected = (
        EVIDENCE_SHA
        + "  "
        + EVIDENCE_NAME
        + "\n"
    )

    check(
        "evidence sidecar exact declaration",
        evidence_sidecar.read_text(
            encoding="utf-8"
        )
        == expected,
    )

if verifier_sidecar.is_file():
    parts = verifier_sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    check(
        "verifier sidecar token count",
        len(parts) == 2,
    )

    if len(parts) == 2:
        check(
            "verifier sidecar basename",
            parts[1] == VERIFIER_NAME,
        )

        check(
            "verifier self integrity",
            parts[0] == sha256(verifier_path),
        )

data = json.loads(
    evidence_path.read_text(
        encoding="utf-8"
    )
)

check(
    "exact top-level JSON key set",
    set(data) == {'nonclaims', 'schema', 'evidence_class', 'github_actions_run', 'postrun_audit_recovery', 'decision', 'repository', 'runtime_payload_boundary', 'runner_and_build_observations', 'workflow', 'cryptographic_execution_summary', 'publication_boundary', 'authority_bindings'},
)

check(
    "schema",
    data.get("schema")
    == "qsv.mldsa.linux-sixcase-metadata-only-public-run-evidence.v0.1",
)

check(
    "evidence class",
    data.get("evidence_class")
    == "metadata_only_public_run_evidence",
)

check(
    "decision",
    data.get("decision")
    == "linux_sixcase_explicit_crypto_reproduction_observed_pass",
)

check(
    "repository",
    data.get("repository")
    == "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
)

workflow = data["workflow"]

check(
    "exact workflow key set",
    set(workflow)
    == {
        "workflow_id",
        "workflow_path",
        "event",
    },
)

check(
    "workflow id",
    workflow["workflow_id"] == int("352761983"),
)

check(
    "workflow path",
    workflow["workflow_path"] == ".github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml",
)

check(
    "workflow event",
    workflow["event"] == "workflow_dispatch",
)

run = data["github_actions_run"]

check(
    "exact github actions run key set",
    set(run)
    == {
        "run_id",
        "job_id",
        "head_branch",
        "head_commit_sha",
        "head_tree_sha",
        "run_attempt",
        "status",
        "conclusion",
        "job_count",
        "required_successful_step_count",
        "actions_artifact_count",
        "rerun_performed",
        "additional_dispatch_performed",
    },
)

check(
    "run id",
    run["run_id"] == int("34183766166"),
)

check(
    "job id",
    run["job_id"] == int("101927914418"),
)

check(
    "head commit",
    run["head_commit_sha"] == "018148be719cd912dfbe7238dbd0642ed30e244c",
)

check(
    "head tree",
    run["head_tree_sha"] == 'ab8d59086d2a70df4e5be6258bfeb5bea0da5036',
)

check(
    "head branch",
    run["head_branch"] == "main",
)

check(
    "run attempt",
    run["run_attempt"] == 1,
)

check(
    "run success",
    run["status"] == "completed"
    and run["conclusion"] == "success",
)

check(
    "single job",
    run["job_count"] == 1,
)

check(
    "required successful steps",
    run["required_successful_step_count"] == 9,
)

check(
    "zero actions artifacts",
    run["actions_artifact_count"] == 0,
)

check(
    "no rerun",
    run["rerun_performed"] is False,
)

check(
    "no additional dispatch",
    run["additional_dispatch_performed"] is False,
)

crypto = data["cryptographic_execution_summary"]

check(
    "exact cryptographic execution summary key set",
    set(crypto)
    == {
        "selected_case_count",
        "expected_valid_case_count",
        "expected_invalid_case_count",
        "openssl_cryptographic_case_count",
        "circl_cryptographic_case_count",
        "cross_implementation_agreement_count",
        "crypto_operational_error_count",
        "cryptographic_execution_performed",
        "cryptographic_signature_verification_performed",
        "result_evidence_sha256",
    },
)

check(
    "selected six cases",
    crypto["selected_case_count"] == 6,
)

check(
    "expected valid three",
    crypto["expected_valid_case_count"] == 3,
)

check(
    "expected invalid three",
    crypto["expected_invalid_case_count"] == 3,
)

check(
    "OpenSSL six cases",
    crypto["openssl_cryptographic_case_count"] == 6,
)

check(
    "CIRCL six cases",
    crypto["circl_cryptographic_case_count"] == 6,
)

check(
    "cross implementation six agreements",
    crypto["cross_implementation_agreement_count"] == 6,
)

check(
    "zero crypto operational errors",
    crypto["crypto_operational_error_count"] == 0,
)

check(
    "crypto execution recorded",
    crypto["cryptographic_execution_performed"] is True,
)

check(
    "signature verification recorded",
    crypto["cryptographic_signature_verification_performed"] is True,
)

check(
    "result evidence hash",
    crypto["result_evidence_sha256"] == "fec2b8063286a59988e3079a73e55a98868cc647e96c60634f94db3ac59ddf26",
)

bindings = data["authority_bindings"]

check(
    "exact authority bindings key set",
    set(bindings)
    == {
        "run_log_sha256",
        "postrun_recovery_audit_sha256",
        "postrun_audit_harness_failure_diagnostic_sha256",
        "dynamic_runner_build_observation_sha256",
    },
)

check(
    "run log binding",
    bindings["run_log_sha256"] == "270147c9d5d9a2536eae56f35653ecf161a36d580bc9fef44e57587ec7a590c3",
)

check(
    "postrun recovery binding",
    bindings["postrun_recovery_audit_sha256"]
    == "567a6c6ca06a74c0dac3dcc377c6cec7ed3360eda730b1113cc39384b9da4674",
)

check(
    "failure diagnostic binding",
    bindings[
        "postrun_audit_harness_failure_diagnostic_sha256"
    ]
    == "1a1c22cc46bb0ca9df2795497dd31d73cdbae8148a0a42ddea802450d0eee69a",
)

check(
    "dynamic observation binding",
    bindings[
        "dynamic_runner_build_observation_sha256"
    ]
    == "8bffdb0aeca3a75175c62b7d293e2e472bae3192358a22ff34b4c2881ca0a047",
)

build = data["runner_and_build_observations"]

check(
    "exact runner and build observation key set",
    set(build)
    == {'python_version', 'openssl_built_libcrypto_sha256', 'runner_arch', 'go_version', 'openssl_harness_binary_sha256', 'runner_image_version', 'openssl_built_runtime_version', 'uname', 'runner_image_os', 'perl_version', 'cc_version', 'circl_harness_binary_sha256', 'openssl_built_binary_sha256', 'runner_os', 'gcc_version', 'make_version'},
)

RUNNER_EXPECTED = {'runner_os': 'Linux', 'runner_arch': 'X64', 'runner_image_os': 'ubuntu24', 'runner_image_version': '20260831.293.1', 'uname': 'Linux runnervmejwal 6.17.0-1022-azure #22-Ubuntu SMP Mon Jul 27 17:24:03 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux', 'cc_version': 'gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0', 'gcc_version': 'gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0', 'make_version': 'GNU Make 4.3', 'perl_version': 'v5.38.2', 'python_version': 'Python 3.12.3', 'go_version': 'go version go1.26.5 linux/amd64', 'openssl_built_runtime_version': '3.6.3', 'openssl_built_binary_sha256': '92649280aacaeb7a35687b3ad9201ed3efe3d25b7aea49e083cc68437007afc3', 'openssl_built_libcrypto_sha256': '8d3757590081d550ebf3e2dfc614f413ab1e2f584471b3c4d21ef5560e563ec3', 'openssl_harness_binary_sha256': '07978755211bffcfe57f28ce6354292245a3a0af08d247c617c3f36378aa6b93', 'circl_harness_binary_sha256': 'b53ca61dd665f628770a2d2326e3b335ea35bc2a18f5dbfd2a23374064c230c0'}

for key, expected_value in RUNNER_EXPECTED.items():
    check(
        "runner/build observation " + key,
        build[key] == expected_value,
    )

check(
    "OpenSSL binary binding",
    build["openssl_built_binary_sha256"]
    == "92649280aacaeb7a35687b3ad9201ed3efe3d25b7aea49e083cc68437007afc3",
)

check(
    "libcrypto binding",
    build["openssl_built_libcrypto_sha256"]
    == "8d3757590081d550ebf3e2dfc614f413ab1e2f584471b3c4d21ef5560e563ec3",
)

check(
    "OpenSSL harness binding",
    build["openssl_harness_binary_sha256"]
    == "07978755211bffcfe57f28ce6354292245a3a0af08d247c617c3f36378aa6b93",
)

check(
    "CIRCL harness binding",
    build["circl_harness_binary_sha256"]
    == "b53ca61dd665f628770a2d2326e3b335ea35bc2a18f5dbfd2a23374064c230c0",
)

payload = data["runtime_payload_boundary"]

check(
    "exact runtime payload boundary key set",
    set(payload)
    == {
        "raw_runtime_vector_payload_emitted_during_execution",
        "raw_runtime_vector_payload_present_at_finalization",
        "raw_runtime_vector_payload_published",
        "raw_runtime_vector_payload_included_in_this_evidence",
        "private_key_material_included_in_this_evidence",
        "secret_key_material_included_in_this_evidence",
        "seed_material_included_in_this_evidence",
    },
)

check(
    "raw payload emitted during execution",
    payload[
        "raw_runtime_vector_payload_emitted_during_execution"
    ]
    is True,
)

check(
    "raw payload not present at finalization",
    payload[
        "raw_runtime_vector_payload_present_at_finalization"
    ]
    is False,
)

check(
    "raw payload not published",
    payload[
        "raw_runtime_vector_payload_published"
    ]
    is False,
)

check(
    "raw payload not included",
    payload[
        "raw_runtime_vector_payload_included_in_this_evidence"
    ]
    is False,
)

check(
    "private key not included",
    payload[
        "private_key_material_included_in_this_evidence"
    ]
    is False,
)

check(
    "secret key not included",
    payload[
        "secret_key_material_included_in_this_evidence"
    ]
    is False,
)

check(
    "seed not included",
    payload[
        "seed_material_included_in_this_evidence"
    ]
    is False,
)

recovery = data["postrun_audit_recovery"]

check(
    "exact postrun audit recovery key set",
    set(recovery)
    == {
        "original_failed_stage",
        "failure_class",
        "undefined_variable_reference",
        "intended_defined_variable",
        "crypto_run_completed_successfully_before_harness_failure",
        "recovery_required_crypto_rerun",
        "recovery_step_cryptographic_execution_performed",
    },
)

POSTRUN_RECOVERY_EXPECTED = {'original_failed_stage': 17, 'failure_class': 'post_run_audit_harness_unbound_variable', 'undefined_variable_reference': 'V02_REL', 'intended_defined_variable': 'KNOWN_V02_REL', 'crypto_run_completed_successfully_before_harness_failure': True, 'recovery_required_crypto_rerun': False, 'recovery_step_cryptographic_execution_performed': False}

for key, expected_value in POSTRUN_RECOVERY_EXPECTED.items():
    check(
        "postrun audit recovery " + key,
        recovery[key] == expected_value,
    )

publication = data["publication_boundary"]

check(
    "exact publication boundary key set",
    set(publication)
    == {
        "metadata_only",
        "contains_raw_runtime_vector_payload",
        "contains_private_key_material",
        "contains_secret_key_material",
        "contains_seed_material",
        "contains_runtime_binaries",
        "contains_actions_artifacts",
    },
)

check(
    "metadata only publication boundary",
    publication["metadata_only"] is True,
)

for key in [
    "contains_raw_runtime_vector_payload",
    "contains_private_key_material",
    "contains_secret_key_material",
    "contains_seed_material",
    "contains_runtime_binaries",
    "contains_actions_artifacts",
]:
    check(
        "publication boundary " + key,
        publication[key] is False,
    )

nonclaims = data["nonclaims"]

check(
    "exact nonclaims key set",
    set(nonclaims)
    == {
        "third_party_independent_reproduction",
        "github_runner_immutable_build_environment",
        "absolute_openssl_build_provenance_complete_claim_allowed",
        "nist_validation_claim_allowed",
        "fips_204_certification_claim_allowed",
        "complete_fips_204_conformance_claim_allowed",
        "complete_sigver_coverage_claim_allowed",
        "result_equals_nist_validation",
        "result_equals_fips_204_certification",
        "result_equals_complete_fips_204_conformance",
        "result_equals_complete_sigver_coverage",
    },
)

for key in [
    "third_party_independent_reproduction",
    "github_runner_immutable_build_environment",
    "absolute_openssl_build_provenance_complete_claim_allowed",
    "nist_validation_claim_allowed",
    "fips_204_certification_claim_allowed",
    "complete_fips_204_conformance_claim_allowed",
    "complete_sigver_coverage_claim_allowed",
    "result_equals_nist_validation",
    "result_equals_fips_204_certification",
    "result_equals_complete_fips_204_conformance",
    "result_equals_complete_sigver_coverage",
]:
    check(
        "nonclaim " + key,
        nonclaims[key] is False,
    )

text = evidence_path.read_text(
    encoding="utf-8",
    errors="strict",
)

check(
    "no PEM private key marker",
    re.search(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        text,
    )
    is None,
)

raw_exact_keys = {
    "pk",
    "sk",
    "private_key",
    "secret_key",
    "seed",
    "message",
    "context",
    "signature",
}

raw_payload_hits = []

def walk(value, path="$"):
    if isinstance(value, dict):
        for key, child in value.items():
            current = path + "." + key

            if (
                key.lower() in raw_exact_keys
                and isinstance(child, str)
                and child != ""
            ):
                raw_payload_hits.append(current)

            walk(child, current)

    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(
                child,
                path + "[" + str(index) + "]",
            )

walk(data)

check(
    "no exact raw vector payload fields",
    raw_payload_hits == [],
)

print(
    "METADATA_ONLY_PUBLIC_RUN_EVIDENCE_CHECK_COUNT="
    + str(checks)
)

print(
    "METADATA_ONLY_PUBLIC_RUN_EVIDENCE_FAILURE_COUNT="
    + str(len(failures))
)

if failures:
    raise SystemExit(1)

print(
    "QSV_MLDSA_LINUX_SIXCASE_METADATA_ONLY_PUBLIC_RUN_EVIDENCE_VERIFICATION=PASS"
)

print(
    "RAW_RUNTIME_VECTOR_PAYLOAD_INCLUDED=NO"
)

print(
    "PRIVATE_KEY_MATERIAL_INCLUDED=NO"
)

print(
    "SECRET_KEY_MATERIAL_INCLUDED=NO"
)

print(
    "SEED_MATERIAL_INCLUDED=NO"
)

print(
    "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false"
)

print(
    "GITHUB_RUNNER_IMMUTABLE_BUILD_ENVIRONMENT=false"
)

print(
    "ABSOLUTE_OPENSSL_BUILD_PROVENANCE_COMPLETE_CLAIM_ALLOWED=false"
)

print(
    "RESULT_EQUALS_NIST_VALIDATION=NO"
)

print(
    "RESULT_EQUALS_FIPS_204_CERTIFICATION=NO"
)

print(
    "RESULT_EQUALS_COMPLETE_FIPS_204_CONFORMANCE=NO"
)

print(
    "RESULT_EQUALS_COMPLETE_SIGVER_COVERAGE=NO"
)
