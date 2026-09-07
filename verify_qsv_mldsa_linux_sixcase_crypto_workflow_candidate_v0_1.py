#!/usr/bin/env python3

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else Path(__file__).resolve().parent
)

WF_REL = (
    ".github/workflows/"
    "qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml"
)

WF_SIDECAR_REL = WF_REL + ".sha256"

VERIFIER_REL = (
    "verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py"
)

VERIFIER_SIDECAR_REL = VERIFIER_REL + ".sha256"

EXPECTED_WORKFLOW_SHA256 = (
    "123d31afd0e2eaa6deba5ab42a90b040"
    "c452d08f72eb61e23db4b3dc1c7c8c52"
)

EXPECTED_FILES = {
    WF_REL,
    WF_SIDECAR_REL,
    VERIFIER_REL,
    VERIFIER_SIDECAR_REL,
}


def sha256(rel):
    return hashlib.sha256(
        (ROOT / rel).read_bytes()
    ).hexdigest()


actual_files = {
    p.relative_to(ROOT).as_posix()
    for p in ROOT.rglob("*")
    if p.is_file()
    and "__pycache__" not in p.parts
}

assert actual_files == EXPECTED_FILES

assert sha256(
    WF_REL
) == EXPECTED_WORKFLOW_SHA256

assert (
    ROOT / WF_SIDECAR_REL
).read_text(
    encoding="utf-8"
) == (
    EXPECTED_WORKFLOW_SHA256
    + "  "
    + WF_REL
    + "\n"
)

verifier_sha = sha256(
    VERIFIER_REL
)

assert (
    ROOT / VERIFIER_SIDECAR_REL
).read_text(
    encoding="utf-8"
) == (
    verifier_sha
    + "  "
    + VERIFIER_REL
    + "\n"
)

workflow = (
    ROOT / WF_REL
).read_text(
    encoding="utf-8"
)

ruby = shutil.which("ruby")
assert ruby is not None

ruby_script = r'''
require "psych"
require "json"

value = Psych.safe_load(
  File.read(ARGV[0]),
  aliases: false
)

puts JSON.generate(value)
'''

proc = subprocess.run(
    [
        ruby,
        "-rpsych",
        "-rjson",
        "-e",
        ruby_script,
        str(ROOT / WF_REL),
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
)

assert proc.returncode == 0, proc.stderr

parsed = json.loads(
    proc.stdout
)

assert parsed["on"] == {
    "workflow_dispatch": {},
}

assert parsed["permissions"] == {
    "contents": "read",
}

jobs = parsed["jobs"]

assert list(
    jobs.keys()
) == [
    "explicit-six-case-crypto"
]

job = jobs[
    "explicit-six-case-crypto"
]

assert job["runs-on"] == "ubuntu-24.04"

env = job["env"]

assert isinstance(
    env,
    dict,
)

assert "QSV_EXECUTE_CRYPTO" not in env

required_env = {
    "PUBLISHED_BASE_COMMIT":
        "9147de5e27a2764a95d7ef296b24b8c5bf235286",

    "PUBLISHED_BASE_TREE":
        "ee64d8091cbe9b0b811b5310b1f58788142da70d",

    "PUBLISHED_BASE_ROOT_SHA256":
        "323485b7d41ba631d04e577bb9666f4779db63eb9094bfdcee084fc7e873ba26",

    "AUTHORITY_DESIGN_DIAGNOSTIC_SHA256":
        "ec0efd2f1c2b175b223a44f0c5b9fd9af4170c241def47aab4da5b88e6843bc4",

    "EXACT_RUNTIME_INTERFACE_CLOSURE_SHA256":
        "2b0597aff36b603b22e3fd9f59bebb71a1f6920337ec488d76a00ef1626f0beb",

    "ATTEMPT_1_FAILURE_DIAGNOSTIC_SHA256":
        "0647b5c4350be4edb8ee1983e576008ae11a3fd7cb6f5d4c8e75f2b9aad8b068",

    "ATTEMPT_1_FAILURE_DIAGNOSTIC_SIDECAR_FILE_SHA256":
        "e1c8c85290bd9a2136d067161aca96c9ec200aa53634dab389d5dcc44d6d04e5",

    "NO_CRYPTO_PRECHECK_WORKFLOW_ID":
        "351986290",

    "NO_CRYPTO_PRECHECK_RUN_ID":
        "34083609487",

    "NO_CRYPTO_PRECHECK_JOB_ID":
        "101623392974",

    "NO_CRYPTO_EVIDENCE_SHA256":
        "bbc7f498231b96726e7bb7d4412269088d74e75cc7f15208974c937bbda2d31f",

    "NO_CRYPTO_VERIFIER_SHA256":
        "d37f60d22b172ed28655938dfe6afb02b3fe6a5f597fa3b04d721f5a3e547e1c",

    "PROFILE_SHA256":
        "0807afb1b87b73d556ba43a07943f62313edb623d74c13024b83c7dfa132e98d",

    "EXTRACTOR_SHA256":
        "0bdad8db61b008ce50e6c53a472d3e56d36cf8169318cb50474672d62e566679",

    "METADATA_SHA256":
        "27104ea68cb2c47c10c0265ca8772b2c4af792ea7b2d5d34925511aefc2592d6",

    "OPENSSL_HARNESS_SOURCE_SHA256":
        "0d5c2030409425115680d3140429918210fbc63c5f18bb0c08257314bd6e6240",

    "CIRCL_HARNESS_SOURCE_SHA256":
        "f3c551821f4c31b8f7fd7242e66002c4aa1cc3dd0abb0c56710f3d0a91fc0fed",

    "RUNTIME_CONTRACT_SHA256":
        "6e3c5161c978ec4a045ad1c72ed491967ae66c1501d83aab660ffcde7cca307e",

    "NIST_COMMIT":
        "975de31eb83d87039ec88934fdc47d8c312b892d",

    "NIST_TREE":
        "a6b81add7faf8a8b647afcdc54268615decde9b5",

    "NIST_PROMPT_SHA256":
        "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",

    "NIST_EXPECTED_RESULTS_SHA256":
        "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",

    "OPENSSL_VERSION_REQUIRED":
        "3.6.3",

    "OPENSSL_COMMIT":
        "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",

    "OPENSSL_TREE":
        "a8a306c000bc2426afd3264b2c41bc7223728475",

    "CIRCL_COMMIT":
        "cfa7c70defd831ffb0792ab2af560bfef43d60ca",

    "CIRCL_TREE":
        "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",

    "GO_VERSION_REQUIRED":
        "1.26.5",

    "GO_LINUX_AMD64_SHA256":
        "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",

    "EXPECTED_TOTAL_CASE_COUNT":
        "6",

    "EXPECTED_VALID_CASE_COUNT":
        "3",

    "EXPECTED_INVALID_CASE_COUNT":
        "3",
}

for key, expected in required_env.items():

    assert key in env, key

    assert str(
        env[key]
    ) == expected, key

assert env["QSV_REMOTE"] == (
    "https://github.com/mokkunsuzuki-code/"
    "qsv-mldsa-interoperability-corpus.git"
)

assert env["NIST_REMOTE"] == (
    "https://github.com/usnistgov/ACVP-Server.git"
)

assert env["OPENSSL_REMOTE"] == (
    "https://github.com/openssl/openssl.git"
)

assert env["CIRCL_REMOTE"] == (
    "https://github.com/cloudflare/circl.git"
)

assert env["GO_LINUX_AMD64_URL"] == (
    "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"
)

steps = job["steps"]

expected_step_names = [
    "Validate execution authority and parent gate",
    "Record runner environment",
    "Fetch exact published QSV and no-crypto evidence",
    "Fetch exact NIST ACVP six-case authority",
    "Build exact OpenSSL 3.6.3 source and harness",
    "Fetch exact official Go archive and build exact CIRCL source",
    "Reconfirm fail-closed gates before explicit crypto",
    "Execute explicit six-case cryptographic verification",
    "Final explicit crypto reproduction decision",
]

assert [
    step["name"]
    for step in steps
] == expected_step_names

for step in steps:

    assert step.get(
        "shell"
    ) == "bash"

    assert "uses" not in step
    assert "env" not in step

assert "$GITHUB_ENV" not in workflow
assert "git push" not in workflow
assert "actions/checkout" not in workflow
assert "upload-artifact" not in workflow

assert (
    'cat > "${WORK}/openssl-build.env" <<EOF'
    not in workflow
)

assert (
    'cat > "${WORK}/circl-build.env" <<EOF'
    not in workflow
)

for literal in [
    "ATTEMPT_1_YAML_FAILURE_LINEAGE_BOUND=PASS",
    "OPENSSL_BUILD_ENV_WRITTEN_WITH_INDENTATION_SAFE_PRINTF=PASS",
    "CIRCL_BUILD_ENV_WRITTEN_WITH_INDENTATION_SAFE_PRINTF=PASS",
]:
    assert literal in workflow

positive_pattern = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"QSV_EXECUTE_CRYPTO=YES"
    r"(?=\s|\\|$)"
)

assert len(
    positive_pattern.findall(
        workflow
    )
) == 3

crypto_step = next(
    step
    for step in steps
    if step["name"]
    == "Execute explicit six-case cryptographic verification"
)

crypto_run = crypto_step["run"]

for step in steps:

    if step is crypto_step:
        continue

    assert not positive_pattern.search(
        step["run"]
    )

positive_lines = [
    line.strip()
    for line in crypto_run.splitlines()
    if positive_pattern.search(
        line
    )
]

assert len(
    positive_lines
) == 3

assert all(
    line.startswith(
        "env QSV_EXECUTE_CRYPTO=YES"
    )
    for line in positive_lines
)

assert (
    "export QSV_EXECUTE_CRYPTO=YES"
    not in workflow
)

pre_gate = next(
    step
    for step in steps
    if step["name"]
    == "Reconfirm fail-closed gates before explicit crypto"
)["run"]

for literal in [
    "EXTRACTOR_NEGATIVE_GATE_REJECTED_COUNT=3",
    "OPENSSL_NEGATIVE_GATE_REJECTED_COUNT=3",
    "CIRCL_NEGATIVE_GATE_REJECTED_COUNT=3",
    "TOTAL_NEGATIVE_GATE_REJECTED_COUNT=9",
    "PRE_CRYPTO_FAIL_CLOSED_GATE_RECONFIRMATION=PASS",
]:
    assert literal in pre_gate

for literal in [
    '--runtime-dir "${PAYLOAD}"',

    "RUNTIME_PAYLOAD_EXACT_SIX_CASE_HASH_VALIDATION=PASS",

    'test "${OPENSSL_COUNT}" -eq 6',
    'test "${CIRCL_COUNT}" -eq 6',
    'test "${CROSS_COUNT}" -eq 6',

    'test "${VALID_COUNT}" -eq 3',
    'test "${INVALID_COUNT}" -eq 3',

    'test "${OPERATIONAL_ERROR_COUNT}" -eq 0',

    "RAW_PAYLOAD_DELETION_BEFORE_RESULT_EVIDENCE=PASS",

    '"linux_six_case_crypto_execution_pass"',

    '"cryptographic_execution_performed": True',

    '"cryptographic_signature_verification_performed": True',

    '"runtime_payload_emitted_during_execution": True',

    '"runtime_payload_present_at_finalization": False',

    '"raw_payload_published": False',

    "RAW_RUNTIME_VECTOR_PAYLOAD_PRESENT_AT_FINALIZATION=NO",

    "RAW_RUNTIME_VECTOR_PAYLOAD_PUBLISHED=NO",

    "QSV_EXECUTE_CRYPTO_YES_SCOPED_TO_CHILD_PROCESS=YES",

    "QSV_MLDSA_LINUX_SIX_CASE_CRYPTO_EXECUTION=PASS",
]:
    assert literal in crypto_run, literal

for case in [
    '("ML-DSA-44", 1, 1, False)',
    '("ML-DSA-44", 1, 3, True)',
    '("ML-DSA-65", 3, 31, False)',
    '("ML-DSA-65", 3, 33, True)',
    '("ML-DSA-87", 5, 61, False)',
    '("ML-DSA-87", 5, 63, True)',
]:
    assert case in crypto_run

assert crypto_run.index(
    "RAW_PAYLOAD_DELETION_BEFORE_RESULT_EVIDENCE=PASS"
) < crypto_run.index(
    "STATIC_RUNTIME_RESULT_EVIDENCE_GENERATION=PASS"
)

final_run = next(
    step
    for step in steps
    if step["name"]
    == "Final explicit crypto reproduction decision"
)["run"]

for literal in [
    "QSV_MLDSA_LINUX_SIX_CASE_EXPLICIT_CRYPTO_REPRODUCTION=PASS",

    "SELECTED_CASE_COUNT=6",

    "OPENSSL_VERIFIED_CASE_COUNT=6",

    "CIRCL_VERIFIED_CASE_COUNT=6",

    "CROSS_IMPLEMENTATION_AGREEMENT_COUNT=6",

    "CRYPTOGRAPHIC_EXECUTION_PERFORMED=YES",

    "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION_PERFORMED=YES",

    "RAW_RUNTIME_VECTOR_PAYLOAD_PRESENT_AT_FINALIZATION=NO",

    "RAW_RUNTIME_VECTOR_PAYLOAD_PUBLISHED=NO",

    "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false",

    "GITHUB_RUNNER_IMMUTABLE_BUILD_ENVIRONMENT=false",

    "ABSOLUTE_OPENSSL_BUILD_PROVENANCE_COMPLETE_CLAIM_ALLOWED=false",

    "NIST_VALIDATION_CLAIM_ALLOWED=false",

    "FIPS_204_CERTIFICATION_CLAIM_ALLOWED=false",

    "COMPLETE_FIPS_204_CONFORMANCE_CLAIM_ALLOWED=false",

    "COMPLETE_SIGVER_COVERAGE_CLAIM_ALLOWED=false",
]:
    assert literal in final_run

assert workflow.count(
    "workflow_dispatch"
) == 1

assert "pull_request:" not in workflow
assert "\npush:" not in workflow
assert "schedule:" not in workflow

print(
    "QSV_MLDSA_LINUX_SIX_CASE_CRYPTO_WORKFLOW_CANDIDATE_VERIFICATION=PASS"
)

print(
    "WORKFLOW_SHA256="
    + EXPECTED_WORKFLOW_SHA256
)

print(
    "PSYCH_YAML_STRUCTURE=PASS"
)

print(
    "WORKFLOW_DISPATCH_ONLY=YES"
)

print(
    "CONTENTS_PERMISSION_READ_ONLY=YES"
)

print(
    "EXTERNAL_ACTIONS_USED=NO"
)

print(
    "QSV_EXECUTE_CRYPTO_GLOBAL_ENV_PRESENT=NO"
)

print(
    "QSV_EXECUTE_CRYPTO_JOB_ENV_PRESENT=NO"
)

print(
    "QSV_EXECUTE_CRYPTO_GITHUB_ENV_PERSISTENCE_PRESENT=NO"
)

print(
    "POSITIVE_GATE_ASSIGNMENT_LITERAL_COUNT=3"
)

print(
    "POSITIVE_GATE_ASSIGNMENTS_ONLY_IN_EXPLICIT_CRYPTO_STEP=YES"
)

print(
    "EXPECTED_RUNTIME_OPENSSL_CRYPTO_CASE_COUNT=6"
)

print(
    "EXPECTED_RUNTIME_CIRCL_CRYPTO_CASE_COUNT=6"
)

print(
    "EXPECTED_RUNTIME_CROSS_IMPLEMENTATION_CASE_COUNT=6"
)

print(
    "RAW_PAYLOAD_DELETION_BEFORE_RESULT_EVIDENCE=YES"
)

print(
    "RESULT_NONCLAIM_BOUNDARIES_PRESENT=YES"
)

print(
    "VERIFIER_SIDECAR_SELF_INTEGRITY_CHECK=PASS"
)
