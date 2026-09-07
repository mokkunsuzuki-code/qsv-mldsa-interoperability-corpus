#!/usr/bin/env python3

import hashlib
import sys
from pathlib import Path


ROOT = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()


WORKFLOW_REL = (
    ".github/workflows/"
    "qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml"
)

WORKFLOW_SIDECAR_REL = (
    WORKFLOW_REL
    + ".sha256"
)

VERIFIER_REL = (
    "verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_2.py"
)

VERIFIER_SIDECAR_REL = (
    VERIFIER_REL
    + ".sha256"
)


EXPECTED_WORKFLOW_SHA = "0351a06ab03e2ff27669f00e30e5e7647bcd54af20c6e905ba2e607233e035b9"


EXPECTED_FILES = {
    WORKFLOW_REL,
    WORKFLOW_SIDECAR_REL,
    VERIFIER_REL,
    VERIFIER_SIDECAR_REL,
}


def digest(path):
    return hashlib.sha256(
        (ROOT / path).read_bytes()
    ).hexdigest()


def fail(message):
    print(
        "FAIL: "
        + message
    )
    raise SystemExit(1)


actual_files = {
    str(p.relative_to(ROOT))
    for p in ROOT.rglob("*")
    if p.is_file()
}


if actual_files != EXPECTED_FILES:
    fail(
        "exact four-file candidate set mismatch"
    )


workflow_sha = digest(
    WORKFLOW_REL
)


if workflow_sha != EXPECTED_WORKFLOW_SHA:
    fail(
        "workflow SHA256 mismatch"
    )


expected_workflow_sidecar = (
    EXPECTED_WORKFLOW_SHA
    + "  "
    + WORKFLOW_REL
    + "\n"
)


if (
    ROOT
    / WORKFLOW_SIDECAR_REL
).read_text(
    encoding="utf-8"
) != expected_workflow_sidecar:
    fail(
        "workflow sidecar mismatch"
    )


#
# Validate the verifier sidecar against the actual verifier bytes.
# The verifier does not hard-code its own hash, avoiding recursion.
#
verifier_sha = digest(
    VERIFIER_REL
)

expected_verifier_sidecar = (
    verifier_sha
    + "  "
    + VERIFIER_REL
    + "\n"
)


if (
    ROOT
    / VERIFIER_SIDECAR_REL
).read_text(
    encoding="utf-8"
) != expected_verifier_sidecar:
    fail(
        "verifier sidecar mismatch"
    )


text = (
    ROOT
    / WORKFLOW_REL
).read_text(
    encoding="utf-8"
)


def require(fragment):
    if fragment not in text:
        fail(
            "missing required fragment: "
            + fragment
        )


def forbid(fragment):
    if fragment in text:
        fail(
            "forbidden fragment: "
            + fragment
        )


require(
    "name: QSV ML-DSA Cross-Platform "
    "Clean-Environment Precheck v0.2"
)


if text.count(
    "workflow_dispatch:"
) != 1:
    fail(
        "workflow_dispatch count"
    )


for fragment in [
    "\n  push:",
    "\n  pull_request:",
    "\n  schedule:",
]:
    forbid(fragment)


require(
    "runs-on: ubuntu-24.04"
)

require(
    "permissions:\n"
    "  contents: read\n"
)


for fragment in [
    "contents: write",
    "id-token: write",
    "uses:",
    "git push",
    "upload-artifact",
    "download-artifact",
]:
    forbid(fragment)


for fragment in [
    (
        "DESIGN_CONTRACT_SHA256: "
        "9f78c559fdcb564efe4320803ce55caa5fe26f379ec2627936fac3912aca2f71"
    ),

    (
        "QSV_COMMIT: "
        "717337adbbcc493ed3de328411b287328b9290dd"
    ),

    (
        "QSV_TREE: "
        "854ed1fdc516c49420474d42c0660b07368d2aca"
    ),

    (
        "NIST_COMMIT: "
        "975de31eb83d87039ec88934fdc47d8c312b892d"
    ),

    (
        "NIST_TREE: "
        "a6b81add7faf8a8b647afcdc54268615decde9b5"
    ),

    (
        "CIRCL_COMMIT: "
        "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
    ),

    (
        "CIRCL_TREE: "
        "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139"
    ),

    (
        "OPENSSL_COMMIT: "
        "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f"
    ),

    (
        "OPENSSL_TREE: "
        "a8a306c000bc2426afd3264b2c41bc7223728475"
    ),

    "GO_VERSION_REQUIRED: 1.26.5",

    (
        "GO_LINUX_AMD64_ARCHIVE: "
        "go1.26.5.linux-amd64.tar.gz"
    ),

    (
        "GO_LINUX_AMD64_URL: "
        "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz"
    ),

    (
        "GO_LINUX_AMD64_SHA256: "
        "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053"
    ),

    'PREVIOUS_FAILED_PRECHECK_RUN_ID: "34079303462"',

    (
        "PREVIOUS_FAILED_PRECHECK_RUN_LOG_SHA256: "
        "97a3a09aff3a9e42cf57e8776b6a62b90e39c1ed4e695b9e4f39728f210e8d80"
    ),
]:
    require(fragment)


forbid(
    "RUNNER_TOOL_CACHE"
)


require(
    "Fetch exact official Go archive "
    "and build exact CIRCL source"
)


for fragment in [
    'GO_ARCHIVE_PATH="${WORK}/${GO_LINUX_AMD64_ARCHIVE}"',
    'GO_EXTRACT_ROOT="${WORK}/go-toolchain"',
    "--fail \\",
    "--location \\",
    "--proto '=https' \\",
    "--tlsv1.2 \\",
    '"${GO_LINUX_AMD64_URL}"',
    'sha256sum "${GO_ARCHIVE_PATH}"',
    ')" = "${GO_LINUX_AMD64_SHA256}"',
    '-xzf "${GO_ARCHIVE_PATH}"',
    '-C "${GO_EXTRACT_ROOT}"',
    'GO_ROOT="${GO_EXTRACT_ROOT}/go"',
    'test -x "${GO_ROOT}/bin/go"',
    'case "${GO_ROOT}" in',
    '"${RUNNER_TEMP}"/*)',
    'rm -f "${GO_ARCHIVE_PATH}"',
    'test ! -e "${GO_ARCHIVE_PATH}"',
    "GO_OFFICIAL_ARCHIVE_SHA256_VERIFICATION=PASS",
    "GO_TOOLCHAIN_SOURCE=official_go_archive_sha256_pinned",
    "GO_TOOLCHAIN_EXTRACTED_UNDER_RUNNER_TEMP=PASS",
    "GO_ARCHIVE_REMOVED_AFTER_EXTRACTION=PASS",
    "export GOTOOLCHAIN=local",
    'GO_VERSION="$(go version)"',
    (
        'test "${GO_VERSION}" = '
        '"go version go1.26.5 linux/amd64"'
    ),
]:
    require(fragment)


sha_index = text.index(
    'sha256sum "${GO_ARCHIVE_PATH}"'
)

extract_index = text.index(
    '-xzf "${GO_ARCHIVE_PATH}"'
)


if sha_index >= extract_index:
    fail(
        "archive extraction occurs before SHA256 verification"
    )


require(
    'WORK="${RUNNER_TEMP}/qsv-cross-platform-precheck"'
)


for fragment in [
    "EXTRACTOR_GATE_REJECTED_COUNT=3",
    "OPENSSL_GATE_REJECTED_COUNT=3",
    "CIRCL_GATE_REJECTED_COUNT=3",
    "ALL_EXECUTION_GATES_FAIL_CLOSED=PASS",
]:
    require(fragment)


forbid(
    "QSV_EXECUTE_CRYPTO=YES"
)


for fragment in [
    "CRYPTOGRAPHIC_EXECUTION_PERFORMED=NO",
    "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION_PERFORMED=NO",
    "RAW_RUNTIME_VECTOR_PAYLOAD_EMITTED=NO",
    "READY_FOR_EXPLICIT_GITHUB_ACTIONS_SIX_CASE_EXECUTION=YES",
]:
    require(fragment)


print(
    "QSV_MLDSA_CORRECTED_GITHUB_ACTIONS_PRECHECK_WORKFLOW_CANDIDATE_VERIFICATION=PASS"
)

print(
    "WORKFLOW_VERSION=v0.2"
)

print(
    "TRIGGER=workflow_dispatch_only"
)

print(
    "TARGET_RUNNER=ubuntu-24.04"
)

print(
    "TARGET_ARCHITECTURE=x86_64"
)

print(
    "EXTERNAL_ACTION_USES_COUNT=0"
)

print(
    "RUNNER_TOOLCACHE_EXACT_PATCH_DEPENDENCY_PRESENT=NO"
)

print(
    "GO_VERSION_REQUIRED=1.26.5"
)

print(
    "GO_SOURCE=official_go_archive"
)

print(
    "GO_ARCHIVE_SHA256_VERIFICATION_REQUIRED=YES"
)

print(
    "GO_EXTRACTION_RUNNER_TEMP_ONLY=YES"
)

print(
    "PREVIOUS_FAILED_RUN_BOUND=YES"
)

print(
    "EXECUTION_GATE_NEGATIVE_TEST_COUNT_PLANNED=9"
)

print(
    "CRYPTO_ENABLE_PRESENT=NO"
)

print(
    "EXPECTED_CRYPTOGRAPHIC_EXECUTION=NO"
)

print(
    "VERIFIER_SIDECAR_SELF_INTEGRITY_CHECK=PASS"
)

print(
    "READY_MARKER_PRESENT=YES"
)
