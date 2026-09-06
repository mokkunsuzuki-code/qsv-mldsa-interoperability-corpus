#!/usr/bin/env python3

import hashlib
import re
import sys
from pathlib import Path


root = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()


workflow_rel = (
    ".github/workflows/"
    "qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml"
)

workflow_sidecar_rel = (
    workflow_rel
    + ".sha256"
)

verifier_rel = (
    "verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_1.py"
)

verifier_sidecar_rel = (
    verifier_rel
    + ".sha256"
)


EXPECTED_WORKFLOW_SHA256 = "3b488f00990c11a796faa7638d39b5aa12874c3e21c9459aa264c77d6315ea16"


workflow = root / workflow_rel
workflow_sidecar = root / workflow_sidecar_rel

verifier = root / verifier_rel
verifier_sidecar = root / verifier_sidecar_rel


actual_files = {
    str(path.relative_to(root))
    for path in root.rglob("*")
    if path.is_file()
}


assert actual_files == {
    workflow_rel,
    workflow_sidecar_rel,
    verifier_rel,
    verifier_sidecar_rel,
}


workflow_raw = workflow.read_bytes()

workflow_sha = hashlib.sha256(
    workflow_raw
).hexdigest()


assert workflow_sha == EXPECTED_WORKFLOW_SHA256


assert workflow_sidecar.read_text(
    encoding="utf-8"
) == (
    EXPECTED_WORKFLOW_SHA256
    + "  "
    + workflow_rel
    + "\n"
)


verifier_sha = hashlib.sha256(
    verifier.read_bytes()
).hexdigest()


assert verifier_sidecar.read_text(
    encoding="utf-8"
) == (
    verifier_sha
    + "  "
    + verifier_rel
    + "\n"
)


text = workflow_raw.decode("utf-8")


assert text.count(
    "runs-on: ubuntu-24.04"
) == 1

assert text.count(
    "workflow_dispatch:"
) == 1

assert "\n  push:" not in text
assert "\n  pull_request:" not in text
assert "\n  schedule:" not in text

assert (
    "permissions:\n"
    "  contents: read\n"
) in text

assert "contents: write" not in text
assert "id-token: write" not in text

assert "uses:" not in text

assert "git push" not in text
assert "gh " not in text

assert "upload-artifact" not in text
assert "download-artifact" not in text


required_exact_strings = [
    "DESIGN_CONTRACT_SHA256: 9f78c559fdcb564efe4320803ce55caa5fe26f379ec2627936fac3912aca2f71",

    "QSV_COMMIT: 717337adbbcc493ed3de328411b287328b9290dd",
    "QSV_TREE: 854ed1fdc516c49420474d42c0660b07368d2aca",

    "RUNTIME_AUTHORITY_COMMIT: fd892bd79478fb5250a4e4dfa53705dd58d8b173",
    "RUNTIME_AUTHORITY_TREE: 37e27a32534381fc43affdeae7bcf9050ee990a2",

    "NIST_COMMIT: 975de31eb83d87039ec88934fdc47d8c312b892d",
    "NIST_TREE: a6b81add7faf8a8b647afcdc54268615decde9b5",

    "NIST_PROMPT_SHA256: e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",

    "NIST_EXPECTED_RESULTS_SHA256: e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",

    "CIRCL_COMMIT: cfa7c70defd831ffb0792ab2af560bfef43d60ca",
    "CIRCL_TREE: b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",

    "OPENSSL_VERSION_REQUIRED: 3.6.3",

    "OPENSSL_COMMIT: aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",
    "OPENSSL_TREE: a8a306c000bc2426afd3264b2c41bc7223728475",

    "GO_VERSION_REQUIRED: 1.26.5",

    'GO_ROOT="${RUNNER_TOOL_CACHE}/go/${GO_VERSION_REQUIRED}/x64"',

    'test "${GO_VERSION}" = "go version go1.26.5 linux/amd64"',

    "go 1.25.0",

    "./Configure \\",
    "linux-x86_64 \\",
    "no-shared \\",

    "go build \\",
    "-mod=readonly \\",
    "-trimpath \\",

    "EXTRACTOR_GATE_REJECTED_COUNT=3",
    "OPENSSL_GATE_REJECTED_COUNT=3",
    "CIRCL_GATE_REJECTED_COUNT=3",

    "QSV_EXECUTE_CRYPTO_YES_SET_IN_PRECHECK=NO",

    "EXTRACTED_RUNTIME_VECTOR_PAYLOAD_EMITTED=NO",

    "OPENSSL_EVP_PKEY_VERIFY_EXECUTED=NO",
    "CIRCL_VERIFY_EXECUTED=NO",

    "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION_PERFORMED=NO",

    "ALL_EXECUTION_GATES_FAIL_CLOSED=PASS",

    "QSV_MLDSA_GITHUB_ACTIONS_CROSS_PLATFORM_PRECHECK=PASS",

    "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false",

    "GITHUB_RUNNER_IMMUTABLE_BUILD_ENVIRONMENT=false",

    "ABSOLUTE_OPENSSL_BUILD_PROVENANCE_COMPLETE_CLAIM_ALLOWED=false",

    "READY_FOR_EXPLICIT_GITHUB_ACTIONS_SIX_CASE_EXECUTION=YES",
]


for value in required_exact_strings:
    assert value in text, value


assert text.count(
    'test "${RC}" -eq 1'
) == 1

assert text.count(
    'test "${RC}" -eq 78'
) == 2


assert "QSV_EXECUTE_CRYPTO=YES" not in text

assert not re.search(
    r"QSV_EXECUTE_CRYPTO\s*:\s*YES",
    text,
)


assert text.count(
    "env QSV_EXECUTE_CRYPTO="
) == 3


assert text.count(
    "env -u QSV_EXECUTE_CRYPTO"
) == 3


assert text.count(
    "unset QSV_EXECUTE_CRYPTO"
) >= 7


assert "apt-get upgrade" not in text
assert "apt upgrade" not in text


assert text.count(
    "fetch \\\n"
) >= 4


assert text.count(
    "--depth=1 \\"
) >= 3


assert "--depth=2 \\" in text


assert "make -j2" in text
assert "make install_sw" in text


assert (
    'test "${RUNNER_OS}" = "Linux"'
) in text

assert (
    'test "${RUNNER_ARCH}" = "X64"'
) in text

assert (
    'test "$(uname -m)" = "x86_64"'
) in text


assert (
    "RUNNER_IMAGE_VERSION=${ImageVersion:-UNSET}"
) in text


assert (
    "OPENSSL_BUILT_BINARY_SHA256="
) in text

assert (
    "OPENSSL_BUILT_LIBCRYPTO_SHA256="
) in text

assert (
    "OPENSSL_HARNESS_BINARY_SHA256="
) in text

assert (
    "CIRCL_HARNESS_BINARY_SHA256="
) in text


print(
    "QSV_MLDSA_GITHUB_ACTIONS_PRECHECK_WORKFLOW_CANDIDATE_VERIFICATION=PASS"
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
    "OPENSSL_EXACT_SOURCE_BUILD_REQUIRED=YES"
)

print(
    "CIRCL_EXACT_SOURCE_BUILD_REQUIRED=YES"
)

print(
    "GO_VERSION_REQUIRED=1.26.5"
)

print(
    "CRYPTO_ENABLE_PRESENT=NO"
)

print(
    "EXPECTED_CRYPTOGRAPHIC_EXECUTION=NO"
)

print(
    "READY_MARKER_PRESENT=YES"
)
