#!/usr/bin/env python3

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(
    sys.argv[1]
    if len(sys.argv) > 1
    else "."
).resolve()


WORKFLOW_REL = (
    ".github/workflows/"
    "qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml"
)

WORKFLOW_SIDECAR_REL = (
    WORKFLOW_REL
    + ".sha256"
)

VERIFIER_REL = (
    "verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_3.py"
)

VERIFIER_SIDECAR_REL = (
    VERIFIER_REL
    + ".sha256"
)


EXPECTED_WORKFLOW_SHA = "f4197f42e2ed6a76c66b12d9f10c069b2d1ef5d7f3653d46a3b80858c858cdc0"


EXPECTED_FILES = {
    WORKFLOW_REL,
    WORKFLOW_SIDECAR_REL,
    VERIFIER_REL,
    VERIFIER_SIDECAR_REL,
}


V02_COMMIT = (
    "970bf929f32a25ca0648fb01f5378bdbfa8eba55"
)

V02_TREE = (
    "5aba74bf8f0efdaa351cf84c44097d0fa3602937"
)

V02_WORKFLOW_SHA = (
    "0351a06ab03e2ff27669f00e30e5e764"
    "7bcd54af20c6e905ba2e607233e035b9"
)

RUN1_ID = "34079303462"

RUN1_LOG_SHA = (
    "97a3a09aff3a9e42cf57e8776b6a62b9"
    "0e39c1ed4e695b9e4f39728f210e8d80"
)

GO_SHA = (
    "5c2c3b16caefa1d968a94c1daca04a7c"
    "a301a496d9b086e17ad77bb81393f053"
)


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


workflow_path = (
    ROOT
    / WORKFLOW_REL
)


workflow_sha = digest(
    WORKFLOW_REL
)


if workflow_sha != EXPECTED_WORKFLOW_SHA:
    fail(
        "workflow SHA256 mismatch"
    )


workflow_sidecar_expected = (
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
) != workflow_sidecar_expected:
    fail(
        "workflow sidecar mismatch"
    )


verifier_sha = digest(
    VERIFIER_REL
)


verifier_sidecar_expected = (
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
) != verifier_sidecar_expected:
    fail(
        "verifier sidecar mismatch"
    )


text = workflow_path.read_text(
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
    "Clean-Environment Precheck v0.3"
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
    "QSV_EXECUTE_CRYPTO=YES",
    "RUNNER_TOOL_CACHE",
]:
    forbid(fragment)


required_env_values = {
    "GO_VERSION_REQUIRED": "1.26.5",

    "GO_LINUX_AMD64_ARCHIVE":
        "go1.26.5.linux-amd64.tar.gz",

    "GO_LINUX_AMD64_URL":
        "https://go.dev/dl/go1.26.5.linux-amd64.tar.gz",

    "GO_LINUX_AMD64_SHA256":
        GO_SHA,

    "PREVIOUS_FAILED_PRECHECK_RUN_ID":
        RUN1_ID,

    "PREVIOUS_FAILED_PRECHECK_RUN_LOG_SHA256":
        RUN1_LOG_SHA,

    "PREVIOUS_V0_2_PUBLISHED_COMMIT":
        V02_COMMIT,

    "PREVIOUS_V0_2_PUBLISHED_TREE":
        V02_TREE,

    "PREVIOUS_V0_2_WORKFLOW_SHA256":
        V02_WORKFLOW_SHA,

    "PREVIOUS_V0_2_ENV_STRUCTURE_VALID":
        "NO",

    "PREVIOUS_V0_2_MISINDENTED_ADDED_ENV_KEY_COUNT":
        "5",

    "PREVIOUS_V0_2_PSYCH_SYNTAX_PARSE_RESULT":
        "REJECT",

    "V0_3_YAML_STRUCTURE_VALIDATION_REQUIRED":
        "YES",
}


#
# Exact indentation gate.
#
lines = text.splitlines()


for key in required_env_values:

    prefix = key + ":"

    matches = [
        line
        for line in lines
        if line.lstrip().startswith(prefix)
    ]

    if len(matches) != 1:
        fail(
            "env key occurrence mismatch: "
            + key
        )

    line = matches[0]

    indent = (
        len(line)
        - len(line.lstrip(" "))
    )

    if indent != 6:
        fail(
            "env key indentation mismatch: "
            + key
        )


#
# Actual YAML parser + parsed-object structural validation.
#
ruby = shutil.which(
    "ruby"
)


if ruby is None:
    fail(
        "ruby unavailable for Psych YAML validation"
    )


ruby_script = r'''
require "psych"
require "json"

data = Psych.load(
  File.read(ARGV[0])
)

raise "root" unless data.is_a?(Hash)

jobs = data.fetch("jobs")
raise "jobs" unless jobs.is_a?(Hash)

precheck = jobs.fetch("precheck")
raise "precheck" unless precheck.is_a?(Hash)

env = precheck.fetch("env")
raise "env" unless env.is_a?(Hash)

steps = precheck.fetch("steps")
raise "steps" unless steps.is_a?(Array)

out = {
  "env" => env.transform_values { |v| v.to_s },
  "step_names" => steps.map {
    |step|
    step.is_a?(Hash) ? step["name"].to_s : ""
  },
}

puts JSON.generate(out)
'''


proc = subprocess.run(
    [
        ruby,
        "-rpsych",
        "-rjson",
        "-e",
        ruby_script,
        str(workflow_path),
    ],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)


if proc.returncode != 0:
    print(proc.stdout)
    fail(
        "Psych YAML parse/object validation rejected"
    )


try:
    parsed = json.loads(
        proc.stdout.strip()
    )
except Exception:
    print(proc.stdout)
    fail(
        "Psych structural JSON output invalid"
    )


env = parsed.get(
    "env"
)


if not isinstance(
    env,
    dict,
):
    fail(
        "parsed env is not mapping"
    )


for key, expected in required_env_values.items():

    if env.get(key) != expected:
        fail(
            "parsed env binding mismatch: "
            + key
        )


step_names = parsed.get(
    "step_names"
)


if not isinstance(
    step_names,
    list,
):
    fail(
        "parsed steps are not sequence"
    )


if (
    "Validate corrected v0.3 environment binding"
    not in step_names
):
    fail(
        "runtime structure gate absent"
    )


#
# Authority and no-crypto semantics.
#
for fragment in [
    (
        "NIST_COMMIT: "
        "975de31eb83d87039ec88934fdc47d8c312b892d"
    ),

    (
        "CIRCL_COMMIT: "
        "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
    ),

    (
        "OPENSSL_COMMIT: "
        "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f"
    ),

    "EXTRACTOR_GATE_REJECTED_COUNT=3",

    "OPENSSL_GATE_REJECTED_COUNT=3",

    "CIRCL_GATE_REJECTED_COUNT=3",

    "ALL_EXECUTION_GATES_FAIL_CLOSED=PASS",

    "CRYPTOGRAPHIC_EXECUTION_PERFORMED=NO",

    "CRYPTOGRAPHIC_SIGNATURE_VERIFICATION_PERFORMED=NO",

    "RAW_RUNTIME_VECTOR_PAYLOAD_EMITTED=NO",

    "READY_FOR_EXPLICIT_GITHUB_ACTIONS_SIX_CASE_EXECUTION=YES",

    "V0_3_CORRECTED_ENV_BINDING_RUNTIME=PASS",

    "V0_3_PREVIOUS_V0_2_DEFECT_BINDING=PASS",
]:
    require(fragment)


print(
    "QSV_MLDSA_V0_3_GITHUB_ACTIONS_PRECHECK_WORKFLOW_CANDIDATE_VERIFICATION=PASS"
)

print(
    "WORKFLOW_VERSION=v0.3"
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
    "ACTUAL_YAML_PARSER=Ruby_Psych"
)

print(
    "YAML_PSYCH_SYNTAX_PARSE=PASS"
)

print(
    "YAML_PARSED_ROOT_MAPPING=PASS"
)

print(
    "YAML_PARSED_JOBS_MAPPING=PASS"
)

print(
    "YAML_PARSED_PRECHECK_ENV_MAPPING=PASS"
)

print(
    "YAML_PARSED_PRECHECK_STEPS_SEQUENCE=PASS"
)

print(
    "V0_3_REQUIRED_ENV_BINDING_COUNT="
    + str(len(required_env_values))
)

print(
    "V0_3_REQUIRED_ENV_BINDINGS=PASS"
)

print(
    "V0_3_REQUIRED_ENV_INDENTATION=6"
)

print(
    "V0_3_ENV_STRUCTURE_VALID=YES"
)

print(
    "PREVIOUS_V0_2_PUBLISHED_COMMIT="
    + V02_COMMIT
)

print(
    "PREVIOUS_V0_2_PUBLISHED_TREE="
    + V02_TREE
)

print(
    "PREVIOUS_V0_2_WORKFLOW_SHA256="
    + V02_WORKFLOW_SHA
)

print(
    "PREVIOUS_V0_2_ENV_STRUCTURE_VALID=NO"
)

print(
    "PREVIOUS_V0_2_MISINDENTED_ADDED_ENV_KEY_COUNT=5"
)

print(
    "PREVIOUS_V0_2_PSYCH_SYNTAX_PARSE_RESULT=REJECT"
)

print(
    "V0_2_DEFECT_LINEAGE_BOUND=YES"
)

print(
    "EXTERNAL_ACTION_USES_COUNT=0"
)

print(
    "RUNNER_TOOLCACHE_EXACT_PATCH_DEPENDENCY_PRESENT=NO"
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
    "V0_3_ACTUAL_YAML_STRUCTURE_VALIDATION=PASS"
)

print(
    "READY_MARKER_PRESENT=YES"
)
