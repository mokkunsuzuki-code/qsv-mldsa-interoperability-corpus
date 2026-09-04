#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

EXPECTED_FILES = {
    "LICENSE",
    "README.md",
    "VERSION",
    "contracts/qsv-mldsa-interoperability-corpus-v0.1.json",
    "schemas/qsv-mldsa-fixture-v0.1.schema.json",
    "templates/qsv-mldsa-fixture-template.json",
    "provenance/qsv-mldsa-provenance-v0.1.json",
    "plans/qsv-mldsa-fixture-plan-v0.1.json",
    "lineage/qsv-mldsa-implementation-lineage-v0.1.json",
    "runners/qsv-mldsa-runner-interface-v0.1.json",
    "manifest/qsv-mldsa-corpus-v0.1-manifest.json",
    "manifest/qsv-mldsa-corpus-v0.1-manifest.json.sha256",
    "verify_qsv_mldsa_corpus_v0_1.py",
    "verify_qsv_mldsa_corpus_v0_1.py.sha256",
}

checks = 0
failures = []


def check(name, condition):
    global checks
    checks += 1

    if not condition:
        failures.append(name)


def load(rel):
    return json.loads(
        (ROOT / rel).read_text(
            encoding="utf-8"
        )
    )


def sha256(rel):
    return hashlib.sha256(
        (ROOT / rel).read_bytes()
    ).hexdigest()


actual_files = set()

for path in ROOT.rglob("*"):
    if not path.is_file():
        continue

    rel = path.relative_to(ROOT)

    if rel.parts and rel.parts[0] == ".git":
        continue

    actual_files.add(
        rel.as_posix()
    )


check(
    "exact fileset",
    actual_files == EXPECTED_FILES,
)

check(
    "version",
    (ROOT / "VERSION").read_text(
        encoding="utf-8"
    ).strip() == "0.1",
)

check(
    "MIT license",
    "MIT License"
    in (ROOT / "LICENSE").read_text(
        encoding="utf-8"
    ),
)


contract = load(
    "contracts/qsv-mldsa-interoperability-corpus-v0.1.json"
)

check(
    "contract schema",
    contract["schema"]
    == "qsv.mldsa-interoperability-corpus.contract.v0.1",
)

check(
    "contract version",
    contract["version"] == "0.1",
)

check(
    "design pending status",
    contract["status"]
    == "design_ready_execution_pending",
)

check(
    "QSV role",
    contract["role"]
    == "qsv_v1_implementation_artifact",
)

norm = contract[
    "normative_reference"
]

check(
    "QSV tag",
    norm["version_tag"] == "v1.0",
)

check(
    "QSV tag object",
    norm["tag_object_sha"]
    == "c73f2e5696d2b453fde2decf2cc012e1cbf645be",
)

check(
    "QSV commit",
    norm["target_commit"]
    == "a900f9c19aae2b165472290dbd4ccc83137433f9",
)

check(
    "QSV tree",
    norm["target_tree"]
    == "8c900bd600cb44dcc9ea2195075424a1bc7fb1f1",
)

check(
    "QSV model hash",
    norm["reference_model_sha256"]
    == "3b89f760aec367060e6f3c801b63b9bc92d468c00cbb958645ef0b12b766df3a",
)

hist = contract[
    "historical_design_input"
]

check(
    "Stage393 role",
    hist["role"]
    == "historical_design_provenance_not_normative_runtime_dependency",
)

check(
    "Stage393 commit",
    hist["commit"]
    == "61809515b6db87123ea60b404d6db4e6751bcac2",
)

check(
    "Stage393 tree",
    hist["tree"]
    == "1ddb9e5d54b4de5e91a3e1b75c635b82213c0d17",
)

check(
    "Stage393 concrete example hash",
    hist["concrete_example_sha256"]
    == "ae3d1a8c2a6dd593ea0dc8765280fdde36f018fb58cf76126081f351d929e899",
)

check(
    "Stage393 not runtime dependency",
    contract["stage393_required_at_runtime"]
    is False,
)

check(
    "independent runnable required",
    contract[
        "completed_release_must_be_independently_runnable"
    ] is True,
)

check(
    "algorithm",
    contract["algorithm"] == "ML-DSA",
)

check(
    "parameter sets",
    contract["parameter_sets"]
    == [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ],
)

check(
    "four evidence dimensions",
    contract["evidence_dimensions"]
    == [
        "known_answer_conformance",
        "cross_implementation_interoperability",
        "negative_behavior",
        "reproduction_integrity",
    ],
)

check(
    "initial implementations",
    contract["initial_implementations"]
    == [
        "OpenSSL",
        "Cloudflare CIRCL",
    ],
)

boundaries = contract[
    "truth_boundaries"
]

for key in [
    "agreement_implies_correctness",
    "timestamp_implies_cryptographic_correctness",
    "unknown_or_pending_implies_verified",
    "randomized_signature_requires_byte_equality",
    "wrapper_diversity_implies_implementation_independence",
]:
    check(
        "false truth boundary: " + key,
        boundaries[key] is False,
    )


execution = contract[
    "execution_state"
]

for key in [
    "cryptographic_fixture_generation_performed",
    "cryptographic_fixture_execution_performed",
    "fixture_results_published",
]:
    check(
        "pre-execution false: " + key,
        execution[key] is False,
    )


publication = contract[
    "publication_boundary"
]

check(
    "production private keys forbidden",
    publication[
        "production_private_keys_allowed"
    ] is False,
)

check(
    "test secret publication not authorized",
    publication[
        "public_test_secret_material_authorized"
    ] is False,
)


schema = load(
    "schemas/qsv-mldsa-fixture-v0.1.schema.json"
)

check(
    "fixture schema id",
    schema["$id"]
    == "urn:qsv:mldsa:fixture:0.1",
)

required = set(
    schema["required"]
)

for name in [
    "fixture_id",
    "dimension",
    "parameter_set",
    "operation",
    "producer",
    "consumer",
    "message",
    "context",
    "randomness_mode",
    "expected_outcome",
    "artifacts",
    "provenance",
    "publication_classification",
]:
    check(
        "fixture required field: " + name,
        name in required,
    )


template = load(
    "templates/qsv-mldsa-fixture-template.json"
)

check(
    "template schema",
    template["schema"]
    == "qsv.mldsa.fixture.v0.1",
)

check(
    "template unassigned",
    template["fixture_id"]
    == "UNASSIGNED",
)

check(
    "template pending",
    template["execution_state"]
    == "pending",
)

check(
    "template publication blocked",
    template["publication_classification"]
    == "not_authorized_for_publication",
)

check(
    "template no private test key",
    template["artifacts"][
        "private_test_key"
    ] is None,
)

check(
    "template no signature",
    template["artifacts"][
        "signature"
    ] is None,
)


provenance = load(
    "provenance/qsv-mldsa-provenance-v0.1.json"
)

design_env = provenance[
    "design_environment"
]

check(
    "Darwin design OS",
    design_env["operating_system"]
    == "Darwin",
)

check(
    "arm64 design architecture",
    design_env["architecture"]
    == "arm64",
)

check(
    "OpenSSL 3.6.3 observed",
    design_env["openssl"]["version"].startswith(
        "OpenSSL 3.6.3 "
    ),
)

check(
    "Go 1.26.5 observed",
    design_env["go"]["version"]
    == "go version go1.26.5 darwin/arm64",
)

asset_policy = provenance[
    "asset_reuse_policy"
]

check(
    "new hash required on reuse",
    asset_policy[
        "copying_existing_logic_requires_new_hash_binding"
    ] is True,
)

check(
    "historical Stage393 immutable",
    asset_policy[
        "historical_stage393_result_must_not_be_rewritten"
    ] is True,
)

check(
    "new corpus emits new evidence",
    asset_policy[
        "new_corpus_execution_must_emit_new_evidence"
    ] is True,
)

check(
    "Stage393 not runtime dependency provenance",
    asset_policy[
        "stage393_is_not_a_runtime_dependency"
    ] is True,
)


plan = load(
    "plans/qsv-mldsa-fixture-plan-v0.1.json"
)

check(
    "plan not executed",
    plan["status"]
    == "planned_not_executed",
)

check(
    "authoritative KAT source required",
    plan[
        "known_answer_conformance"
    ][
        "authoritative_source_required"
    ] is True,
)

check(
    "vector revision pinned",
    plan[
        "known_answer_conformance"
    ][
        "source_identity_and_revision_must_be_pinned"
    ] is True,
)

check(
    "KAT operations exact",
    plan[
        "known_answer_conformance"
    ][
        "operations"
    ]
    == [
        "key_generation",
        "sign",
        "verify",
    ],
)

check(
    "signing modes exact",
    plan[
        "known_answer_conformance"
    ][
        "signing_modes_where_supported"
    ]
    == [
        "deterministic",
        "hedged_or_randomized",
    ],
)

interop = plan[
    "cross_implementation_interoperability"
]

check(
    "bidirectional interop",
    interop["directions"]
    == [
        "OpenSSL_generate_or_sign__CIRCL_verify",
        "CIRCL_generate_or_sign__OpenSSL_verify",
    ],
)

check(
    "all parameter sets interop",
    interop[
        "all_parameter_sets_required"
    ] is True,
)

check(
    "no randomized byte equality",
    interop[
        "randomized_signatures_compared_by_byte_equality"
    ] is False,
)

check(
    "cross verification required",
    interop[
        "successful_cross_verification_required"
    ] is True,
)

check(
    "context cases",
    plan["context_cases"]
    == [
        "empty",
        "maximum_permitted_where_supported",
        "mismatched",
    ],
)

negative_targets = set(
    plan[
        "negative_behavior"
    ][
        "targets"
    ]
)

for target in [
    "public_key",
    "message",
    "context",
    "signature_hint",
    "challenge",
    "length_fields",
    "truncated_encoding",
    "extended_encoding",
    "non_canonical_values",
]:
    check(
        "negative target: " + target,
        target in negative_targets,
    )

check(
    "negative expected reject",
    plan[
        "negative_behavior"
    ][
        "expected_behavior"
    ] == "reject",
)

repro = plan[
    "reproduction_integrity"
]

for field in [
    "source_commit",
    "compiler_or_toolchain",
    "build_flags",
    "cpu_architecture",
    "dependencies",
    "test_vector_revision",
    "container_or_base_image_digest_when_used",
]:
    check(
        "reproduction field: " + field,
        field
        in repro[
            "required_environment_fields"
        ],
    )

check(
    "exact command required",
    repro[
        "exact_command_required"
    ] is True,
)

check(
    "exit status required",
    repro[
        "exit_status_required"
    ] is True,
)

check(
    "artifact hashes required",
    repro[
        "artifact_hashes_required"
    ] is True,
)

for key, value in plan[
    "fixture_material_state"
].items():
    check(
        "fixture material not generated: "
        + key,
        value is False,
    )


lineage = load(
    "lineage/qsv-mldsa-implementation-lineage-v0.1.json"
)

implementations = lineage[
    "implementations"
]

check(
    "two lineage records",
    len(implementations) == 2,
)

ids = [
    entry[
        "implementation_id"
    ]
    for entry in implementations
]

check(
    "OpenSSL lineage record",
    "openssl" in ids,
)

check(
    "CIRCL lineage record",
    "cloudflare-circl" in ids,
)

for entry in implementations:
    check(
        "source commit pending before execution: "
        + entry[
            "implementation_id"
        ],
        entry[
            "implementation_source_commit"
        ]
        == "must_be_pinned_before_fixture_execution",
    )

    check(
        "wrapper not independence proof: "
        + entry[
            "implementation_id"
        ],
        entry[
            "wrapper_identity_is_not_independence_proof"
        ] is True,
    )

check(
    "independence not yet verified",
    lineage[
        "independence_claim"
    ][
        "two_independent_implementations_verified"
    ] is False,
)

check(
    "shared code disclosure",
    lineage[
        "same_underlying_code_must_be_disclosed"
    ] is True,
)


runner = load(
    "runners/qsv-mldsa-runner-interface-v0.1.json"
)

check(
    "runner interface pending",
    runner["status"]
    == "interface_defined_implementation_pending",
)

required_output = set(
    runner[
        "output"
    ][
        "required_fields"
    ]
)

for field in [
    "fixture_id",
    "implementation",
    "operation",
    "result_state",
    "observed_acceptance",
    "exact_command",
    "inputs",
    "output",
    "exit_status",
    "artifact_hashes",
    "environment",
]:
    check(
        "runner output field: " + field,
        field in required_output,
    )

for key in [
    "unknown_result_is_success",
    "unsupported_is_verified",
    "execution_error_is_verified",
    "missing_hash_is_verified",
    "missing_lineage_is_verified",
]:
    check(
        "runner fail closed: " + key,
        runner[
            "fail_closed"
        ][key]
        is False,
    )


manifest = load(
    "manifest/qsv-mldsa-corpus-v0.1-manifest.json"
)

check(
    "manifest version",
    manifest["version"] == "0.1",
)

check(
    "manifest artifact count",
    manifest["artifact_count"] == 10,
)

check(
    "manifest execution false",
    manifest[
        "cryptographic_fixture_execution_performed"
    ] is False,
)

check(
    "manifest test secret false",
    manifest[
        "test_secret_material_published"
    ] is False,
)

manifest_entries = {
    entry["path"]: entry["sha256"]
    for entry in manifest["artifacts"]
}

check(
    "manifest has ten unique entries",
    len(manifest_entries) == 10,
)

for rel, digest in manifest_entries.items():
    check(
        "manifest file exists: " + rel,
        (ROOT / rel).is_file(),
    )

    if (ROOT / rel).is_file():
        check(
            "manifest hash: " + rel,
            sha256(rel) == digest,
        )


manifest_sidecar = (
    ROOT
    / "manifest/qsv-mldsa-corpus-v0.1-manifest.json.sha256"
)

declared_manifest_sha = (
    manifest_sidecar.read_text(
        encoding="utf-8"
    )
    .split()[0]
)

check(
    "manifest sidecar hash",
    declared_manifest_sha
    == sha256(
        "manifest/qsv-mldsa-corpus-v0.1-manifest.json"
    ),
)


self_sidecar = (
    ROOT
    / "verify_qsv_mldsa_corpus_v0_1.py.sha256"
)

check(
    "verifier sidecar exists",
    self_sidecar.is_file(),
)

if self_sidecar.is_file():
    declared_self_sha = (
        self_sidecar.read_text(
            encoding="utf-8"
        )
        .split()[0]
    )

    check(
        "verifier self hash",
        declared_self_sha
        == sha256(
            "verify_qsv_mldsa_corpus_v0_1.py"
        ),
    )
else:
    check(
        "verifier self hash",
        False,
    )


readme = (
    ROOT
    / "README.md"
).read_text(
    encoding="utf-8"
)

for phrase in [
    "Agreement ≠ Correctness",
    "Timestamp ≠ Cryptographic Correctness",
    "Unknown / Pending ≠ Verified",
    "Randomized Signature ≠ Byte Equality",
    "Wrapper Diversity ≠ Implementation Independence",
    "Stage393 is **not** a normative runtime dependency",
    "No production private keys are permitted",
]:
    check(
        "README boundary: " + phrase,
        phrase in readme,
    )


forbidden_extensions = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".ots",
    ".tsr",
    ".tsq",
}

for rel in actual_files:
    check(
        "no forbidden extension: " + rel,
        Path(rel).suffix
        not in forbidden_extensions,
    )


for path in ROOT.rglob("*"):
    if not path.is_file():
        continue

    if ".git" in path.parts:
        continue

    try:
        text = path.read_text(
            encoding="utf-8"
        )
    except UnicodeDecodeError:
        continue

    private_key_pem_markers = [
        "-----BEGIN " + "PRIVATE KEY-----",
        "-----BEGIN " + "RSA PRIVATE KEY-----",
        "-----BEGIN " + "EC PRIVATE KEY-----",
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
        "-----BEGIN " + "DSA PRIVATE KEY-----",
        "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
    ]

    check(
        "no private key PEM marker: "
        + path.relative_to(ROOT).as_posix(),
        all(
            marker not in text
            for marker in private_key_pem_markers
        ),
    )



# Pre-publication hardening derived from the coordinated
# 48-case fail-closed mutation audit.

check(
    "contract exact command claim requirement",
    "exact_command"
    in contract["claim_record_required_fields"],
)

check(
    "contract artifact hashes claim requirement",
    "artifact_hashes"
    in contract["claim_record_required_fields"],
)

check(
    "contract tool result states exact",
    contract["tool_level_result_states"]
    == [
        "pass",
        "expected_reject",
        "unexpected_accept",
        "unexpected_reject",
        "unsupported",
        "error",
        "blocked",
    ],
)

check(
    "formal certification nonclaim retained",
    "formal_certification"
    in contract["non_claims"],
)

check(
    "system wide quantum safety nonclaim retained",
    "system_wide_quantum_safety"
    in contract["non_claims"],
)

check(
    "fixture schema additional properties forbidden",
    schema["additionalProperties"]
    is False,
)

check(
    "fixture schema parameter sets exact",
    schema["properties"]["parameter_set"]["enum"]
    == [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ],
)

check(
    "fixture schema expected outcomes exact",
    schema["properties"]["expected_outcome"]["enum"]
    == [
        "accept",
        "reject",
    ],
)

check(
    "fixture schema publication classifications exact",
    schema["properties"][
        "publication_classification"
    ]["enum"]
    == [
        "public_non_secret",
        "public_test_only_material",
        "not_authorized_for_publication",
    ],
)

check(
    "provenance QSV target commit exact",
    provenance["normative_reference"]["target_commit"]
    == "a900f9c19aae2b165472290dbd4ccc83137433f9",
)

check(
    "provenance Stage393 commit exact",
    provenance["historical_design_input"]["commit"]
    == "61809515b6db87123ea60b404d6db4e6751bcac2",
)

check(
    "provenance Stage393 reusable asset hashes exact",
    provenance["stage393_reusable_source_assets"]
    == {
        "generate_stage393_circl_external_mu_overlay.py":
            "cb57f79ab1059cda2fcf4471eee9f8b3cd88c31f384680ad7c21d9bffb6ed169",
        "run_stage393_deterministic_fixedrnd.py":
            "b4b9fcbb66ae00b3564031bb2ade88c3cb7b686bbc702abe8f2422513d94d23b",
        "run_stage393_full_dual_implementation.py":
            "1b9baf39bd35a91ad86b165507a2f6b4a5789a56bb272cdc0cca8f953ece536e",
        "stage393_circl_full_harness.go":
            "60eb0cf69888ffe8244a90affc3400717d67c0fc49c182291d53902026955e80",
        "stage393_circl_fixedrnd_harness_test.go":
            "4becc8d265d0eb11d70f2cdb52b1f4c84e70f80bc71c1c4d6fe90894f1b0f734",
        "stage393_openssl_full_harness.py":
            "a1e694858be45521290c00043386dafae4ecd00434e406746ee4fc18e494fa14",
        "stage393_openssl_full_probe.c":
            "1b4ccc7aade8a75ba4e286967f1bc6045edc9eb6d94a9402961298869fce4a58",
    },
)

check(
    "fixture plan parameter sets exact",
    plan["parameter_sets"]
    == [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ],
)

check(
    "implementation native lineage exact",
    {
        entry["implementation_id"]:
            entry["underlying_native_implementation"]
        for entry in lineage["implementations"]
    }
    == {
        "openssl": "OpenSSL",
        "cloudflare-circl": "Cloudflare CIRCL",
    },
)

check(
    "runner result states exact",
    runner["result_states"]
    == [
        "pass",
        "expected_reject",
        "unexpected_accept",
        "unexpected_reject",
        "unsupported",
        "error",
        "blocked",
    ],
)

check(
    "runner exit code zero semantics exact",
    runner["exit_codes"]["0"]
    == "execution_completed_result_recorded",
)

check(
    "runner fixture schema exact",
    runner["input"]["fixture_schema"]
    == "urn:qsv:mldsa:fixture:0.1",
)

check(
    "manifest schema exact",
    manifest["schema"]
    == "qsv.mldsa-interoperability-corpus.manifest.v0.1",
)

check(
    "manifest artifact path set exact",
    set(
        entry["path"]
        for entry in manifest["artifacts"]
    )
    == {
        "LICENSE",
        "README.md",
        "VERSION",
        "contracts/qsv-mldsa-interoperability-corpus-v0.1.json",
        "schemas/qsv-mldsa-fixture-v0.1.schema.json",
        "templates/qsv-mldsa-fixture-template.json",
        "provenance/qsv-mldsa-provenance-v0.1.json",
        "plans/qsv-mldsa-fixture-plan-v0.1.json",
        "lineage/qsv-mldsa-implementation-lineage-v0.1.json",
        "runners/qsv-mldsa-runner-interface-v0.1.json",
    },
)

check(
    "README does not claim formal certification",
    "formal certification claimed: yes"
    not in readme.lower(),
)


print(
    "qsv_mldsa_corpus_check_count="
    + str(checks)
)

print(
    "qsv_mldsa_corpus_pass_count="
    + str(
        checks - len(failures)
    )
)

print(
    "qsv_mldsa_corpus_failure_count="
    + str(len(failures))
)

if failures:
    for name in failures:
        print(
            "FAIL: " + name
        )

    raise SystemExit(1)

print(
    "QSV_MLDSA_INTEROPERABILITY_CORPUS_V0_1_VERIFICATION=PASS"
)
