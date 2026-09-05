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
    "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json",
    "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json.sha256",
    "verify_qsv_mldsa_source_lineage_v0_1.py",
    "verify_qsv_mldsa_source_lineage_v0_1.py.sha256",
    "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json",
    "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json.sha256",
    "verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py",
    "verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py.sha256",
    "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json",
    "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json.sha256",
    "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py",
    "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py.sha256",
    "runtime/qsv_mldsa_sixcase_extractor_v0_1.py",
    "runtime/qsv_mldsa_sixcase_extractor_v0_1.py.sha256",
    "runtime/qsv_mldsa_sixcase_metadata_v0_1.json",
    "runtime/qsv_mldsa_sixcase_metadata_v0_1.json.sha256",
    "runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c",
    "runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c.sha256",
    "runtime/qsv_mldsa_circl_sigver_harness_v0_1.go",
    "runtime/qsv_mldsa_circl_sigver_harness_v0_1.go.sha256",
    "runtime/qsv_mldsa_runtime_harness_contract_v0_1.json",
    "runtime/qsv_mldsa_runtime_harness_contract_v0_1.json.sha256",
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



source_binding = load(
    "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json"
)

check(
    "source binding schema",
    source_binding["schema"]
    == "qsv.mldsa.implementation-source-lineage-binding.v0.1",
)

check(
    "source binding version",
    source_binding["version"] == "0.1",
)

check(
    "source binding status",
    source_binding["status"]
    == "source_lineage_bound_fixture_execution_pending",
)

check(
    "source binding role",
    source_binding["role"]
    == "append_only_implementation_source_lineage_evidence",
)

source_base = source_binding[
    "base_corpus_authority"
]

check(
    "source binding base repository",
    source_base["repository"]
    == "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
)

check(
    "source binding base commit",
    source_base["commit"]
    == "5c43415a2570ec0e1e3e8211b589f7a9916108a1",
)

check(
    "source binding base tree",
    source_base["tree"]
    == "67fd0ecdf14f49523dd94f95fbfee908b39312a3",
)

source_norm = source_binding[
    "normative_reference"
]

check(
    "source binding QSV repository",
    source_norm["repository"]
    == "mokkunsuzuki-code/qsv-reference-model",
)

check(
    "source binding QSV tag",
    source_norm["tag"] == "v1.0",
)

check(
    "source binding QSV target",
    source_norm["target_commit"]
    == "a900f9c19aae2b165472290dbd4ccc83137433f9",
)

source_hist = source_binding[
    "historical_evidence_source"
]

check(
    "source binding Stage393 repository",
    source_hist["repository"]
    == "mokkunsuzuki-code/stage393",
)

check(
    "source binding Stage393 commit",
    source_hist["commit"]
    == "61809515b6db87123ea60b404d6db4e6751bcac2",
)

check(
    "source binding Stage393 tree",
    source_hist["tree"]
    == "1ddb9e5d54b4de5e91a3e1b75c635b82213c0d17",
)

source_openssl = source_binding[
    "implementations"
][
    "openssl"
]

check(
    "source OpenSSL id",
    source_openssl["implementation_id"]
    == "openssl",
)

check(
    "source OpenSSL runtime version",
    source_openssl["observed_runtime"]["version"]
    == "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)",
)

check(
    "source OpenSSL binary",
    source_openssl["observed_runtime"]["binary"]
    == "/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl",
)

check(
    "source OpenSSL binary hash",
    source_openssl["observed_runtime"]["binary_sha256"]
    == "5d8f84484b7317ec5639ce68ccecc1d6f565ca6df483c8ae731e25265d83466d",
)

source_openssl_upstream = source_openssl[
    "upstream_release"
]

check(
    "source OpenSSL upstream repository",
    source_openssl_upstream["repository"]
    == "https://github.com/openssl/openssl.git",
)

check(
    "source OpenSSL release tag",
    source_openssl_upstream["tag"]
    == "openssl-3.6.3",
)

check(
    "source OpenSSL tag object",
    source_openssl_upstream["tag_object"]
    == "e5c234b0c471a676ae6141d2f157df61eb293477",
)

check(
    "source OpenSSL commit",
    source_openssl_upstream["source_commit"]
    == "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",
)

check(
    "source OpenSSL tree",
    source_openssl_upstream["source_tree"]
    == "a8a306c000bc2426afd3264b2c41bc7223728475",
)

check(
    "source OpenSSL VERSION.dat hash",
    source_openssl_upstream["version_dat_sha256"]
    == "13996b257fa122047907c75bb6605cf9b18859099e555d8091dfc95df6344470",
)

check(
    "source OpenSSL VERSION.dat blob",
    source_openssl_upstream["version_dat_git_blob"]
    == "1926982f6388b752f19dde368a04b4b09e6a66a6",
)

source_brew = source_openssl[
    "homebrew_observation"
]

check(
    "source Homebrew formula",
    source_brew["formula"]
    == "openssl@3",
)

check(
    "source Homebrew stable observed",
    source_brew["stable_version_observed"]
    == "3.6.4",
)

check(
    "source Homebrew installed observed",
    source_brew["installed_version_observed"]
    == "3.6.3",
)

check(
    "source Homebrew metadata hash",
    source_brew["metadata_sha256"]
    == "312f2abccd4297078aa7c4f11d2906a5f8e2b820c39b4c78ecf47d5857bdf1fd",
)

source_build = source_openssl[
    "build_provenance"
]

check(
    "source OpenSSL commit not proven for binary",
    source_build["local_binary_source_commit_proven"]
    is False,
)

check(
    "source OpenSSL build provenance incomplete",
    source_build["complete"]
    is False,
)

check(
    "source OpenSSL provenance status",
    source_build["status"]
    == "incomplete",
)

check(
    "source OpenSSL provenance reason exact",
    source_build["reason"]
    == 'runtime_version_and_upstream_tag_are_verified_but_source_to_local_binary_build_chain_is_not_yet_cryptographically_established',
)

check(
    "source implementation set exact",
    set(
        source_binding["implementations"].keys()
    )
    == {
        "openssl",
        "cloudflare_circl",
    },
)

source_circl = source_binding[
    "implementations"
][
    "cloudflare_circl"
]

check(
    "source CIRCL id",
    source_circl["implementation_id"]
    == "cloudflare-circl",
)

check(
    "source CIRCL repository",
    source_circl["repository"]
    == "https://github.com/cloudflare/circl.git",
)

check(
    "source CIRCL commit",
    source_circl["source_commit"]
    == "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
)

check(
    "source CIRCL tree",
    source_circl["source_tree"]
    == "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",
)

check(
    "source CIRCL go.mod hash",
    source_circl["go_mod_sha256"]
    == "79b9daccc7f033377bcbc70524418d999a1677849924d7b5e488e646c4cf00d7",
)

check(
    "source CIRCL go.sum hash",
    source_circl["go_sum_sha256"]
    == "3d75d69d3b553e9aa69e1278de681b8dc55c28c6e4233bb398c5b7373c3abd0a",
)

check(
    "source CIRCL go.mod blob",
    source_circl["go_mod_git_blob"]
    == "f4ab94067d62a67bb50733fab6e41eab38434146",
)

check(
    "source CIRCL go.sum blob",
    source_circl["go_sum_git_blob"]
    == "c6d3ed6c6bc51c566570ee9c19b4187f094fca49",
)

check(
    "source CIRCL upstream commit match",
    source_circl["upstream_commit_match"]
    is True,
)

check(
    "source CIRCL upstream tree match",
    source_circl["upstream_tree_match"]
    is True,
)

check(
    "source CIRCL fixture execution pending",
    source_circl[
        "fixture_execution_from_pinned_source_performed"
    ] is False,
)

source_truth = source_binding[
    "truth_boundaries"
]

check(
    "source agreement not correctness",
    source_truth["agreement_implies_correctness"]
    is False,
)

check(
    "source hash not build provenance",
    source_truth["hash_alone_implies_build_provenance"]
    is False,
)

check(
    "source version not build provenance",
    source_truth["version_string_implies_build_provenance"]
    is False,
)

source_execution = source_binding[
    "execution_state"
]

check(
    "source fixture generation pending",
    source_execution[
        "cryptographic_fixture_generation_performed"
    ] is False,
)

check(
    "source fixture execution pending",
    source_execution[
        "cryptographic_fixture_execution_performed"
    ] is False,
)

check(
    "source results unpublished",
    source_execution[
        "fixture_results_published"
    ] is False,
)

check(
    "source implementation independence unverified",
    source_execution[
        "two_independent_implementations_verified"
    ] is False,
)

source_binding_sidecar = (
    ROOT
    / "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json.sha256"
)

check(
    "source binding sidecar hash",
    source_binding_sidecar.read_text(
        encoding="utf-8"
    ).split()[0]
    == sha256(
        "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json"
    ),
)

source_verifier_sidecar = (
    ROOT
    / "verify_qsv_mldsa_source_lineage_v0_1.py.sha256"
)

check(
    "source binding verifier sidecar hash",
    source_verifier_sidecar.read_text(
        encoding="utf-8"
    ).split()[0]
    == sha256(
        "verify_qsv_mldsa_source_lineage_v0_1.py"
    ),
)



nist_vector_binding = load(
    "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

check(
    "NIST vector binding identity exact",
    (
        nist_vector_binding["schema"]
        == "qsv.mldsa.nist-acvp-vector-source-binding.v0.1"
        and nist_vector_binding["version"] == "0.1"
        and nist_vector_binding["status"]
        == "authoritative_vector_source_bound_execution_pending"
        and nist_vector_binding["role"]
        == "append_only_known_answer_vector_source_authority"
    ),
)

check(
    "NIST vector base corpus authority exact",
    nist_vector_binding["base_corpus_authority"]
    == {
        "repository":
            "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
        "commit":
            "27967c03620f099793a1edb3aa1c07487487c736",
        "tree":
            "a9bd9e3dff66a2267cf66ed26ace8be0ed8c1078",
    },
)

nist_source = nist_vector_binding["source_authority"]

check(
    "NIST selected source revision exact",
    (
        nist_source["organization"] == "NIST"
        and nist_source["repository"]
        == "https://github.com/usnistgov/ACVP-Server.git"
        and nist_source["selected_tag"] == "v1.1.0.43"
        and nist_source["selected_commit"]
        == "975de31eb83d87039ec88934fdc47d8c312b892d"
        and nist_source["selected_tree"]
        == "a6b81add7faf8a8b647afcdc54268615decde9b5"
        and nist_source["prior_tag"] == "v1.1.0.42"
        and nist_source["prior_commit"]
        == "15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0"
        and nist_source["prior_tree"]
        == "757c230c95b7b90c9f0f0def5ea5b813347bf8f2"
    ),
)

check(
    "NIST release observation exact",
    (
        nist_source["master_equal_selected_at_discovery"] is True
        and nist_source["selected_release_metadata_sha256"]
        == "89db9445342a74034e463257e6023fd81921751927ea99d5bb03c18f06fa23a9"
        and nist_source["prior_release_metadata_sha256"]
        == "4e7d0b005c5dc67362182721496fe8199a8b846609481235bdcfaff0d15a3e3d"
        and nist_source["selected_github_release_immutable"] is False
        and nist_source["selected_release_published_at"]
        == "2026-08-12T19:32:51Z"
        and nist_source["selected_release_updated_at"]
        == "2026-08-20T17:48:32Z"
    ),
)

nist_surface = nist_vector_binding[
    "selected_vector_surface"
]

check(
    "NIST vector counts exact",
    (
        nist_surface["base_fips204_file_count"] == 15
        and nist_surface["fips204_tr1_siggen_file_count"] == 5
        and nist_surface["total_file_count"] == 20
        and nist_surface["prior_revision_tr1_siggen_file_count"] == 0
        and nist_surface["selected_revision_tr1_siggen_file_count"] == 5
    ),
)

check(
    "NIST parameter sets exact",
    nist_surface["parameter_sets"]
    == [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ],
)

check(
    "NIST discovery binding set digest exact",
    nist_surface["discovery_binding_set_sha256"]
    == "5ecee116974b667aada74e91823d987174f500605a13f13b70db379844c9b2df",
)

check(
    "NIST exact vector record count",
    len(nist_surface["files"]) == 20,
)

check(
    "NIST exact vector path set",
    [item["path"] for item in nist_surface["files"]]
    == [
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json",
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json",
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/registration.json",
        "gen-val/json-files/ML-DSA-keyGen-FIPS204/validation.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/registration.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204/validation.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/registration.json",
        "gen-val/json-files/ML-DSA-sigVer-FIPS204/validation.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/expectedResults.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/internalProjection.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/prompt.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/registration.json",
        "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/validation.json",
    ],
)

import hashlib as _qsv_nist_hashlib
import json as _qsv_nist_json

nist_vector_record_metadata_canonical = (
    _qsv_nist_json.dumps(
        nist_surface["files"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
)

check(
    "NIST exact vector record metadata digest",
    _qsv_nist_hashlib.sha256(
        nist_vector_record_metadata_canonical
    ).hexdigest()
    == "ee30d4a27f64bfcbf3b01b0865cc964ad41ac1f4cde8afc0ee47cbd62b3f1dfe",
)


check(
    "NIST selection evidence exact",
    nist_vector_binding["selection_evidence"]
    == {
        "selected_release_declares_mldsa_fips204_tr1": True,
        "selected_release_declares_externalmu_fix": True,
        "selected_release_declares_modifyz_fix": True,
        "selected_release_declares_tr1_prod_enablement": True,
        "stable_to_selected_base15_changed_file_count": 9,
        "selected_to_master_base15_changed_file_count_at_discovery": 0,
    },
)

check(
    "NIST truth boundaries exact",
    nist_vector_binding["truth_boundaries"]
    == {
        "source_snapshot_implies_cryptographic_correctness": False,
        "vector_presence_implies_implementation_conformance": False,
        "nist_source_binding_implies_nist_validation_of_qsv": False,
        "selected_revision_implies_all_implementations_support_all_vector_semantics": False,
    },
)

check(
    "NIST vector execution state exact",
    nist_vector_binding["execution_state"]
    == {
        "nist_vector_payload_copied_to_corpus": False,
        "public_test_secret_material_copied_to_corpus": False,
        "public_test_secret_material_authorized": False,
        "cryptographic_fixture_generation_performed": False,
        "cryptographic_fixture_execution_performed": False,
        "fixture_results_published": False,
    },
)

nist_binding_sidecar = (
    ROOT
    / "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json.sha256"
)

check(
    "NIST vector binding sidecar hash",
    nist_binding_sidecar.read_text(
        encoding="utf-8"
    ).split()[0]
    == sha256(
        "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json"
    ),
)

nist_verifier_sidecar = (
    ROOT
    / "verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py.sha256"
)

check(
    "NIST vector verifier sidecar hash",
    nist_verifier_sidecar.read_text(
        encoding="utf-8"
    ).split()[0]
    == sha256(
        "verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py"
    ),
)



minimal_kat_profile = load(
    "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

check(
    "minimal KAT profile identity exact",
    (
        minimal_kat_profile["schema"]
        == "qsv.mldsa.nist-acvp-known-answer-execution-profile.v0.1"
        and minimal_kat_profile["version"] == "0.1"
        and minimal_kat_profile["status"]
        == "profile_candidate_defined_execution_not_performed"
        and minimal_kat_profile["role"]
        == "minimal_public_sigver_known_answer_execution_precondition"
    ),
)

check(
    "minimal KAT QSV source authority exact",
    minimal_kat_profile["qsv_source_authority"]
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
    "minimal KAT NIST source authority exact",
    minimal_kat_profile["nist_source_authority"]
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
    "minimal KAT source inputs exact",
    minimal_kat_profile["source_inputs"]
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
    "minimal KAT execution surface exact",
    minimal_kat_profile["execution_surface"]
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

check(
    "minimal KAT selected cases exact",
    minimal_kat_profile["selected_cases"]
    == [
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
    ],
)

check(
    "minimal KAT selected prompt fields exact",
    minimal_kat_profile["selected_prompt_field_names"]
    == {
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
    },
)

check(
    "minimal KAT material boundary exact",
    minimal_kat_profile["material_boundary"]
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
    "minimal KAT execution policy exact",
    minimal_kat_profile["execution_policy"]
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
    "minimal KAT excluded surface exact",
    minimal_kat_profile["excluded_from_v0_1"]
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
    "minimal KAT truth boundaries exact",
    minimal_kat_profile["truth_boundaries"]
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
    "minimal KAT execution state exact",
    minimal_kat_profile["execution_state"]
    == {
        "cryptographic_fixture_generation_performed":
            False,
        "cryptographic_fixture_execution_performed":
            False,
        "fixture_results_published":
            False,
    },
)

minimal_kat_profile_canonical = json.dumps(
    minimal_kat_profile,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")

check(
    "minimal KAT canonical digest exact",
    hashlib.sha256(
        minimal_kat_profile_canonical
    ).hexdigest()
    == "acb84ee1b8dafd1ed84273f4820349ab2e40f3f5c1bd2e0cd0f5e482b78a2646",
)

minimal_kat_profile_sidecar = (
    ROOT
    / "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json.sha256"
)

check(
    "minimal KAT profile sidecar exact declaration",
    minimal_kat_profile_sidecar.read_text(
        encoding="utf-8"
    )
    == (
        sha256(
            "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
        )
        + "  "
        + "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
        + "\n"
    ),
)

minimal_kat_verifier_sidecar = (
    ROOT
    / "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py.sha256"
)

check(
    "minimal KAT verifier sidecar exact declaration",
    minimal_kat_verifier_sidecar.read_text(
        encoding="utf-8"
    )
    == (
        sha256(
            "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py"
        )
        + "  "
        + "verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py"
        + "\n"
    ),
)



# Byte-frozen minimal KAT runtime execution authority.
#
# These artifacts define how the six pinned public sigVer
# cases may be extracted and passed to OpenSSL / CIRCL.
# They do not themselves prove that cryptographic execution
# has occurred.

runtime_artifact_hashes = {
    "runtime/qsv_mldsa_sixcase_extractor_v0_1.py":
        "0bdad8db61b008ce50e6c53a472d3e56d36cf8169318cb50474672d62e566679",

    "runtime/qsv_mldsa_sixcase_metadata_v0_1.json":
        "27104ea68cb2c47c10c0265ca8772b2c4af792ea7b2d5d34925511aefc2592d6",

    "runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c":
        "0d5c2030409425115680d3140429918210fbc63c5f18bb0c08257314bd6e6240",

    "runtime/qsv_mldsa_circl_sigver_harness_v0_1.go":
        "f3c551821f4c31b8f7fd7242e66002c4aa1cc3dd0abb0c56710f3d0a91fc0fed",

    "runtime/qsv_mldsa_runtime_harness_contract_v0_1.json":
        "6e3c5161c978ec4a045ad1c72ed491967ae66c1501d83aab660ffcde7cca307e",
}


for rel, digest in runtime_artifact_hashes.items():

    check(
        "runtime artifact hash: " + rel,
        (
            (ROOT / rel).is_file()
            and sha256(rel) == digest
        ),
    )

    sidecar_rel = rel + ".sha256"

    check(
        "runtime sidecar exact declaration: " + rel,
        (
            (ROOT / sidecar_rel).is_file()
            and (
                ROOT
                / sidecar_rel
            ).read_text(
                encoding="utf-8"
            )
            == (
                digest
                + "  "
                + rel
                + "\n"
            )
        ),
    )


runtime_contract = load(
    "runtime/qsv_mldsa_runtime_harness_contract_v0_1.json"
)


check(
    "runtime contract identity exact",
    (
        runtime_contract["schema"]
        == "qsv.mldsa.minimal-kat-runtime-harness-contract.v0.1"
        and runtime_contract["role"]
        == "static_runtime_execution_authority"
    ),
)


check(
    "runtime QSV profile authority exact",
    runtime_contract["qsv_profile_authority"]
    == {
        "commit":
            "81382cc1765a24dbf02e44ac691fd04fe8bbab22",
        "tree":
            "5d9e36fdabeba921152f070b909592d0db24c787",
    },
)


check(
    "runtime NIST vector authority exact",
    runtime_contract["nist_vector_authority"]
    == {
        "commit":
            "975de31eb83d87039ec88934fdc47d8c312b892d",
        "tree":
            "a6b81add7faf8a8b647afcdc54268615decde9b5",
        "prompt_sha256":
            "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
        "expected_results_sha256":
            "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
    },
)


check(
    "runtime CIRCL source authority exact",
    runtime_contract["circl_source_authority"]
    == {
        "commit":
            "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
        "tree":
            "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",
    },
)


check(
    "runtime OpenSSL requirement exact",
    runtime_contract["openssl_runtime_requirement"]
    == {
        "version":
            "3.6.3",
        "local_binary_source_commit_proven":
            False,
        "local_binary_build_provenance_complete":
            False,
    },
)


check(
    "runtime selected cases exact",
    runtime_contract["selected_cases"]
    == [
        {
            "parameter_set":
                "ML-DSA-44",
            "tg_id":
                1,
            "tc_id":
                1,
            "expected_valid":
                False,
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
        },
    ],
)


check(
    "runtime input surface exact",
    runtime_contract["runtime_input_surface"]
    == {
        "operation":
            "sigVer",
        "revision":
            "FIPS204",
        "signature_interface":
            "external",
        "pre_hash":
            "pure",
        "fields": [
            "pk",
            "message",
            "context",
            "signature",
        ],
        "context_max_bytes":
            255,
        "payload_storage_policy":
            "ephemeral_tmp_only",
    },
)


check(
    "runtime execution gate exact",
    runtime_contract["execution_gate"]
    == {
        "environment_variable":
            "QSV_EXECUTE_CRYPTO",
        "required_value":
            "YES",
        "extractor_payload_emission_requires_gate":
            True,
        "openssl_crypto_operation_requires_gate":
            True,
        "circl_crypto_operation_requires_gate":
            True,
    },
)


check(
    "runtime OpenSSL adapter exact",
    runtime_contract["openssl_adapter"]
    == {
        "public_key_import":
            "EVP_PKEY_fromdata(OSSL_PKEY_PARAM_PUB_KEY)",
        "verify_init":
            "EVP_PKEY_verify_message_init",
        "verify_operation":
            "EVP_PKEY_verify",
        "context_parameter":
            "OSSL_SIGNATURE_PARAM_CONTEXT_STRING",
        "return_1_semantics":
            "valid_signature",
        "return_0_semantics":
            "invalid_signature",
        "negative_return_semantics":
            "operational_error_fail_closed",
    },
)


check(
    "runtime CIRCL adapter exact",
    runtime_contract["circl_adapter"]
    == {
        "public_key_import":
            "PublicKey.UnmarshalBinary",
        "verification_api":
            "Verify(pk,msg,ctx,sig)",
    },
)


check(
    "runtime artifact hashes exact",
    runtime_contract["artifact_hashes"]
    == {
        "extractor_sha256":
            "0bdad8db61b008ce50e6c53a472d3e56d36cf8169318cb50474672d62e566679",
        "metadata_manifest_sha256":
            "27104ea68cb2c47c10c0265ca8772b2c4af792ea7b2d5d34925511aefc2592d6",
        "openssl_harness_source_sha256":
            "0d5c2030409425115680d3140429918210fbc63c5f18bb0c08257314bd6e6240",
        "circl_harness_source_sha256":
            "f3c551821f4c31b8f7fd7242e66002c4aa1cc3dd0abb0c56710f3d0a91fc0fed",
    },
)


check(
    "runtime contract nonclaims exact",
    runtime_contract["non_claims"]
    == {
        "this_contract_proves_cryptographic_execution":
            False,
        "this_contract_proves_cross_implementation_agreement":
            False,
        "this_contract_is_nist_validation":
            False,
        "this_contract_is_fips_204_certification":
            False,
        "this_contract_proves_complete_fips_204_conformance":
            False,
        "this_contract_proves_complete_sigver_coverage":
            False,
    },
)


check(
    "runtime contract mutable state absent",
    all(
        key not in runtime_contract
        for key in [
            "status",
            "execution_state",
            "publication_state",
            "results_state",
        ]
    ),
)


runtime_metadata = load(
    "runtime/qsv_mldsa_sixcase_metadata_v0_1.json"
)


check(
    "runtime metadata identity exact",
    (
        runtime_metadata["schema"]
        == "qsv.mldsa.runtime-sixcase-metadata.v0.1"
        and runtime_metadata["payload_embedded"] is False
        and runtime_metadata["runtime_payload_emitted"] is False
        and runtime_metadata["case_count"] == 6
    ),
)


runtime_case_projection = [
    {
        "parameter_set":
            item["parameter_set"],
        "tg_id":
            item["tg_id"],
        "tc_id":
            item["tc_id"],
        "expected_valid":
            item["expected_valid"],
        "pk_size_bytes":
            item["pk_size_bytes"],
        "message_size_bytes":
            item["message_size_bytes"],
        "context_size_bytes":
            item["context_size_bytes"],
        "signature_size_bytes":
            item["signature_size_bytes"],
    }
    for item in runtime_metadata["cases"]
]


check(
    "runtime metadata six case projection exact",
    runtime_case_projection
    == [
        {
            "parameter_set":
                "ML-DSA-44",
            "tg_id":
                1,
            "tc_id":
                1,
            "expected_valid":
                False,
            "pk_size_bytes":
                1312,
            "message_size_bytes":
                7318,
            "context_size_bytes":
                171,
            "signature_size_bytes":
                2420,
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
            "pk_size_bytes":
                1312,
            "message_size_bytes":
                2473,
            "context_size_bytes":
                31,
            "signature_size_bytes":
                2420,
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
            "pk_size_bytes":
                1952,
            "message_size_bytes":
                3468,
            "context_size_bytes":
                13,
            "signature_size_bytes":
                3309,
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
            "pk_size_bytes":
                1952,
            "message_size_bytes":
                1481,
            "context_size_bytes":
                142,
            "signature_size_bytes":
                3309,
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
            "pk_size_bytes":
                2592,
            "message_size_bytes":
                3155,
            "context_size_bytes":
                76,
            "signature_size_bytes":
                4627,
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
            "pk_size_bytes":
                2592,
            "message_size_bytes":
                7147,
            "context_size_bytes":
                93,
            "signature_size_bytes":
                4627,
        },
    ],
)


runtime_metadata_case_keys = {
    "parameter_set",
    "tg_id",
    "tc_id",
    "expected_valid",
    "pk_size_bytes",
    "message_size_bytes",
    "context_size_bytes",
    "signature_size_bytes",
    "pk_sha256",
    "message_sha256",
    "context_sha256",
    "signature_sha256",
}


check(
    "runtime metadata case keys exact",
    all(
        set(item.keys())
        == runtime_metadata_case_keys
        for item in runtime_metadata["cases"]
    ),
)


runtime_extractor_text = (
    ROOT
    / "runtime/qsv_mldsa_sixcase_extractor_v0_1.py"
).read_text(
    encoding="utf-8"
)


check(
    "runtime extractor static gate exact",
    all(
        token in runtime_extractor_text
        for token in [
            "QSV_EXECUTE_CRYPTO",
            "before runtime payload emission",
            "runtime_root.mkdir",
            "exist_ok=False",
            "signature.bin",
        ]
    ),
)


runtime_openssl_text = (
    ROOT
    / "runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c"
).read_text(
    encoding="utf-8"
)


check(
    "runtime OpenSSL static API gate exact",
    all(
        token in runtime_openssl_text
        for token in [
            "QSV_EXECUTE_CRYPTO",
            "EVP_PKEY_fromdata",
            "OSSL_PKEY_PARAM_PUB_KEY",
            "EVP_PKEY_verify_message_init",
            "EVP_PKEY_verify(",
            "OSSL_SIGNATURE_PARAM_CONTEXT_STRING",
            "OPENSSL_OPERATIONAL_ERROR=YES",
        ]
    ),
)


runtime_circl_text = (
    ROOT
    / "runtime/qsv_mldsa_circl_sigver_harness_v0_1.go"
).read_text(
    encoding="utf-8"
)


check(
    "runtime CIRCL static API gate exact",
    all(
        token in runtime_circl_text
        for token in [
            "QSV_EXECUTE_CRYPTO",
            "UnmarshalBinary",
            "mldsa44.Verify(",
            "mldsa65.Verify(",
            "mldsa87.Verify(",
            "CIRCL_OPERATIONAL_ERROR=YES",
        ]
    ),
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
