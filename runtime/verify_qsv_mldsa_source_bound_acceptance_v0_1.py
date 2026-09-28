#!/usr/bin/env python3

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True

CASE_DOMAIN = b"QSV-MLDSA-SOURCE-CASE-V1\x00"
FIXTURE_DOMAIN = b"QSV-MLDSA-NEUTRAL-FIXTURE-V1\x00"

CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-source-bound-acceptance-contract-v0.1.json"
)

ACCEPTANCE_SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-source-bound-acceptance-v0.1.schema.json"
)

CONSUMER_SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-consumer-identity-v0.1.schema.json"
)

SELF_REL = (
    "runtime/"
    "verify_qsv_mldsa_source_bound_acceptance_v0_1.py"
)

FIXTURE_SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-fixture-v0.3.schema.json"
)

CANONICALIZATION_CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-neutral-fixture-canonicalization-contract-v0.1.json"
)

ACVP_MAPPER_REL = (
    "runtime/"
    "qsv_mldsa_acvp_to_neutral_fixture_mapper_v0_1.py"
)

GAP_VERIFIER_REL = (
    "runtime/"
    "verify_qsv_mldsa_neutral_fixture_gap_closure_v0_1.py"
)

NIST_BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

NIST_PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

WYCHEPROOF_BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-wycheproof-vector-source-v0.1.json"
)

WYCHEPROOF_PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json"
)

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class GateFailure(Exception):
    state = "FAIL"


class GateBlocked(Exception):
    state = "BLOCKED"


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(target):
    return sha256_bytes(target.read_bytes())


def load_json(target):
    return json.loads(
        target.read_text(encoding="utf-8")
    )


def canonical_bytes(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def domain_hash(domain, value):
    return sha256_bytes(
        domain + canonical_bytes(value)
    )


def safe_repo_path(root, rel):
    candidate = (root / rel).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise GateFailure(
            "PATH_ESCAPES_REPOSITORY"
        ) from exc

    return candidate


def verify_sidecar(root, rel):
    target = safe_repo_path(root, rel)
    sidecar = safe_repo_path(
        root,
        rel + ".sha256",
    )

    if not target.is_file():
        raise GateFailure(
            "MISSING_FILE:" + rel
        )

    if not sidecar.is_file():
        raise GateFailure(
            "MISSING_SIDECAR:" + rel
        )

    tokens = sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    if len(tokens) != 2:
        raise GateFailure(
            "INVALID_SIDECAR:" + rel
        )

    if tokens[0] != sha256_file(target):
        raise GateFailure(
            "SIDECAR_DIGEST_MISMATCH:" + rel
        )

    if tokens[1] != rel:
        raise GateFailure(
            "SIDECAR_PATH_MISMATCH:" + rel
        )


def artifact_commitment(value):
    if value is None:
        return None

    return {
        "sha256": value["sha256"],
        "byte_count": value["byte_count"],
    }


def case_descriptor(fixture):
    binding = fixture["source_binding"]

    return {
        "source_family":
            binding["source_family"],

        "source_repository":
            binding["source_repository"],

        "source_commit":
            binding["source_commit"],

        "source_tree":
            binding["source_tree"],

        "source_files":
            binding["source_files"],

        "case_identity":
            binding["case_identity"],

        "expected_outcome":
            fixture["expected_outcome"],

        "artifact_commitments": {
            "message":
                artifact_commitment(
                    fixture["message"]
                ),

            "context":
                artifact_commitment(
                    fixture["context"]
                ),

            "private_test_key":
                artifact_commitment(
                    fixture[
                        "artifacts"
                    ][
                        "private_test_key"
                    ]
                ),

            "public_key":
                artifact_commitment(
                    fixture[
                        "artifacts"
                    ][
                        "public_key"
                    ]
                ),

            "signature":
                artifact_commitment(
                    fixture[
                        "artifacts"
                    ][
                        "signature"
                    ]
                ),
        },
    }


def fixture_hash(fixture):
    target = copy.deepcopy(fixture)

    target.pop(
        "neutral_fixture_sha256",
        None,
    )

    return domain_hash(
        FIXTURE_DOMAIN,
        target,
    )


def load_contract(root):
    verify_sidecar(
        root,
        CONTRACT_REL,
    )

    verify_sidecar(
        root,
        SELF_REL,
    )

    contract = load_json(
        safe_repo_path(
            root,
            CONTRACT_REL,
        )
    )

    if contract.get("schema") != (
        "qsv.mldsa."
        "source-bound-acceptance-contract.v0.1"
    ):
        raise GateFailure(
            "CONTRACT_SCHEMA_MISMATCH"
        )

    if contract.get(
        "verification_attempt_states"
    ) != [
        "PASS",
        "FAIL",
        "BLOCKED",
    ]:
        raise GateFailure(
            "CONTRACT_STATE_SEMANTICS_MISMATCH"
        )

    policies = contract[
        "comparison_policies"
    ]

    if policies[
        "nist_acvp"
    ][
        "mode"
    ] != (
        "byte_identical_serialized_file_bytes"
    ):
        raise GateFailure(
            "NIST_COMPARISON_POLICY_MISMATCH"
        )

    if policies[
        "wycheproof"
    ][
        "mode"
    ] != (
        "canonical_json_identical"
    ):
        raise GateFailure(
            "WYCHEPROOF_COMPARISON_POLICY_MISMATCH"
        )

    return contract


def validate_contract_against_existing_authorities(
    root,
    contract,
):
    nist_binding = load_json(
        safe_repo_path(
            root,
            NIST_BINDING_REL,
        )
    )

    nist_profile = load_json(
        safe_repo_path(
            root,
            NIST_PROFILE_REL,
        )
    )

    wy_binding = load_json(
        safe_repo_path(
            root,
            WYCHEPROOF_BINDING_REL,
        )
    )

    wy_profile = load_json(
        safe_repo_path(
            root,
            WYCHEPROOF_PROFILE_REL,
        )
    )

    nist_contract = contract[
        "source_authorities"
    ][
        "nist_acvp"
    ]

    nist_authority = nist_binding[
        "source_authority"
    ]

    if (
        nist_contract["repository"]
        != nist_authority["repository"]
        or
        nist_contract["commit"]
        != nist_authority["selected_commit"]
        or
        nist_contract["tree"]
        != nist_authority["selected_tree"]
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    profile_sources = []

    for item in nist_profile[
        "source_inputs"
    ]:
        role = (
            "prompt"
            if item["path"].endswith(
                "/prompt.json"
            )
            else "expected_results"
        )

        profile_sources.append(
            {
                "role": role,
                "path": item["path"],
                "sha256": item["sha256"],
            }
        )

    if (
        nist_contract[
            "required_source_files"
        ]
        != profile_sources
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    wy_contract = contract[
        "source_authorities"
    ][
        "wycheproof"
    ]

    wy_authority = wy_binding[
        "source_authority"
    ]

    if (
        wy_contract["repository"]
        != wy_authority["repository"]
        or
        wy_contract["commit"]
        != wy_authority["selected_commit"]
        or
        wy_contract["tree"]
        is not None
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    matches = [
        item
        for item
        in wy_profile["selected_cases"]
        if item["case_id"]
        ==
        "QSV-MLDSA-WYCHEPROOF-44-0052"
    ]

    if len(matches) != 1:
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    selected = matches[0]

    expected_wy = [
        {
            "role": "vector",
            "path":
                selected["source_path"],
            "sha256":
                selected[
                    "source_file_sha256"
                ],
        }
    ]

    if (
        wy_contract[
            "required_source_files"
        ]
        != expected_wy
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )


def covered_fixture_entry(
    contract,
    fixture_rel,
):
    matches = [
        item
        for item
        in contract[
            "covered_fixtures"
        ]
        if item["path"] == fixture_rel
    ]

    if len(matches) != 1:
        raise GateFailure(
            "FIXTURE_NOT_COVERED_BY_SB1"
        )

    return matches[0]


def expected_fixture_source_files(
    fixture,
    contract,
):
    family = fixture[
        "source_binding"
    ][
        "source_family"
    ]

    authority = contract[
        "source_authorities"
    ][
        family
    ]

    binding = fixture[
        "source_binding"
    ]

    if (
        binding["source_repository"]
        != authority["repository"]
        or
        binding["source_commit"]
        != authority["commit"]
        or
        binding["source_tree"]
        != authority["tree"]
        or
        binding["source_tree_status"]
        != authority["tree_status"]
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    expected = [
        {
            "role": item["role"],
            "path": item["path"],
            "sha256": item["sha256"],
        }
        for item
        in authority[
            "required_source_files"
        ]
    ]

    if (
        binding["source_files"]
        != expected
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    return expected


def validate_fixture_metadata(
    root,
    fixture_rel,
    contract,
):
    fixture_target = safe_repo_path(
        root,
        fixture_rel,
    )

    if not fixture_target.is_file():
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    entry = covered_fixture_entry(
        contract,
        fixture_rel,
    )

    actual_fixture_sha = sha256_file(
        fixture_target
    )

    if actual_fixture_sha != entry[
        "sha256"
    ]:
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    fixture = load_json(
        fixture_target
    )

    fixture_schema = load_json(
        safe_repo_path(
            root,
            FIXTURE_SCHEMA_REL,
        )
    )

    if fixture_schema["$id"] != (
        "urn:qsv:mldsa:fixture:0.3"
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if set(fixture.keys()) != set(
        fixture_schema["required"]
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if (
        fixture["schema"]
        != "qsv.mldsa.fixture.v0.3"
        or
        fixture["algorithm"]
        != "ML-DSA"
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if (
        fixture[
            "source_binding"
        ][
            "source_family"
        ]
        != entry["source_family"]
    ):
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    if (
        fixture[
            "source_binding"
        ][
            "case_identity"
        ]
        != entry["case_identity"]
    ):
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    canon_target = safe_repo_path(
        root,
        CANONICALIZATION_CONTRACT_REL,
    )

    canon_sha = sha256_file(
        canon_target
    )

    canonicalization = fixture[
        "source_binding"
    ][
        "canonicalization"
    ]

    if (
        canonicalization[
            "contract_path"
        ]
        != CANONICALIZATION_CONTRACT_REL
        or
        canonicalization[
            "contract_sha256"
        ]
        != canon_sha
        or
        canonicalization[
            "case_source_hash_profile"
        ]
        != "QSV-MLDSA-SOURCE-CASE-V1"
        or
        canonicalization[
            "neutral_fixture_hash_profile"
        ]
        != "QSV-MLDSA-NEUTRAL-FIXTURE-V1"
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    expected_sources = (
        expected_fixture_source_files(
            fixture,
            contract,
        )
    )

    recomputed_case = domain_hash(
        CASE_DOMAIN,
        case_descriptor(fixture),
    )

    if (
        fixture[
            "source_binding"
        ][
            "case_source_sha256"
        ]
        != recomputed_case
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if (
        fixture[
            "neutral_fixture_sha256"
        ]
        != fixture_hash(fixture)
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    return {
        "fixture":
            fixture,

        "fixture_target":
            fixture_target,

        "fixture_rel":
            fixture_rel,

        "fixture_sha256":
            actual_fixture_sha,

        "source_family":
            entry["source_family"],

        "source_files":
            expected_sources,
    }


def observed_source_files(
    metadata,
    args,
):
    family = metadata[
        "source_family"
    ]

    if family == "nist_acvp":
        if (
            args.nist_prompt is None
            or
            args.nist_expected is None
            or
            args.wycheproof_source
            is not None
        ):
            raise GateBlocked(
                "REQUIRED_SOURCE_SET_INCOMPLETE"
            )

        local_by_role = {
            "prompt":
                Path(
                    args.nist_prompt
                ).resolve(),

            "expected_results":
                Path(
                    args.nist_expected
                ).resolve(),
        }

    elif family == "wycheproof":
        if (
            args.wycheproof_source
            is None
            or
            args.nist_prompt is not None
            or
            args.nist_expected is not None
        ):
            raise GateBlocked(
                "REQUIRED_SOURCE_SET_INCOMPLETE"
            )

        local_by_role = {
            "vector":
                Path(
                    args.wycheproof_source
                ).resolve(),
        }

    else:
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    result = []

    for expected in metadata[
        "source_files"
    ]:
        local_target = local_by_role[
            expected["role"]
        ]

        if not local_target.is_file():
            raise GateBlocked(
                "SOURCE_INACCESSIBLE"
            )

        observed = sha256_file(
            local_target
        )

        if observed != expected[
            "sha256"
        ]:
            raise GateFailure(
                "SOURCE_FILE_DIGEST_MISMATCH"
            )

        result.append(
            {
                "role":
                    expected["role"],

                "path":
                    expected["path"],

                "expected_sha256":
                    expected["sha256"],

                "observed_sha256":
                    observed,

                "verification_status":
                    "MATCH",

                "_local_target":
                    local_target,
            }
        )

    return result


def import_gap_authority(root):
    module_target = safe_repo_path(
        root,
        GAP_VERIFIER_REL,
    )

    spec = (
        importlib.util
        .spec_from_file_location(
            "qsv_gap_authority",
            module_target,
        )
    )

    if (
        spec is None
        or spec.loader is None
    ):
        raise GateBlocked(
            "PREREQUISITE_UNAVAILABLE"
        )

    module = (
        importlib.util
        .module_from_spec(spec)
    )

    spec.loader.exec_module(module)

    return module


def regenerate_nist(
    root,
    metadata,
    observed,
):
    fixture = metadata["fixture"]

    mapper = safe_repo_path(
        root,
        ACVP_MAPPER_REL,
    )

    if not mapper.is_file():
        raise GateBlocked(
            "PREREQUISITE_UNAVAILABLE"
        )

    source_targets = {
        item["role"]:
            item["_local_target"]
        for item in observed
    }

    coordinates = fixture[
        "source_binding"
    ][
        "case_identity"
    ][
        "coordinates"
    ]

    env = dict(os.environ)
    env.pop(
        "QSV_EXECUTE_CRYPTO",
        None,
    )
    env[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    with tempfile.TemporaryDirectory(
        prefix="qsv-sb1-acvp-"
    ) as temp_name:

        temp_root = Path(temp_name)

        run1 = temp_root / "run1.json"
        run2 = temp_root / "run2.json"

        base = [
            sys.executable,
            str(mapper),
            "--root",
            str(root),
            "--prompt",
            str(
                source_targets["prompt"]
            ),
            "--expected",
            str(
                source_targets[
                    "expected_results"
                ]
            ),
            "--parameter-set",
            fixture["parameter_set"],
            "--tg-id",
            str(coordinates["tg_id"]),
            "--tc-id",
            str(coordinates["tc_id"]),
        ]

        for output_target in [
            run1,
            run2,
        ]:
            proc = subprocess.run(
                base
                + [
                    "--output",
                    str(output_target),
                ],
                cwd=str(root),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            if proc.returncode != 0:
                raise GateFailure(
                    "REGENERATION_EXECUTION_FAILURE"
                )

        run1_bytes = run1.read_bytes()
        run2_bytes = run2.read_bytes()

        if run1_bytes != run2_bytes:
            raise GateFailure(
                "REGENERATION_NONDETERMINISTIC"
            )

        if run1_bytes != metadata[
            "fixture_target"
        ].read_bytes():
            raise GateFailure(
                "REGENERATED_FIXTURE_MISMATCH"
            )

    return {
        "performed":
            True,

        "comparison_mode":
            "byte_identical_serialized_file_bytes",

        "run1_equals_run2":
            True,

        "regenerated_fixture_match":
            True,
    }


def regenerate_wycheproof(
    root,
    metadata,
    observed,
):
    vector_target = observed[
        0
    ][
        "_local_target"
    ]

    module = import_gap_authority(
        root
    )

    contract_sha = sha256_file(
        safe_repo_path(
            root,
            CANONICALIZATION_CONTRACT_REL,
        )
    )

    try:
        run1 = (
            module
            .build_wycheproof_expected(
                root,
                vector_target,
                contract_sha,
            )
        )

        run2 = (
            module
            .build_wycheproof_expected(
                root,
                vector_target,
                contract_sha,
            )
        )

    except Exception as exc:
        raise GateFailure(
            "REGENERATION_EXECUTION_FAILURE"
        ) from exc

    run1_bytes = canonical_bytes(run1)
    run2_bytes = canonical_bytes(run2)

    published_bytes = canonical_bytes(
        metadata["fixture"]
    )

    if run1_bytes != run2_bytes:
        raise GateFailure(
            "REGENERATION_NONDETERMINISTIC"
        )

    if run1_bytes != published_bytes:
        raise GateFailure(
            "REGENERATED_FIXTURE_MISMATCH"
        )

    return {
        "performed":
            True,

        "comparison_mode":
            "canonical_json_identical",

        "run1_equals_run2":
            True,

        "regenerated_fixture_match":
            True,
    }


def public_source_files(observed):
    result = []

    for item in observed:
        result.append(
            {
                key: value
                for key, value
                in item.items()
                if key != "_local_target"
            }
        )

    return result


def build_record(
    metadata,
    requested,
    observed,
    regeneration,
    state,
    reason,
):
    fixture = metadata["fixture"]
    binding = fixture["source_binding"]

    if observed is None:
        source_files = [
            {
                "role":
                    item["role"],

                "path":
                    item["path"],

                "expected_sha256":
                    item["sha256"],

                "observed_sha256":
                    None,

                "verification_status":
                    "NOT_VERIFIED",
            }
            for item
            in metadata["source_files"]
        ]
    else:
        source_files = public_source_files(
            observed
        )

    return {
        "schema":
            "qsv.mldsa."
            "source-bound-acceptance.v0.1",

        "case_scoped":
            True,

        "fixture_scoped":
            True,

        "source_bound_verification_requested":
            requested,

        "fixture_metadata_validation":
            "PASS",

        "source_authority": {
            "source_family":
                binding["source_family"],

            "repository":
                binding["source_repository"],

            "commit":
                binding["source_commit"],

            "tree":
                binding["source_tree"],

            "tree_status":
                binding[
                    "source_tree_status"
                ],
        },

        "source_files":
            source_files,

        "case_identity":
            copy.deepcopy(
                binding["case_identity"]
            ),

        "regeneration":
            regeneration,

        "published_fixture": {
            "path":
                metadata["fixture_rel"],

            "sha256":
                metadata[
                    "fixture_sha256"
                ],
        },

        "source_bound_verification_state":
            state,

        "reason_code":
            reason,
    }


def validate_acceptance_record(
    record,
    contract,
):
    required_keys = {
        "schema",
        "case_scoped",
        "fixture_scoped",
        "source_bound_verification_requested",
        "fixture_metadata_validation",
        "source_authority",
        "source_files",
        "case_identity",
        "regeneration",
        "published_fixture",
        "source_bound_verification_state",
        "reason_code",
    }

    if set(record) != required_keys:
        raise GateFailure(
            "ACCEPTANCE_RECORD_FIELDSET_MISMATCH"
        )

    if (
        record["case_scoped"] is not True
        or
        record["fixture_scoped"] is not True
    ):
        raise GateFailure(
            "ACCEPTANCE_SCOPE_MISMATCH"
        )

    family = record[
        "source_authority"
    ][
        "source_family"
    ]

    expected_mode = contract[
        "comparison_policies"
    ][
        family
    ][
        "mode"
    ]

    requested = record[
        "source_bound_verification_requested"
    ]

    state = record[
        "source_bound_verification_state"
    ]

    regeneration = record[
        "regeneration"
    ]

    if requested is False:
        if (
            state is not None
            or
            record["reason_code"]
            != "NOT_REQUESTED"
            or
            regeneration["performed"]
            is not False
            or
            regeneration[
                "comparison_mode"
            ]
            is not None
            or
            regeneration[
                "run1_equals_run2"
            ]
            is not None
            or
            regeneration[
                "regenerated_fixture_match"
            ]
            is not None
        ):
            raise GateFailure(
                "METADATA_ONLY_STATE_MISMATCH"
            )

        for item in record[
            "source_files"
        ]:
            if (
                item[
                    "observed_sha256"
                ]
                is not None
                or
                item[
                    "verification_status"
                ]
                != "NOT_VERIFIED"
            ):
                raise GateFailure(
                    "METADATA_ONLY_SOURCE_STATE_MISMATCH"
                )

        return

    if state not in {
        "PASS",
        "FAIL",
        "BLOCKED",
    }:
        raise GateFailure(
            "SOURCE_BOUND_STATE_INVALID"
        )

    if state == "PASS":
        if (
            record[
                "fixture_metadata_validation"
            ]
            != "PASS"
            or
            record["reason_code"]
            != "PASS"
            or
            regeneration["performed"]
            is not True
            or
            regeneration[
                "comparison_mode"
            ]
            != expected_mode
            or
            regeneration[
                "run1_equals_run2"
            ]
            is not True
            or
            regeneration[
                "regenerated_fixture_match"
            ]
            is not True
        ):
            raise GateFailure(
                "FORGED_SOURCE_BOUND_PASS"
            )

        for item in record[
            "source_files"
        ]:
            if (
                item[
                    "verification_status"
                ]
                != "MATCH"
                or
                item[
                    "observed_sha256"
                ]
                != item[
                    "expected_sha256"
                ]
            ):
                raise GateFailure(
                    "FORGED_SOURCE_BOUND_PASS"
                )


def write_record(target, record):
    target.write_bytes(
        canonical_bytes(record)
    )


def validate_consumer_record(
    root,
    consumer_target,
):
    record = load_json(
        consumer_target
    )

    if set(record) != {
        "schema",
        "consumer",
    }:
        raise GateFailure(
            "CONSUMER_FIELDSET_MISMATCH"
        )

    if record["schema"] != (
        "qsv.mldsa.consumer-identity.v0.1"
    ):
        raise GateFailure(
            "CONSUMER_SCHEMA_MISMATCH"
        )

    consumer = record["consumer"]

    required = {
        "implementation_id",
        "repository",
        "runtime_identity",
        "source_identity",
        "identity_basis",
        "source_to_runtime_binding",
        "lineage",
        "adapter_identity",
    }

    if set(consumer) != required:
        raise GateFailure(
            "CONSUMER_FIELDSET_MISMATCH"
        )

    implementation = consumer[
        "implementation_id"
    ]

    if re.fullmatch(
        r"[a-z0-9][a-z0-9._-]*",
        implementation,
    ) is None:
        raise GateFailure(
            "CONSUMER_IMPLEMENTATION_INVALID"
        )

    if not isinstance(
        consumer["repository"],
        str,
    ) or not consumer["repository"]:
        raise GateFailure(
            "CONSUMER_REPOSITORY_INVALID"
        )

    runtime = consumer[
        "runtime_identity"
    ]

    if set(runtime) != {
        "version",
        "executable_sha256",
    }:
        raise GateFailure(
            "RUNTIME_IDENTITY_INVALID"
        )

    if (
        runtime["version"]
        is not None
        and (
            not isinstance(
                runtime["version"],
                str,
            )
            or not runtime["version"]
        )
    ):
        raise GateFailure(
            "RUNTIME_IDENTITY_INVALID"
        )

    if (
        runtime["executable_sha256"]
        is not None
        and HEX64.fullmatch(
            runtime["executable_sha256"]
        )
        is None
    ):
        raise GateFailure(
            "RUNTIME_IDENTITY_INVALID"
        )

    source = consumer[
        "source_identity"
    ]

    if set(source) != {
        "version",
        "commit",
        "tree",
    }:
        raise GateFailure(
            "SOURCE_IDENTITY_INVALID"
        )

    if (
        source["version"] is None
        and
        source["commit"] is None
    ):
        raise GateFailure(
            "SOURCE_IDENTITY_INVALID"
        )

    if (
        source["version"]
        is not None
        and (
            not isinstance(
                source["version"],
                str,
            )
            or not source["version"]
        )
    ):
        raise GateFailure(
            "SOURCE_IDENTITY_INVALID"
        )

    if (
        source["commit"]
        is not None
        and HEX40.fullmatch(
            source["commit"]
        )
        is None
    ):
        raise GateFailure(
            "SOURCE_IDENTITY_INVALID"
        )

    if (
        source["tree"]
        is not None
        and HEX40.fullmatch(
            source["tree"]
        )
        is None
    ):
        raise GateFailure(
            "SOURCE_IDENTITY_INVALID"
        )

    basis = consumer[
        "identity_basis"
    ]

    if basis not in {
        "runtime_version",
        "source_commit",
        "runtime_version_and_source_commit",
    }:
        raise GateFailure(
            "IDENTITY_BASIS_INVALID"
        )

    if (
        basis == "runtime_version"
        and runtime["version"] is None
    ):
        raise GateFailure(
            "IDENTITY_BASIS_INVALID"
        )

    if (
        basis == "source_commit"
        and source["commit"] is None
    ):
        raise GateFailure(
            "IDENTITY_BASIS_INVALID"
        )

    if (
        basis
        == "runtime_version_and_source_commit"
        and (
            runtime["version"] is None
            or source["commit"] is None
        )
    ):
        raise GateFailure(
            "IDENTITY_BASIS_INVALID"
        )

    source_runtime = consumer[
        "source_to_runtime_binding"
    ]

    if set(source_runtime) != {
        "status",
        "evidence_path",
        "evidence_sha256",
    }:
        raise GateFailure(
            "SOURCE_TO_RUNTIME_BINDING_INVALID"
        )

    if source_runtime["status"] not in {
        "proven",
        "incomplete",
        "not_established",
    }:
        raise GateFailure(
            "SOURCE_TO_RUNTIME_BINDING_INVALID"
        )

    lineage = consumer["lineage"]

    if set(lineage) != {
        "implementation_id",
        "binding_path",
        "binding_sha256",
        "equivalence_class",
    }:
        raise GateFailure(
            "LINEAGE_INVALID"
        )

    if (
        lineage["implementation_id"]
        != implementation
    ):
        raise GateFailure(
            "LINEAGE_IMPLEMENTATION_MISMATCH"
        )

    lineage_target = safe_repo_path(
        root,
        lineage["binding_path"],
    )

    if not lineage_target.is_file():
        raise GateFailure(
            "LINEAGE_EVIDENCE_MISSING"
        )

    lineage_sha = sha256_file(
        lineage_target
    )

    if (
        lineage["binding_sha256"]
        != lineage_sha
    ):
        raise GateFailure(
            "LINEAGE_DIGEST_MISMATCH"
        )

    if not lineage["equivalence_class"]:
        raise GateFailure(
            "LINEAGE_EQUIVALENCE_CLASS_MISSING"
        )

    lineage_data = load_json(
        lineage_target
    )

    implementations = lineage_data[
        "implementations"
    ]

    implementation_matches = [
        value
        for value
        in implementations.values()
        if value.get(
            "implementation_id"
        ) == implementation
    ]

    if len(
        implementation_matches
    ) == 0:
        raise GateFailure(
            "LINEAGE_IMPLEMENTATION_MISSING"
        )

    if len(
        implementation_matches
    ) != 1:
        raise GateFailure(
            "LINEAGE_IMPLEMENTATION_AMBIGUOUS"
        )

    existing = implementation_matches[
        0
    ]

    if implementation == "openssl":
        provenance = existing[
            "build_provenance"
        ]

        if (
            provenance["complete"]
            is False
            or
            provenance[
                "local_binary_source_commit_proven"
            ]
            is False
        ):
            if (
                source_runtime["status"]
                != "incomplete"
            ):
                raise GateFailure(
                    "SOURCE_TO_RUNTIME_PROVENANCE_PROMOTION"
                )

    if implementation == "cloudflare-circl":
        if (
            existing[
                "fixture_execution_from_pinned_source_performed"
            ]
            is False
            and
            source_runtime["status"]
            == "proven"
        ):
            raise GateFailure(
                "SOURCE_TO_RUNTIME_PROVENANCE_PROMOTION"
            )

    evidence_rel = source_runtime[
        "evidence_path"
    ]

    evidence_sha = source_runtime[
        "evidence_sha256"
    ]

    if source_runtime["status"] in {
        "proven",
        "incomplete",
    }:
        if (
            not isinstance(
                evidence_rel,
                str,
            )
            or not evidence_rel
            or
            not isinstance(
                evidence_sha,
                str,
            )
            or HEX64.fullmatch(
                evidence_sha
            )
            is None
        ):
            raise GateFailure(
                "SOURCE_TO_RUNTIME_BINDING_INVALID"
            )

        evidence_target = safe_repo_path(
            root,
            evidence_rel,
        )

        if (
            not evidence_target.is_file()
            or
            sha256_file(
                evidence_target
            )
            != evidence_sha
        ):
            raise GateFailure(
                "SOURCE_TO_RUNTIME_EVIDENCE_MISMATCH"
            )

    adapter = consumer[
        "adapter_identity"
    ]

    if set(adapter) != {
        "path",
        "sha256",
        "schema_version",
    }:
        raise GateFailure(
            "ADAPTER_IDENTITY_INVALID"
        )

    adapter_target = safe_repo_path(
        root,
        adapter["path"],
    )

    if not adapter_target.is_file():
        raise GateFailure(
            "ADAPTER_IDENTITY_MISSING"
        )

    if (
        sha256_file(adapter_target)
        != adapter["sha256"]
    ):
        raise GateFailure(
            "ADAPTER_IDENTITY_DIGEST_MISMATCH"
        )

    if (
        not isinstance(
            adapter["schema_version"],
            str,
        )
        or not adapter["schema_version"]
    ):
        raise GateFailure(
            "ADAPTER_IDENTITY_INVALID"
        )

    return record


def consumers_are_independent(
    left,
    right,
):
    left_lineage = (
        left["consumer"]["lineage"]
    )

    right_lineage = (
        right["consumer"]["lineage"]
    )

    if (
        left_lineage[
            "equivalence_class"
        ]
        ==
        right_lineage[
            "equivalence_class"
        ]
    ):
        return False

    if (
        left_lineage["binding_path"]
        ==
        right_lineage["binding_path"]
        and
        left_lineage[
            "implementation_id"
        ]
        ==
        right_lineage[
            "implementation_id"
        ]
    ):
        return False

    return True


def run(args):
    if "QSV_EXECUTE_CRYPTO" in os.environ:
        raise GateFailure(
            "QSV_EXECUTE_CRYPTO_PRESENT"
        )

    root = Path(args.root).resolve()

    contract = load_contract(root)

    validate_contract_against_existing_authorities(
        root,
        contract,
    )

    acceptance_schema = load_json(
        safe_repo_path(
            root,
            ACCEPTANCE_SCHEMA_REL,
        )
    )

    consumer_schema = load_json(
        safe_repo_path(
            root,
            CONSUMER_SCHEMA_REL,
        )
    )

    if acceptance_schema["$id"] != (
        "urn:qsv:mldsa:"
        "source-bound-acceptance:0.1"
    ):
        raise GateFailure(
            "ACCEPTANCE_SCHEMA_ID_MISMATCH"
        )

    if consumer_schema["$id"] != (
        "urn:qsv:mldsa:"
        "consumer-identity:0.1"
    ):
        raise GateFailure(
            "CONSUMER_SCHEMA_ID_MISMATCH"
        )

    if args.consumer is not None:
        validate_consumer_record(
            root,
            Path(args.consumer).resolve(),
        )

        print(
            "CONSUMER_IDENTITY_VALIDATION=PASS"
        )

    if args.consumer_only:
        if args.consumer is None:
            raise GateFailure(
                "CONSUMER_RECORD_REQUIRED"
            )

        print(
            "QSV_MLDSA_CONSUMER_IDENTITY_VERIFIER=PASS"
        )
        print(
            "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
        )
        print(
            "VERIFIER_NETWORK_FETCH=NO"
        )
        return

    if args.fixture is None:
        raise GateFailure(
            "FIXTURE_REQUIRED"
        )

    metadata = validate_fixture_metadata(
        root,
        args.fixture,
        contract,
    )

    print(
        "FIXTURE_METADATA_VALIDATION=PASS"
    )

    requested = (
        args.source_bound_requested
        == "yes"
    )

    any_sources = any(
        value is not None
        for value in [
            args.nist_prompt,
            args.nist_expected,
            args.wycheproof_source,
        ]
    )

    if not requested:
        if any_sources:
            raise GateBlocked(
                "SOURCE_INPUTS_SUPPLIED_WITHOUT_REQUEST"
            )

        regeneration = {
            "performed": False,
            "comparison_mode": None,
            "run1_equals_run2": None,
            "regenerated_fixture_match": None,
        }

        record = build_record(
            metadata,
            False,
            None,
            regeneration,
            None,
            "NOT_REQUESTED",
        )

        validate_acceptance_record(
            record,
            contract,
        )

        if args.output is not None:
            write_record(
                Path(args.output),
                record,
            )

        print(
            "SOURCE_BOUND_VERIFICATION_REQUESTED=NO"
        )
        print(
            "SOURCE_BOUND_VERIFICATION_STATE=NULL"
        )
        print(
            "SOURCE_REGENERATION_PERFORMED=NO"
        )
        print(
            "SOURCE_BOUND_PASS_CLAIM=NO"
        )
        print(
            "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER=PASS"
        )
        print(
            "VERIFIER_NETWORK_FETCH=NO"
        )
        print(
            "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
        )
        return

    observed = observed_source_files(
        metadata,
        args,
    )

    family = metadata["source_family"]

    expected_mode = contract[
        "comparison_policies"
    ][
        family
    ][
        "mode"
    ]

    comparison_mode = (
        args.comparison_mode
        if args.comparison_mode
        is not None
        else expected_mode
    )

    if comparison_mode != expected_mode:
        raise GateFailure(
            "SOURCE_FAMILY_COMPARISON_POLICY_MISMATCH"
        )

    if family == "nist_acvp":
        regeneration = regenerate_nist(
            root,
            metadata,
            observed,
        )

    elif family == "wycheproof":
        regeneration = (
            regenerate_wycheproof(
                root,
                metadata,
                observed,
            )
        )

    else:
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    if (
        regeneration[
            "comparison_mode"
        ]
        != expected_mode
    ):
        raise GateFailure(
            "SOURCE_FAMILY_COMPARISON_POLICY_MISMATCH"
        )

    record = build_record(
        metadata,
        True,
        observed,
        regeneration,
        "PASS",
        "PASS",
    )

    validate_acceptance_record(
        record,
        contract,
    )

    if args.output is not None:
        write_record(
            Path(args.output),
            record,
        )

    print(
        "SOURCE_BOUND_VERIFICATION_REQUESTED=YES"
    )
    print(
        "REQUIRED_SOURCE_SET_COMPLETE=YES"
    )
    print(
        "SOURCE_AUTHORITY_MATCH=YES"
    )
    print(
        "SOURCE_FILE_DIGESTS_MATCH=YES"
    )
    print(
        "CASE_IDENTITY_MATCH=YES"
    )
    print(
        "SOURCE_REGENERATION_PERFORMED=YES"
    )
    print(
        "COMPARISON_POLICY_VALID=YES"
    )
    print(
        "REGENERATION_RUN1_EQUALS_RUN2=YES"
    )
    print(
        "REGENERATED_FIXTURE_MATCH=YES"
    )
    print(
        "SOURCE_BOUND_VERIFICATION_STATE=PASS"
    )
    print(
        "SOURCE_BOUND_PASS_CLAIM=YES"
    )
    print(
        "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER=PASS"
    )
    print(
        "VERIFIER_NETWORK_FETCH=NO"
    )
    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        default=".",
    )

    parser.add_argument(
        "--fixture",
    )

    parser.add_argument(
        "--source-bound-requested",
        choices=[
            "yes",
            "no",
        ],
        default="no",
    )

    parser.add_argument(
        "--nist-prompt",
    )

    parser.add_argument(
        "--nist-expected",
    )

    parser.add_argument(
        "--wycheproof-source",
    )

    parser.add_argument(
        "--comparison-mode",
    )

    parser.add_argument(
        "--consumer",
    )

    parser.add_argument(
        "--consumer-only",
        action="store_true",
    )

    parser.add_argument(
        "--output",
    )

    args = parser.parse_args()

    try:
        run(args)

    except GateBlocked as exc:
        print(
            "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER=FAIL"
        )
        print(
            "SOURCE_BOUND_VERIFICATION_STATE=BLOCKED"
        )
        print(
            "FAILURE_REASON="
            + str(exc)
        )
        print(
            "SOURCE_BOUND_PASS_CLAIM=NO"
        )
        print(
            "VERIFIER_NETWORK_FETCH=NO"
        )
        print(
            "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
        )
        raise SystemExit(2)

    except (
        GateFailure,
        AssertionError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(
            "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER=FAIL"
        )
        print(
            "SOURCE_BOUND_VERIFICATION_STATE=FAIL"
        )
        print(
            "FAILURE_REASON="
            + (
                str(exc)
                if str(exc)
                else exc.__class__.__name__
            )
        )
        print(
            "SOURCE_BOUND_PASS_CLAIM=NO"
        )
        print(
            "VERIFIER_NETWORK_FETCH=NO"
        )
        print(
            "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
