#!/usr/bin/env python3

import argparse
import copy
import hashlib
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
    "qsv-mldsa-source-bound-acceptance-contract-v0.2.json"
)

ACCEPTANCE_SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-source-bound-acceptance-v0.2.schema.json"
)

SELF_REL = (
    "runtime/"
    "verify_qsv_mldsa_source_bound_acceptance_v0_2.py"
)

COVERAGE_MANIFEST_REL = (
    "manifest/"
    "qsv-mldsa-f7-sixcase-neutral-fixture-coverage-v0.1-manifest.json"
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

NIST_BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

NIST_PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

PREDECESSOR_CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-source-bound-acceptance-contract-v0.1.json"
)

PREDECESSOR_CONTRACT_SHA256 = (
    "b0f29bf4f5c7d607dca2f32c1c5716ba87a93c5658bf367793b8a7ed7d02b5f5"
)

PREDECESSOR_PUBLIC_COMMIT = (
    "bbc2f9ef6002fb55143d86dfcdb7fbbecf86462c"
)

PREDECESSOR_PUBLIC_TREE = (
    "6e79deb9e3eae3b2fbf6e7c156a1f33d694283fe"
)

EXPECTED_CONTRACT_SHA256 = "3b3b844c364cc338f4e6c9cf24281cf850ff6a5bf6e051c34d3b6472e8909da3"
EXPECTED_SCHEMA_SHA256 = "37c2e0e88dc54f4eb5b0e00972d05f4fb42a2c8524fd0b863fe0adc745d1c606"

HEX64 = re.compile(r"^[0-9a-f]{64}$")


CLAIM_BOUNDARY = {
    "complete_acvp_coverage": False,
    "complete_fips_204_conformance": False,
    "fips_204_certification": False,
    "implementation_independence_proven": False,
    "mldsa_implementation_correctness": False,
    "nist_validation": False,
}


EXECUTION_BOUNDARY = {
    "network_fetch_performed": False,
    "new_crypto_execution_performed": False,
}


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
        target.read_text(
            encoding="utf-8"
        )
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
    candidate = (
        root / rel
    ).resolve()

    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise GateFailure(
            "PATH_ESCAPES_REPOSITORY"
        ) from exc

    return candidate


def verify_sidecar(root, rel):
    target = safe_repo_path(
        root,
        rel,
    )

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

    line = sidecar.read_text(
        encoding="utf-8"
    ).splitlines()

    if len(line) != 1:
        raise GateFailure(
            "INVALID_SIDECAR:" + rel
        )

    parts = line[0].split(
        None,
        1,
    )

    if len(parts) != 2:
        raise GateFailure(
            "INVALID_SIDECAR:" + rel
        )

    if parts[0] != sha256_file(target):
        raise GateFailure(
            "SIDECAR_DIGEST_MISMATCH:" + rel
        )

    if parts[1] != rel:
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
    target = copy.deepcopy(
        fixture
    )

    target.pop(
        "neutral_fixture_sha256",
        None,
    )

    return domain_hash(
        FIXTURE_DOMAIN,
        target,
    )


def expected_identity(entry):
    return {
        "parameter_set":
            entry["parameter_set"],

        "primary":
            entry[
                "case_identity"
            ][
                "primary"
            ],

        "coordinates":
            entry[
                "case_identity"
            ][
                "coordinates"
            ],

        "expected_valid":
            entry[
                "expected_valid"
            ],
    }


def load_contract(root):
    verify_sidecar(
        root,
        CONTRACT_REL,
    )

    verify_sidecar(
        root,
        SELF_REL,
    )

    contract_target = safe_repo_path(
        root,
        CONTRACT_REL,
    )

    if sha256_file(
        contract_target
    ) != EXPECTED_CONTRACT_SHA256:
        raise GateFailure(
            "CONTRACT_AUTHORITY_DIGEST_MISMATCH"
        )

    schema_target = safe_repo_path(
        root,
        ACCEPTANCE_SCHEMA_REL,
    )

    if not schema_target.is_file():
        raise GateFailure(
            "ACCEPTANCE_SCHEMA_MISSING"
        )

    if sha256_file(
        schema_target
    ) != EXPECTED_SCHEMA_SHA256:
        raise GateFailure(
            "ACCEPTANCE_SCHEMA_DIGEST_MISMATCH"
        )

    schema = load_json(
        schema_target
    )

    if schema.get("$id") != (
        "urn:qsv:mldsa:"
        "source-bound-acceptance:0.2"
    ):
        raise GateFailure(
            "ACCEPTANCE_SCHEMA_ID_MISMATCH"
        )

    contract = load_json(
        contract_target
    )

    required_top_level = {
        "schema",
        "version",
        "authority_relationship",
        "predecessor",
        "scope",
        "covered_fixtures",
        "coverage_manifest",
        "acceptance_record",
        "verifier",
        "source_authorities",
        "comparison_policies",
        "source_input_policy",
        "verification_request",
        "case_pass_conditions",
        "aggregate_semantics",
        "determinism",
        "historical_evidence",
        "publication_semantics",
        "claim_boundary",
    }

    if set(contract) != required_top_level:
        raise GateFailure(
            "CONTRACT_FIELDSET_MISMATCH"
        )

    if contract["schema"] != (
        "qsv.mldsa."
        "source-bound-acceptance-contract.v0.2"
    ):
        raise GateFailure(
            "CONTRACT_SCHEMA_MISMATCH"
        )

    if contract["version"] != "0.2":
        raise GateFailure(
            "CONTRACT_VERSION_MISMATCH"
        )

    relationship = contract[
        "authority_relationship"
    ]

    if relationship != {
        "type":
            "APPEND_ONLY_VERSIONED_EXTENSION_AUTHORITY",

        "semantic_relationship":
            "extends_without_modifying",

        "replaces_predecessor":
            False,

        "supersedes_predecessor":
            False,
    }:
        raise GateFailure(
            "SUCCESSOR_RELATIONSHIP_MISMATCH"
        )

    predecessor = contract[
        "predecessor"
    ]

    if predecessor != {
        "contract_path":
            PREDECESSOR_CONTRACT_REL,

        "contract_sha256":
            PREDECESSOR_CONTRACT_SHA256,

        "public_commit":
            PREDECESSOR_PUBLIC_COMMIT,

        "public_tree":
            PREDECESSOR_PUBLIC_TREE,

        "relationship":
            "extends_without_modifying",
    }:
        raise GateFailure(
            "PREDECESSOR_BINDING_MISMATCH"
        )

    predecessor_target = safe_repo_path(
        root,
        PREDECESSOR_CONTRACT_REL,
    )

    if (
        not predecessor_target.is_file()
        or
        sha256_file(
            predecessor_target
        )
        != PREDECESSOR_CONTRACT_SHA256
    ):
        raise GateFailure(
            "PREDECESSOR_BINDING_MISMATCH"
        )

    if len(
        contract["covered_fixtures"]
    ) != 6:
        raise GateFailure(
            "SUCCESSOR_COVERAGE_COUNT_MISMATCH"
        )

    if contract[
        "scope"
    ][
        "exact_f7_acvp_case_count"
    ] != 6:
        raise GateFailure(
            "SUCCESSOR_COVERAGE_COUNT_MISMATCH"
        )

    if contract[
        "scope"
    ][
        "wycheproof_included_in_f7_successor_scope"
    ] is not False:
        raise GateFailure(
            "SUCCESSOR_SCOPE_MISMATCH"
        )

    if contract[
        "coverage_manifest"
    ][
        "path"
    ] != COVERAGE_MANIFEST_REL:
        raise GateFailure(
            "COVERAGE_MANIFEST_PATH_MISMATCH"
        )

    if contract[
        "coverage_manifest"
    ][
        "required"
    ] is not True:
        raise GateFailure(
            "COVERAGE_MANIFEST_REQUIREMENT_MISMATCH"
        )

    for field in [
        "implies_source_bound_acceptance",
        "implies_crypto_correctness",
        "implies_nist_validation",
        "implies_fips_204_certification",
    ]:
        if contract[
            "coverage_manifest"
        ][field] is not False:
            raise GateFailure(
                "COVERAGE_MANIFEST_CLAIM_PROMOTION"
            )

    if contract[
        "verifier"
    ][
        "network_fetch"
    ] is not False:
        raise GateFailure(
            "NETWORK_FETCH_POLICY_MISMATCH"
        )

    if contract[
        "verifier"
    ][
        "new_crypto_execution_required"
    ] is not False:
        raise GateFailure(
            "CRYPTO_EXECUTION_POLICY_MISMATCH"
        )

    publication = contract[
        "publication_semantics"
    ]

    if any(
        publication[field] is not False
        for field in publication
    ):
        raise GateFailure(
            "CONTRACT_FALSE_EXECUTION_CLAIM"
        )

    if any(
        contract[
            "claim_boundary"
        ][field] is not False
        for field in contract[
            "claim_boundary"
        ]
    ):
        raise GateFailure(
            "CLAIM_BOUNDARY_MISMATCH"
        )

    return contract


def validate_contract_against_existing_authorities(
    root,
    contract,
):
    binding = load_json(
        safe_repo_path(
            root,
            NIST_BINDING_REL,
        )
    )

    profile = load_json(
        safe_repo_path(
            root,
            NIST_PROFILE_REL,
        )
    )

    authority = contract[
        "source_authorities"
    ][
        "nist_acvp"
    ]

    binding_authority = binding[
        "source_authority"
    ]

    if (
        authority["repository"]
        != binding_authority["repository"]
        or
        authority["commit"]
        != binding_authority["selected_commit"]
        or
        authority["tree"]
        != binding_authority["selected_tree"]
    ):
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    expected_sources = [
        {
            "role":
                (
                    "prompt"
                    if item["path"].endswith(
                        "/prompt.json"
                    )
                    else "expected_results"
                ),

            "path":
                item["path"],

            "sha256":
                item["sha256"],
        }
        for item in profile[
            "source_inputs"
        ]
    ]

    if authority[
        "required_source_files"
    ] != expected_sources:
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    profile_cases = {
        (
            item["parameter_set"],
            int(item["tg_id"]),
            int(item["tc_id"]),
            bool(item["expected_valid"]),
        )
        for item in profile[
            "selected_cases"
        ]
    }

    contract_cases = {
        (
            item["parameter_set"],
            int(
                item[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tg_id"
                ]
            ),
            int(
                item[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tc_id"
                ]
            ),
            bool(
                item[
                    "expected_valid"
                ]
            ),
        )
        for item in contract[
            "covered_fixtures"
        ]
    }

    if contract_cases != profile_cases:
        raise GateFailure(
            "SIX_CASE_AUTHORITY_MISMATCH"
        )


def covered_fixture_entry(
    contract,
    fixture_rel,
):
    matches = [
        item
        for item in contract[
            "covered_fixtures"
        ]
        if item["path"] == fixture_rel
    ]

    if len(matches) != 1:
        raise GateFailure(
            "FIXTURE_NOT_COVERED_BY_SUCCESSOR"
        )

    return matches[0]


def expected_fixture_source_files(
    fixture,
    contract,
):
    binding = fixture[
        "source_binding"
    ]

    if binding[
        "source_family"
    ] != "nist_acvp":
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    authority = contract[
        "source_authorities"
    ][
        "nist_acvp"
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
            "role":
                item["role"],

            "path":
                item["path"],

            "sha256":
                item["sha256"],
        }
        for item in authority[
            "required_source_files"
        ]
    ]

    if binding[
        "source_files"
    ] != expected:
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

    return expected


def validate_fixture_metadata(
    root,
    fixture_rel,
    contract,
):
    target = safe_repo_path(
        root,
        fixture_rel,
    )

    if not target.is_file():
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    entry = covered_fixture_entry(
        contract,
        fixture_rel,
    )

    observed_fixture_sha = sha256_file(
        target
    )

    if observed_fixture_sha != entry[
        "sha256"
    ]:
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    fixture = load_json(
        target
    )

    schema = load_json(
        safe_repo_path(
            root,
            FIXTURE_SCHEMA_REL,
        )
    )

    if schema.get("$id") != (
        "urn:qsv:mldsa:fixture:0.3"
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if (
        fixture.get("schema")
        != "qsv.mldsa.fixture.v0.3"
        or
        fixture.get("algorithm")
        != "ML-DSA"
        or
        fixture.get("parameter_set")
        != entry["parameter_set"]
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    expected_outcome = (
        "accept"
        if entry[
            "expected_valid"
        ]
        else "reject"
    )

    if fixture.get(
        "expected_outcome"
    ) != expected_outcome:
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    if fixture[
        "source_binding"
    ][
        "case_identity"
    ] != entry[
        "case_identity"
    ]:
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    canonicalization = fixture[
        "source_binding"
    ][
        "canonicalization"
    ]

    canon_target = safe_repo_path(
        root,
        CANONICALIZATION_CONTRACT_REL,
    )

    if (
        canonicalization[
            "contract_path"
        ]
        != CANONICALIZATION_CONTRACT_REL
        or
        canonicalization[
            "contract_sha256"
        ]
        != sha256_file(
            canon_target
        )
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

    if fixture[
        "source_binding"
    ][
        "case_source_sha256"
    ] != domain_hash(
        CASE_DOMAIN,
        case_descriptor(
            fixture
        ),
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    if fixture[
        "neutral_fixture_sha256"
    ] != fixture_hash(
        fixture
    ):
        raise GateFailure(
            "FIXTURE_METADATA_VALIDATION_FAILED"
        )

    return {
        "fixture":
            fixture,

        "fixture_target":
            target,

        "fixture_rel":
            fixture_rel,

        "fixture_sha256":
            observed_fixture_sha,

        "entry":
            entry,

        "source_files":
            expected_sources,
    }


def observed_source_files(
    metadata,
    args,
):
    if (
        args.nist_prompt is None
        or
        args.nist_expected is None
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


def regenerate_nist(
    root,
    metadata,
    observed,
):
    mapper = safe_repo_path(
        root,
        ACVP_MAPPER_REL,
    )

    if not mapper.is_file():
        raise GateBlocked(
            "PREREQUISITE_UNAVAILABLE"
        )

    targets = {
        item["role"]:
            item["_local_target"]
        for item in observed
    }

    fixture = metadata[
        "fixture"
    ]

    coordinates = fixture[
        "source_binding"
    ][
        "case_identity"
    ][
        "coordinates"
    ]

    env = dict(
        os.environ
    )

    env.pop(
        "QSV_EXECUTE_CRYPTO",
        None,
    )

    env[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    with tempfile.TemporaryDirectory(
        prefix="qsv-sb2r-acvp-"
    ) as temp_name:

        temp_root = Path(
            temp_name
        )

        run1 = temp_root / "run1.json"
        run2 = temp_root / "run2.json"

        base = [
            sys.executable,
            str(mapper),
            "--root",
            str(root),
            "--prompt",
            str(
                targets[
                    "prompt"
                ]
            ),
            "--expected",
            str(
                targets[
                    "expected_results"
                ]
            ),
            "--parameter-set",
            fixture[
                "parameter_set"
            ],
            "--tg-id",
            str(
                coordinates[
                    "tg_id"
                ]
            ),
            "--tc-id",
            str(
                coordinates[
                    "tc_id"
                ]
            ),
        ]

        for output in [
            run1,
            run2,
        ]:
            proc = subprocess.run(
                base
                + [
                    "--output",
                    str(output),
                ],
                cwd=str(root),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                check=False,
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


def public_source_files(
    expected,
    observed=None,
):
    observed_by_role = {}

    if observed is not None:
        observed_by_role = {
            item["role"]:
                item
            for item in observed
        }

    result = []

    for item in expected:
        match = observed_by_role.get(
            item["role"]
        )

        result.append(
            {
                "role":
                    item["role"],

                "path":
                    item["path"],

                "expected_sha256":
                    item["sha256"],

                "observed_sha256":
                    (
                        match[
                            "observed_sha256"
                        ]
                        if match is not None
                        else None
                    ),

                "verification_status":
                    (
                        match[
                            "verification_status"
                        ]
                        if match is not None
                        else "NOT_VERIFIED"
                    ),
            }
        )

    return result


def build_case_record(
    root,
    metadata,
    requested,
    observed,
    regeneration,
    state,
    reason,
):
    contract_sha = sha256_file(
        safe_repo_path(
            root,
            CONTRACT_REL,
        )
    )

    entry = metadata[
        "entry"
    ]

    return {
        "schema":
            "qsv.mldsa."
            "source-bound-acceptance.v0.2",

        "record_kind":
            "case_acceptance",

        "authority_binding": {
            "contract_path":
                CONTRACT_REL,

            "contract_sha256":
                contract_sha,
        },

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
                "nist_acvp",

            "repository":
                metadata[
                    "fixture"
                ][
                    "source_binding"
                ][
                    "source_repository"
                ],

            "commit":
                metadata[
                    "fixture"
                ][
                    "source_binding"
                ][
                    "source_commit"
                ],

            "tree":
                metadata[
                    "fixture"
                ][
                    "source_binding"
                ][
                    "source_tree"
                ],

            "tree_status":
                metadata[
                    "fixture"
                ][
                    "source_binding"
                ][
                    "source_tree_status"
                ],
        },

        "source_files":
            public_source_files(
                metadata[
                    "source_files"
                ],
                observed,
            ),

        "case_identity":
            expected_identity(
                entry
            ),

        "regeneration":
            regeneration,

        "published_fixture": {
            "path":
                metadata[
                    "fixture_rel"
                ],

            "sha256":
                metadata[
                    "fixture_sha256"
                ],
        },

        "source_bound_verification_state":
            state,

        "reason_code":
            reason,

        "execution_boundary":
            dict(
                EXECUTION_BOUNDARY
            ),

        "claim_boundary":
            dict(
                CLAIM_BOUNDARY
            ),
    }


def validate_case_record(
    root,
    record,
    contract,
):
    required = {
        "schema",
        "record_kind",
        "authority_binding",
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
        "execution_boundary",
        "claim_boundary",
    }

    if set(record) != required:
        raise GateFailure(
            "CASE_RECORD_FIELDSET_MISMATCH"
        )

    if (
        record["schema"]
        != "qsv.mldsa.source-bound-acceptance.v0.2"
        or
        record["record_kind"]
        != "case_acceptance"
    ):
        raise GateFailure(
            "CASE_RECORD_SCHEMA_MISMATCH"
        )

    expected_authority = {
        "contract_path":
            CONTRACT_REL,

        "contract_sha256":
            sha256_file(
                safe_repo_path(
                    root,
                    CONTRACT_REL,
                )
            ),
    }

    if record[
        "authority_binding"
    ] != expected_authority:
        raise GateFailure(
            "AUTHORITY_BINDING_MISMATCH"
        )

    if record[
        "execution_boundary"
    ] != EXECUTION_BOUNDARY:
        raise GateFailure(
            "EXECUTION_BOUNDARY_MISMATCH"
        )

    if record[
        "claim_boundary"
    ] != CLAIM_BOUNDARY:
        raise GateFailure(
            "CLAIM_BOUNDARY_MISMATCH"
        )

    published = record[
        "published_fixture"
    ]

    entry = covered_fixture_entry(
        contract,
        published["path"],
    )

    if published[
        "sha256"
    ] != entry[
        "sha256"
    ]:
        raise GateFailure(
            "FIXTURE_BINDING_MISMATCH"
        )

    if record[
        "case_identity"
    ] != expected_identity(
        entry
    ):
        raise GateFailure(
            "CASE_IDENTITY_MISMATCH"
        )

    nist_authority = contract[
        "source_authorities"
    ][
        "nist_acvp"
    ]

    expected_source_authority = {
        "source_family":
            "nist_acvp",

        "repository":
            nist_authority[
                "repository"
            ],

        "commit":
            nist_authority[
                "commit"
            ],

        "tree":
            nist_authority[
                "tree"
            ],

        "tree_status":
            nist_authority[
                "tree_status"
            ],
    }

    if record[
        "source_authority"
    ] != expected_source_authority:
        raise GateFailure(
            "SOURCE_AUTHORITY_MISMATCH"
        )

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
            record[
                "reason_code"
            ] != "NOT_REQUESTED"
            or
            regeneration[
                "performed"
            ] is not False
            or
            regeneration[
                "comparison_mode"
            ] is not None
            or
            regeneration[
                "run1_equals_run2"
            ] is not None
            or
            regeneration[
                "regenerated_fixture_match"
            ] is not None
        ):
            raise GateFailure(
                "METADATA_ONLY_STATE_MISMATCH"
            )

        return entry

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
            ] != "PASS"
            or
            record[
                "reason_code"
            ] != "PASS"
            or
            regeneration[
                "performed"
            ] is not True
            or
            regeneration[
                "comparison_mode"
            ] != (
                "byte_identical_serialized_file_bytes"
            )
            or
            regeneration[
                "run1_equals_run2"
            ] is not True
            or
            regeneration[
                "regenerated_fixture_match"
            ] is not True
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
                ] != "MATCH"
                or
                item[
                    "observed_sha256"
                ] != item[
                    "expected_sha256"
                ]
            ):
                raise GateFailure(
                    "FORGED_SOURCE_BOUND_PASS"
                )

    return entry


def load_manifest(
    root,
    contract,
):
    verify_sidecar(
        root,
        COVERAGE_MANIFEST_REL,
    )

    target = safe_repo_path(
        root,
        COVERAGE_MANIFEST_REL,
    )

    manifest = load_json(
        target
    )

    required = {
        "schema",
        "version",
        "authority_binding",
        "meaning",
        "semantics",
        "cases",
    }

    if set(manifest) != required:
        raise GateFailure(
            "COVERAGE_MANIFEST_FIELDSET_MISMATCH"
        )

    if manifest[
        "schema"
    ] != (
        "qsv.mldsa."
        "f7-sixcase-neutral-fixture-coverage-manifest.v0.1"
    ):
        raise GateFailure(
            "COVERAGE_MANIFEST_SCHEMA_MISMATCH"
        )

    if manifest[
        "version"
    ] != "0.1":
        raise GateFailure(
            "COVERAGE_MANIFEST_VERSION_MISMATCH"
        )

    if manifest[
        "authority_binding"
    ] != {
        "contract_path":
            CONTRACT_REL,

        "contract_sha256":
            sha256_file(
                safe_repo_path(
                    root,
                    CONTRACT_REL,
                )
            ),
    }:
        raise GateFailure(
            "COVERAGE_MANIFEST_AUTHORITY_MISMATCH"
        )

    semantics = manifest[
        "semantics"
    ]

    if semantics != {
        "published_neutral_fixture_authority":
            True,

        "source_bound_acceptance":
            False,

        "crypto_correctness":
            False,

        "nist_validation":
            False,

        "fips_certification":
            False,
    }:
        raise GateFailure(
            "COVERAGE_MANIFEST_FALSE_CLAIM"
        )

    if manifest[
        "meaning"
    ] != (
        "published_neutral_fixture_authority_exists_for_exact_six_selected_f7_acvp_cases"
    ):
        raise GateFailure(
            "COVERAGE_MANIFEST_MEANING_MISMATCH"
        )

    cases = manifest[
        "cases"
    ]

    if len(cases) != 6:
        raise GateFailure(
            "COVERAGE_MANIFEST_CASE_COUNT_MISMATCH"
        )

    contract_entries = {
        item["path"]:
            item
        for item in contract[
            "covered_fixtures"
        ]
    }

    seen = set()

    for item in cases:
        fixture_rel = item.get(
            "fixture_path"
        )

        if fixture_rel in seen:
            raise GateFailure(
                "COVERAGE_MANIFEST_DUPLICATE_CASE"
            )

        seen.add(
            fixture_rel
        )

        if fixture_rel not in contract_entries:
            raise GateFailure(
                "COVERAGE_MANIFEST_EXTRA_CASE"
            )

        expected = contract_entries[
            fixture_rel
        ]

        expected_case = {
            "parameter_set":
                expected[
                    "parameter_set"
                ],

            "case_identity":
                expected[
                    "case_identity"
                ],

            "expected_valid":
                expected[
                    "expected_valid"
                ],

            "fixture_path":
                expected[
                    "path"
                ],

            "fixture_sha256":
                expected[
                    "sha256"
                ],
        }

        if item != expected_case:
            raise GateFailure(
                "COVERAGE_MANIFEST_FIXTURE_BINDING_MISMATCH"
            )

    if seen != set(
        contract_entries
    ):
        raise GateFailure(
            "COVERAGE_MANIFEST_MISSING_CASE"
        )

    return {
        "manifest":
            manifest,

        "sha256":
            sha256_file(
                target
            ),
    }


def write_record(
    target,
    record,
):
    if target.exists():
        raise GateFailure(
            "OUTPUT_ALREADY_EXISTS"
        )

    target.write_bytes(
        canonical_bytes(
            record
        )
    )


def run_case(
    args,
    root,
    contract,
):
    if args.fixture is None:
        raise GateFailure(
            "FIXTURE_REQUIRED"
        )

    load_manifest(
        root,
        contract,
    )

    metadata = validate_fixture_metadata(
        root,
        args.fixture,
        contract,
    )

    requested = (
        args.source_bound_requested
        == "yes"
    )

    any_sources = (
        args.nist_prompt is not None
        or
        args.nist_expected is not None
    )

    if not requested:
        if any_sources:
            raise GateBlocked(
                "SOURCE_INPUTS_SUPPLIED_WITHOUT_REQUEST"
            )

        regeneration = {
            "performed":
                False,

            "comparison_mode":
                None,

            "run1_equals_run2":
                None,

            "regenerated_fixture_match":
                None,
        }

        record = build_case_record(
            root,
            metadata,
            False,
            None,
            regeneration,
            None,
            "NOT_REQUESTED",
        )

        validate_case_record(
            root,
            record,
            contract,
        )

        if args.output is not None:
            write_record(
                Path(
                    args.output
                ).resolve(),
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

        return

    observed = observed_source_files(
        metadata,
        args,
    )

    expected_mode = contract[
        "comparison_policies"
    ][
        "nist_acvp"
    ][
        "mode"
    ]

    comparison_mode = (
        args.comparison_mode
        if args.comparison_mode is not None
        else expected_mode
    )

    if comparison_mode != expected_mode:
        raise GateFailure(
            "SOURCE_FAMILY_COMPARISON_POLICY_MISMATCH"
        )

    regeneration = regenerate_nist(
        root,
        metadata,
        observed,
    )

    record = build_case_record(
        root,
        metadata,
        True,
        observed,
        regeneration,
        "PASS",
        "PASS",
    )

    validate_case_record(
        root,
        record,
        contract,
    )

    if args.output is not None:
        write_record(
            Path(
                args.output
            ).resolve(),
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


def aggregate_key(
    identity,
):
    return (
        identity[
            "parameter_set"
        ],

        identity[
            "coordinates"
        ][
            "tg_id"
        ],

        identity[
            "coordinates"
        ][
            "tc_id"
        ],

        identity[
            "expected_valid"
        ],
    )


def run_aggregate(
    args,
    root,
    contract,
):
    manifest = load_manifest(
        root,
        contract,
    )

    expected_entries = contract[
        "covered_fixtures"
    ]

    expected_by_key = {
        aggregate_key(
            expected_identity(
                entry
            )
        ):
            entry
        for entry in expected_entries
    }

    provided = {}

    for rel in (
        args.case_record
        or []
    ):
        target = safe_repo_path(
            root,
            rel,
        )

        if not target.is_file():
            raise GateBlocked(
                "CASE_RECORD_MISSING"
            )

        record = load_json(
            target
        )

        entry = validate_case_record(
            root,
            record,
            contract,
        )

        key = aggregate_key(
            expected_identity(
                entry
            )
        )

        if key in provided:
            raise GateFailure(
                "DUPLICATE_CASE_IDENTITY"
            )

        if key not in expected_by_key:
            raise GateFailure(
                "CASE_IDENTITY_MISMATCH"
            )

        provided[key] = {
            "rel":
                rel,

            "sha256":
                sha256_file(
                    target
                ),

            "record":
                record,
        }

    if len(provided) > 6:
        raise GateFailure(
            "EXTRA_CASE_RECORD"
        )

    references = []
    states = []

    for entry in expected_entries:
        identity = expected_identity(
            entry
        )

        key = aggregate_key(
            identity
        )

        item = provided.get(
            key
        )

        if item is None:
            state = "MISSING"

            references.append(
                {
                    "case_identity":
                        identity,

                    "record_path":
                        None,

                    "record_sha256":
                        None,

                    "state":
                        state,
                }
            )

        else:
            record_state = item[
                "record"
            ][
                "source_bound_verification_state"
            ]

            state = (
                "NOT_REQUESTED"
                if record_state is None
                else record_state
            )

            references.append(
                {
                    "case_identity":
                        identity,

                    "record_path":
                        item[
                            "rel"
                        ],

                    "record_sha256":
                        item[
                            "sha256"
                        ],

                    "state":
                        state,
                }
            )

        states.append(
            state
        )

    if all(
        state == "PASS"
        for state in states
    ):
        aggregate_state = "PASS"
        reason = "PASS"
        global_acceptance = True
        complete = True

    elif any(
        state == "FAIL"
        for state in states
    ):
        aggregate_state = "FAIL"
        reason = "CASE_FAILURE"
        global_acceptance = False
        complete = False

    else:
        aggregate_state = "NOT_COMPLETE"
        reason = "NOT_COMPLETE"
        global_acceptance = False
        complete = False

    record = {
        "schema":
            "qsv.mldsa."
            "source-bound-acceptance.v0.2",

        "record_kind":
            "aggregate_summary",

        "authority_binding": {
            "contract_path":
                CONTRACT_REL,

            "contract_sha256":
                sha256_file(
                    safe_repo_path(
                        root,
                        CONTRACT_REL,
                    )
                ),
        },

        "case_scoped":
            False,

        "fixture_scoped":
            False,

        "aggregate_scoped":
            True,

        "expected_case_count":
            6,

        "case_record_references":
            references,

        "aggregate_state":
            aggregate_state,

        "aggregate_reason_code":
            reason,

        "global_f7_source_bound_acceptance":
            global_acceptance,

        "source_bound_acceptance_complete":
            complete,

        "coverage_manifest_binding": {
            "path":
                COVERAGE_MANIFEST_REL,

            "sha256":
                manifest[
                    "sha256"
                ],
        },

        "execution_boundary":
            dict(
                EXECUTION_BOUNDARY
            ),

        "claim_boundary":
            dict(
                CLAIM_BOUNDARY
            ),
    }

    if args.output is not None:
        write_record(
            Path(
                args.output
            ).resolve(),
            record,
        )

    print(
        "AGGREGATE_STATE="
        + aggregate_state
    )

    print(
        "GLOBAL_F7_SOURCE_BOUND_ACCEPTANCE="
        + (
            "YES"
            if global_acceptance
            else "NO"
        )
    )

    print(
        "SOURCE_BOUND_ACCEPTANCE_COMPLETE="
        + (
            "YES"
            if complete
            else "NO"
        )
    )


def run(args):
    if "QSV_EXECUTE_CRYPTO" in os.environ:
        raise GateFailure(
            "QSV_EXECUTE_CRYPTO_PRESENT"
        )

    root = Path(
        args.root
    ).resolve()

    contract = load_contract(
        root
    )

    validate_contract_against_existing_authorities(
        root,
        contract,
    )

    if args.mode == "case":
        run_case(
            args,
            root,
            contract,
        )

    elif args.mode == "aggregate":
        run_aggregate(
            args,
            root,
            contract,
        )

    else:
        raise GateFailure(
            "MODE_INVALID"
        )

    print(
        "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER_V0_2=PASS"
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
        "--mode",
        choices=[
            "case",
            "aggregate",
        ],
        default="case",
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
        "--comparison-mode",
    )

    parser.add_argument(
        "--case-record",
        action="append",
    )

    parser.add_argument(
        "--output",
    )

    args = parser.parse_args()

    try:
        run(
            args
        )

    except GateBlocked as exc:
        print(
            "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER_V0_2=FAIL"
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
            "QSV_MLDSA_SOURCE_BOUND_ACCEPTANCE_VERIFIER_V0_2=FAIL"
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
