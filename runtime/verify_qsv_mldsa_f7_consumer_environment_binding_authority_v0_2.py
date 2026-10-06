#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path


PREDECESSOR_COMMIT = (
    "00f0d3cfbc6f6fef2e9eb3cec450dbe9af76497a"
)

PREDECESSOR_TREE = (
    "b7603a2cc969ca171b3f43425b33f6d6f413ce25"
)

CONSUMER_SCHEMA = (
    "schemas/qsv-mldsa-consumer-identity-v0.1.schema.json"
)

OPENSSL_CONSUMER = (
    "manifest/qsv-mldsa-f7-consumer-identity-openssl-v0.1.json"
)

CIRCL_CONSUMER = (
    "manifest/qsv-mldsa-f7-consumer-identity-cloudflare-circl-v0.1.json"
)

ENV_AUTHORITY = (
    "contracts/qsv-mldsa-f7-source-bound-execution-environment-authority-v0.1.json"
)

BINDING_MANIFEST = (
    "manifest/qsv-mldsa-f7-consumer-environment-binding-authority-v0.1-manifest.json"
)

EXPECTED_BINDING_MANIFEST_SHA256 = (
    "0c11378155fb948ef86d9f2b8bae1719e99c8fb5d719ab5dab4e6f20dab81b42"
)

PROSPECTIVE_AUTHORITY = (
    "contracts/"
    "qsv-mldsa-f7-prospective-python-execution-authority-v0.1.json"
)

CAPTURE_CONTROLLER = (
    "runtime/"
    "capture_qsv_mldsa_f7_prospective_python_execution_authority_v0_1.py"
)

EXACT_INVOCATION_LAUNCHER = (
    "runtime/"
    "run_qsv_mldsa_f7_source_bound_acceptance_with_python_authority_v0_1.py"
)

BINDING_MANIFEST_SIDECAR = (
    BINDING_MANIFEST + ".sha256"
)

SELF_PATH = (
    "runtime/verify_qsv_mldsa_f7_consumer_environment_binding_authority_v0_2.py"
)

SELF_SIDECAR = (
    SELF_PATH + ".sha256"
)

V02_CONTRACT = (
    "contracts/qsv-mldsa-source-bound-acceptance-contract-v0.2.json"
)

V02_SCHEMA = (
    "schemas/qsv-mldsa-source-bound-acceptance-v0.2.schema.json"
)

V02_VERIFIER = (
    "runtime/verify_qsv_mldsa_source_bound_acceptance_v0_2.py"
)

MAPPER = (
    "runtime/qsv_mldsa_acvp_to_neutral_fixture_mapper_v0_1.py"
)

PATH_AUTHORITY = (
    "manifest/qsv-mldsa-f7-source-bound-acceptance-evidence-path-authority-v0.1-manifest.json"
)

COVERAGE_MANIFEST = (
    "manifest/qsv-mldsa-f7-sixcase-neutral-fixture-coverage-v0.1-manifest.json"
)

SOURCE_LINEAGE = (
    "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json"
)

RUNTIME_EVIDENCE = (
    "results/qsv_mldsa_f7_runtime_invocation_evidence_v0_1/"
    "qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json"
)

NORMALIZED_EVIDENCE = (
    "results/qsv_mldsa_f7_normalized_result_evidence_v0_1/"
    "qsv_mldsa_f7_normalized_result_evidence_v0_1.json"
)

NORMALIZED_ADAPTER = (
    "runtime/qsv_mldsa_normalized_result_adapter_v0_1.py"
)

EXPECTED_STDLIB = [
    "argparse",
    "copy",
    "hashlib",
    "json",
    "os",
    "pathlib",
    "re",
    "subprocess",
    "sys",
    "tempfile",
]

EXPECTED_NIST_REPOSITORY = (
    "https://github.com/usnistgov/ACVP-Server.git"
)

EXPECTED_NIST_COMMIT = (
    "975de31eb83d87039ec88934fdc47d8c312b892d"
)

EXPECTED_NIST_TREE = (
    "a6b81add7faf8a8b647afcdc54268615decde9b5"
)

EXPECTED_NIST_PROMPT_SHA = (
    "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"
)

EXPECTED_NIST_EXPECTED_SHA = (
    "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6"
)

EXPECTED_RUN_ID = "34968252038"
EXPECTED_JOB_ID = 104377847614
EXPECTED_EXECUTION_COMMIT = (
    "e7c2f85a6cdf49c39a42cccdd96ba6ab1a8da6cd"
)

HEX40 = re.compile(
    r"^[0-9a-f]{40}$"
)

HEX64 = re.compile(
    r"^[0-9a-f]{64}$"
)


class GateFailure(Exception):
    pass


def sha256_bytes(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(path):
    return sha256_bytes(
        path.read_bytes()
    )


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def git(root, args):
    proc = subprocess.run(
        [
            "/usr/bin/git",
            *args,
        ],
        cwd=str(root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=os.environ.copy(),
    )

    if proc.returncode != 0:
        raise GateFailure(
            "GIT_QUERY_FAILURE:"
            + " ".join(args)
        )

    return proc.stdout.decode(
        "utf-8",
        "surrogateescape",
    ).strip()


def safe_path(root, rel):
    if (
        not isinstance(rel, str)
        or not rel
        or rel.startswith("/")
        or "\\" in rel
        or "//" in rel
        or any(
            part in ("", ".", "..")
            for part in rel.split("/")
        )
    ):
        raise GateFailure(
            "UNSAFE_PATH:"
            + str(rel)
        )

    root = root.resolve()

    target = (
        root
        / rel
    ).resolve()

    try:
        target.relative_to(
            root
        )
    except ValueError:
        raise GateFailure(
            "PATH_ESCAPE:"
            + rel
        )

    return target


def validate_prospective_python_authority(doc):
    if not isinstance(doc, dict):
        raise GateFailure(
            "PROSPECTIVE_AUTHORITY_DOCUMENT_TYPE_MISMATCH"
        )

    captured = doc.get(
        "captured"
    )

    if not isinstance(
        captured,
        dict,
    ):
        raise GateFailure(
            "PROSPECTIVE_CAPTURED_OBJECT_MISMATCH"
        )

    candidate = captured.get(
        "candidate"
    )

    if not isinstance(
        candidate,
        dict,
    ):
        raise GateFailure(
            "PROSPECTIVE_CANDIDATE_OBJECT_MISMATCH"
        )

    non_guarantees = doc.get(
        "non_guarantees"
    )

    if not isinstance(
        non_guarantees,
        dict,
    ):
        raise GateFailure(
            "PROSPECTIVE_NON_GUARANTEES_OBJECT_MISMATCH"
        )

    if doc.get(
        "role"
    ) != (
        "PROSPECTIVE_PRE_EXECUTION_PYTHON_EXECUTION_AUTHORITY"
    ):
        raise GateFailure(
            "PROSPECTIVE_AUTHORITY_ROLE_MISMATCH"
        )

    if doc.get(
        "prospective"
    ) is not True:
        raise GateFailure(
            "PROSPECTIVE_AUTHORITY_FLAG_MISMATCH"
        )

    if doc.get(
        "retroactive_claim"
    ) is not False:
        raise GateFailure(
            "PROSPECTIVE_RETROACTIVE_FLAG_MISMATCH"
        )

    if doc.get(
        "historical_f7_implementation_claimed"
    ) is not False:
        raise GateFailure(
            "PROSPECTIVE_HISTORICAL_IMPLEMENTATION_CLAIM_MISMATCH"
        )

    if candidate.get(
        "invocation_path"
    ) != (
        "/Users/motohiro/.pyenv/versions/3.10.14/bin/python3.10"
    ):
        raise GateFailure(
            "PROSPECTIVE_INVOCATION_PATH_MISMATCH"
        )

    if candidate.get(
        "invocation_path_is_symlink"
    ) is not False:
        raise GateFailure(
            "PROSPECTIVE_INTERPRETER_SYMLINK_FLAG_MISMATCH"
        )

    if candidate.get(
        "resolved_executable_path"
    ) != (
        "/Users/motohiro/.pyenv/versions/3.10.14/bin/python3.10"
    ):
        raise GateFailure(
            "PROSPECTIVE_RESOLVED_PATH_MISMATCH"
        )

    if candidate.get(
        "resolved_executable_sha256"
    ) != (
        "094f3e91845a17d403c59b020b877e3845b205cbb431e50032cce346e04d8e6a"
    ):
        raise GateFailure(
            "PROSPECTIVE_INTERPRETER_SHA256_MISMATCH"
        )

    if candidate.get(
        "sys_implementation_name"
    ) != "cpython":
        raise GateFailure(
            "PROSPECTIVE_IMPLEMENTATION_MISMATCH"
        )

    if candidate.get(
        "platform_python_implementation"
    ) != "CPython":
        raise GateFailure(
            "PROSPECTIVE_PLATFORM_IMPLEMENTATION_MISMATCH"
        )

    if candidate.get(
        "version_info"
    ) != [
        3,
        10,
        14,
    ]:
        raise GateFailure(
            "PROSPECTIVE_VERSION_INFO_MISMATCH"
        )

    if candidate.get(
        "platform_python_version"
    ) != "3.10.14":
        raise GateFailure(
            "PROSPECTIVE_PLATFORM_VERSION_MISMATCH"
        )

    if non_guarantees.get(
        "executable_sha256_is_complete_runtime_provenance"
    ) is not False:
        raise GateFailure(
            "PROSPECTIVE_RUNTIME_PROVENANCE_BOUNDARY_MISMATCH"
        )

    if non_guarantees.get(
        "python_source_to_runtime_provenance_proven"
    ) is not False:
        raise GateFailure(
            "PROSPECTIVE_SOURCE_RUNTIME_BOUNDARY_MISMATCH"
        )


def verify_hash_bound_reference(
    root,
    reference,
    expected_path,
):
    if not isinstance(
        reference,
        dict,
    ):
        raise GateFailure(
            "HASH_BOUND_REFERENCE_NOT_OBJECT:"
            + str(expected_path)
        )

    if set(reference) != {
        "path",
        "sha256",
    }:
        raise GateFailure(
            "HASH_BOUND_REFERENCE_KEY_SET_MISMATCH:"
            + str(expected_path)
        )

    if reference[
        "path"
    ] != expected_path:
        raise GateFailure(
            "HASH_BOUND_REFERENCE_PATH_MISMATCH:"
            + str(expected_path)
        )

    expected_sha = reference[
        "sha256"
    ]

    if (
        not isinstance(
            expected_sha,
            str,
        )
        or HEX64.fullmatch(
            expected_sha
        )
        is None
    ):
        raise GateFailure(
            "HASH_BOUND_REFERENCE_SHA256_FORMAT_INVALID:"
            + str(expected_path)
        )

    target = safe_path(
        root,
        reference[
            "path"
        ],
    )

    lexical_target = (
        root.resolve()
        / reference[
            "path"
        ]
    )

    if lexical_target.is_symlink():
        raise GateFailure(
            "HASH_BOUND_REFERENCE_SYMLINK_REJECTED:"
            + str(expected_path)
        )

    if (
        not lexical_target.is_file()
        or not target.is_file()
    ):
        raise GateFailure(
            "HASH_BOUND_REFERENCE_NOT_REGULAR_FILE:"
            + str(expected_path)
        )

    if sha256_file(
        target
    ) != expected_sha:
        raise GateFailure(
            "HASH_BOUND_REFERENCE_SHA256_MISMATCH:"
            + str(expected_path)
        )

    return target


def parse_sidecar(path):
    text = path.read_text(
        encoding="utf-8"
    )

    match = re.fullmatch(
        r"([0-9a-f]{64})  ([^\r\n]+)\n",
        text,
    )

    if match is None:
        raise GateFailure(
            "SIDECAR_FORMAT_INVALID:"
            + str(path)
        )

    return (
        match.group(1),
        match.group(2),
    )


def runtime_summary(runtime, implementation):
    rows = [
        row
        for row
        in runtime["invocations"]
        if row.get(
            "implementation"
        )
        == implementation
    ]

    if len(rows) != 6:
        raise GateFailure(
            "RUNTIME_INVOCATION_COUNT_MISMATCH:"
            + implementation
        )

    versions = {
        row[
            "implementation_version"
        ]
        for row in rows
    }

    repositories = {
        row[
            "implementation_source_authority"
        ][
            "repository"
        ]
        for row in rows
    }

    commits = {
        row[
            "implementation_source_authority"
        ][
            "commit"
        ]
        for row in rows
    }

    trees = {
        row[
            "implementation_source_authority"
        ][
            "tree"
        ]
        for row in rows
    }

    executable_hashes = {
        row[
            "resolved_executable_sha256"
        ]
        for row in rows
    }

    if not (
        len(versions) == 1
        and len(repositories) == 1
        and len(commits) == 1
        and len(trees) == 1
        and len(executable_hashes) == 1
    ):
        raise GateFailure(
            "RUNTIME_IDENTITY_AMBIGUOUS:"
            + implementation
        )

    return {
        "version":
            next(
                iter(
                    versions
                )
            ),

        "repository":
            next(
                iter(
                    repositories
                )
            ),

        "commit":
            next(
                iter(
                    commits
                )
            ),

        "tree":
            next(
                iter(
                    trees
                )
            ),

        "executable_sha256":
            next(
                iter(
                    executable_hashes
                )
            ),
    }


def validate_predecessor(root):
    commit_type = git(
        root,
        [
            "cat-file",
            "-t",
            PREDECESSOR_COMMIT,
        ],
    )

    if commit_type != "commit":
        raise GateFailure(
            "PREDECESSOR_COMMIT_MISSING"
        )

    tree = git(
        root,
        [
            "rev-parse",
            PREDECESSOR_COMMIT
            + "^{tree}",
        ],
    )

    if tree != PREDECESSOR_TREE:
        raise GateFailure(
            "PREDECESSOR_TREE_MISMATCH"
        )

    return True


def expected_consumer_values(
    root,
    implementation,
):
    runtime = load_json(
        safe_path(
            root,
            RUNTIME_EVIDENCE,
        )
    )

    summary = runtime_summary(
        runtime,
        implementation,
    )

    lineage_sha = sha256_file(
        safe_path(
            root,
            SOURCE_LINEAGE,
        )
    )

    normalized = load_json(
        safe_path(
            root,
            NORMALIZED_EVIDENCE,
        )
    )

    adapter = normalized[
        "normalization_authority"
    ]

    equivalence = (
        "historical-f7-openssl-v0.1"
        if implementation
        == "openssl"
        else
        "historical-f7-cloudflare-circl-v0.1"
    )

    source_version = (
        "3.6.3"
        if implementation
        == "openssl"
        else None
    )

    return {
        "implementation_id":
            implementation,

        "repository":
            summary[
                "repository"
            ],

        "runtime_version":
            summary[
                "version"
            ],

        "runtime_executable_sha256":
            summary[
                "executable_sha256"
            ],

        "source_version":
            source_version,

        "source_commit":
            summary[
                "commit"
            ],

        "source_tree":
            summary[
                "tree"
            ],

        "lineage_sha256":
            lineage_sha,

        "equivalence_class":
            equivalence,

        "adapter_path":
            adapter[
                "adapter_path"
            ],

        "adapter_sha256":
            adapter[
                "adapter_sha256"
            ],
    }


def validate_consumer_document(
    root,
    record,
    implementation,
):
    if set(record) != {
        "schema",
        "consumer",
    }:
        raise GateFailure(
            "CONSUMER_RECORD_FIELDSET_MISMATCH"
        )

    if record["schema"] != (
        "qsv.mldsa.consumer-identity.v0.1"
    ):
        raise GateFailure(
            "CONSUMER_SCHEMA_MISMATCH"
        )

    consumer = record[
        "consumer"
    ]

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

    if implementation not in {
        "openssl",
        "cloudflare-circl",
    }:
        raise GateFailure(
            "UNKNOWN_CONSUMER"
        )

    expected = expected_consumer_values(
        root,
        implementation,
    )

    if (
        consumer[
            "implementation_id"
        ]
        != expected[
            "implementation_id"
        ]
    ):
        raise GateFailure(
            "IMPLEMENTATION_ID_MISMATCH"
        )

    if (
        consumer[
            "repository"
        ]
        != expected[
            "repository"
        ]
    ):
        raise GateFailure(
            "CONSUMER_REPOSITORY_MISMATCH"
        )

    runtime = consumer[
        "runtime_identity"
    ]

    if set(runtime) != {
        "version",
        "executable_sha256",
    }:
        raise GateFailure(
            "RUNTIME_IDENTITY_FIELDSET_MISMATCH"
        )

    if (
        runtime[
            "version"
        ]
        != expected[
            "runtime_version"
        ]
        or runtime[
            "executable_sha256"
        ]
        != expected[
            "runtime_executable_sha256"
        ]
    ):
        raise GateFailure(
            "RUNTIME_IDENTITY_MISMATCH"
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
            "SOURCE_IDENTITY_FIELDSET_MISMATCH"
        )

    if (
        source[
            "version"
        ]
        != expected[
            "source_version"
        ]
        or source[
            "commit"
        ]
        != expected[
            "source_commit"
        ]
        or source[
            "tree"
        ]
        != expected[
            "source_tree"
        ]
    ):
        raise GateFailure(
            "SOURCE_IDENTITY_MISMATCH"
        )

    if (
        consumer[
            "identity_basis"
        ]
        != (
            "runtime_version_and_source_commit"
        )
    ):
        raise GateFailure(
            "IDENTITY_BASIS_MISMATCH"
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
            "SOURCE_TO_RUNTIME_FIELDSET_MISMATCH"
        )

    if (
        source_runtime[
            "status"
        ]
        != "incomplete"
    ):
        raise GateFailure(
            "SOURCE_TO_RUNTIME_STATUS_PROMOTION"
        )

    if (
        source_runtime[
            "evidence_path"
        ]
        != SOURCE_LINEAGE
        or source_runtime[
            "evidence_sha256"
        ]
        != expected[
            "lineage_sha256"
        ]
    ):
        raise GateFailure(
            "SOURCE_TO_RUNTIME_EVIDENCE_MISMATCH"
        )

    lineage = consumer[
        "lineage"
    ]

    if set(lineage) != {
        "implementation_id",
        "binding_path",
        "binding_sha256",
        "equivalence_class",
    }:
        raise GateFailure(
            "LINEAGE_FIELDSET_MISMATCH"
        )

    if (
        lineage[
            "implementation_id"
        ]
        != implementation
        or lineage[
            "binding_path"
        ]
        != SOURCE_LINEAGE
        or lineage[
            "binding_sha256"
        ]
        != expected[
            "lineage_sha256"
        ]
        or lineage[
            "equivalence_class"
        ]
        != expected[
            "equivalence_class"
        ]
    ):
        raise GateFailure(
            "LINEAGE_IDENTITY_MISMATCH"
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
            "ADAPTER_FIELDSET_MISMATCH"
        )

    if (
        adapter[
            "path"
        ]
        != expected[
            "adapter_path"
        ]
        or adapter[
            "sha256"
        ]
        != expected[
            "adapter_sha256"
        ]
        or adapter[
            "schema_version"
        ]
        != "0.1"
    ):
        raise GateFailure(
            "ADAPTER_IDENTITY_MISMATCH"
        )

    return True


def validate_consumer_path(
    root,
    rel,
    implementation,
):
    return validate_consumer_document(
        root,
        load_json(
            safe_path(
                root,
                rel,
            )
        ),
        implementation,
    )


def validate_environment_document(
    root,
    doc,
    prospective_reference,
    prospective_doc,
    runtime_check=True,
):
    expected_top = {
        "schema",
        "version",
        "authority_role",
        "semantic_relationship",
        "predecessor_public_authority",
        "python_authority",
        "acceptance_components",
        "python_dependencies",
        "execution_semantics",
        "environment_policy",
        "source_acquisition_separation",
        "publication_semantics",
    }

    if set(doc) != expected_top:
        raise GateFailure(
            "ENVIRONMENT_FIELDSET_MISMATCH"
        )

    if (
        doc["schema"]
        != (
            "qsv.mldsa.f7."
            "source-bound-execution-environment-authority.v0.1"
        )
        or doc["version"] != "0.1"
        or doc[
            "authority_role"
        ]
        != (
            "SOURCE_BOUND_EXECUTION_"
            "ENVIRONMENT_AUTHORITY"
        )
        or doc[
            "semantic_relationship"
        ]
        != "extends_without_modifying"
    ):
        raise GateFailure(
            "ENVIRONMENT_METADATA_MISMATCH"
        )

    predecessor = doc[
        "predecessor_public_authority"
    ]

    if predecessor != {
        "commit":
            PREDECESSOR_COMMIT,
        "tree":
            PREDECESSOR_TREE,
    }:
        raise GateFailure(
            "ENVIRONMENT_PREDECESSOR_MISMATCH"
        )

    python = doc[
        "python_authority"
    ]

    historical = python.get(
        "historical_f7_boundary",
        {},
    )

    claim_boundary = python.get(
        "claim_boundary",
        {},
    )

    if (
        python.get(
            "authority_model"
        )
        != "BOUND_PROSPECTIVE_PYTHON_EXECUTION_AUTHORITY"
        or python.get(
            "authority_path"
        )
        != PROSPECTIVE_AUTHORITY
        or python.get(
            "authority_sha256"
        )
        != prospective_reference.get(
            "sha256"
        )
        or python.get(
            "required_authority_role"
        )
        != "PROSPECTIVE_PRE_EXECUTION_PYTHON_EXECUTION_AUTHORITY"
        or python.get(
            "required_prospective"
        )
        is not True
        or python.get(
            "required_retroactive_claim"
        )
        is not False
        or python.get(
            "required_historical_f7_implementation_claimed"
        )
        is not False
        or python.get(
            "selection_policy"
        )
        != "MINIMUM_SUFFICIENT_EXECUTION_BASELINE"
        or python.get(
            "project_declared_minimum_feature_baseline"
        )
        != "PYTHON_3_10_COMPATIBLE"
    ):
        raise GateFailure(
            "PYTHON_AUTHORITY_BINDING_MISMATCH"
        )

    if (
        historical.get(
            "public_historical_python_version_evidence"
        )
        != "Python 3.12.3"
        or historical.get(
            "public_historical_python_implementation_authority"
        )
        != "UNRESOLVED"
        or historical.get(
            "historical_f7_python_version_rewritten"
        )
        is not False
        or historical.get(
            "historical_f7_implementation_claimed"
        )
        is not False
        or historical.get(
            "retroactive_cpython_claim_allowed"
        )
        is not False
        or historical.get(
            "historical_runtime_fact_equals_future_execution_requirement"
        )
        is not False
    ):
        raise GateFailure(
            "ENVIRONMENT_HISTORICAL_BOUNDARY_MISMATCH"
        )

    if (
        claim_boundary.get(
            "prospective_authority_binding_is_historical_fact"
        )
        is not False
        or claim_boundary.get(
            "prospective_candidate_identity_applies_to_future_sb2r_execution_only"
        )
        is not True
        or claim_boundary.get(
            "environment_authority_independently_proves_python_identity"
        )
        is not False
    ):
        raise GateFailure(
            "ENVIRONMENT_CLAIM_BOUNDARY_MISMATCH"
        )

    validate_prospective_python_authority(
        prospective_doc
    )

    components = doc[
        "acceptance_components"
    ]

    if set(components) != {
        "verifier",
        "mapper",
    }:
        raise GateFailure(
            "ACCEPTANCE_COMPONENT_FIELDSET_MISMATCH"
        )

    for role, rel in [
        (
            "verifier",
            V02_VERIFIER,
        ),
        (
            "mapper",
            MAPPER,
        ),
    ]:
        target = components[
            role
        ]

        if (
            target.get(
                "path"
            )
            != rel
            or target.get(
                "sha256"
            )
            != sha256_file(
                safe_path(
                    root,
                    rel,
                )
            )
        ):
            raise GateFailure(
                "ACCEPTANCE_COMPONENT_MISMATCH:"
                + role
            )

    dependencies = doc[
        "python_dependencies"
    ]

    if (
        dependencies.get(
            "stdlib"
        )
        != EXPECTED_STDLIB
        or dependencies.get(
            "third_party"
        )
        != []
    ):
        raise GateFailure(
            "PYTHON_DEPENDENCY_MISMATCH"
        )

    local = dependencies.get(
        "repository_local"
    )

    if (
        not isinstance(
            local,
            list,
        )
        or len(local) != 1
        or local[0].get(
            "path"
        )
        != MAPPER
        or local[0].get(
            "sha256"
        )
        != sha256_file(
            safe_path(
                root,
                MAPPER,
            )
        )
    ):
        raise GateFailure(
            "REPOSITORY_LOCAL_DEPENDENCY_MISMATCH"
        )

    execution = doc[
        "execution_semantics"
    ]

    if execution != {
        "working_directory":
            "QSV_REPOSITORY_ROOT_AT_PUBLISHED_AUTHORITY",

        "working_directory_required":
            True,

        "subprocess_shell":
            False,

        "acceptance_computation_network_required":
            False,

        "os_authority_required":
            False,

        "cpu_arch_authority_required":
            False,
    }:
        raise GateFailure(
            "EXECUTION_SEMANTICS_MISMATCH"
        )

    environment = doc[
        "environment_policy"
    ]

    if (
        environment.get(
            "must_be_absent"
        )
        != [
            "QSV_EXECUTE_CRYPTO",
        ]
        or environment.get(
            "mapper_injected"
        )
        != {
            "PYTHONDONTWRITEBYTECODE":
                "1",
        }
        or environment.get(
            "other_inherited_variables_normative"
        )
        is not False
        or environment.get(
            "secret_dependency_count"
        )
        != 0
    ):
        raise GateFailure(
            "ENVIRONMENT_POLICY_MISMATCH"
        )

    source_separation = doc[
        "source_acquisition_separation"
    ]

    if source_separation != {
        "acquisition_external_to_acceptance_computation":
            True,

        "selected_method":
            (
                "CANONICAL_GIT_EXACT_COMMIT_FETCH_IN_"
                "EPHEMERAL_EXTERNAL_AUDIT_REPOSITORY"
            ),

        "github_api_required":
            False,

        "api_rate_limit_dependent":
            False,
    }:
        raise GateFailure(
            "SOURCE_ACQUISITION_SEPARATION_MISMATCH"
        )

    if runtime_check:
        if (
            Path.cwd().resolve()
            != root.resolve()
        ):
            raise GateFailure(
                "WORKING_DIRECTORY_MISMATCH"
            )

        if (
            "QSV_EXECUTE_CRYPTO"
            in os.environ
        ):
            raise GateFailure(
                "QSV_EXECUTE_CRYPTO_PRESENT"
            )

    return True
    return True


def validate_historical_scope(root):
    runtime = load_json(
        safe_path(
            root,
            RUNTIME_EVIDENCE,
        )
    )

    github = runtime[
        "github"
    ]

    if not (
        str(
            github[
                "github_run_id"
            ]
        )
        == EXPECTED_RUN_ID
        and github[
            "github_job_id_numeric"
        ]
        == EXPECTED_JOB_ID
        and github[
            "github_sha"
        ]
        == EXPECTED_EXECUTION_COMMIT
    ):
        raise GateFailure(
            "HISTORICAL_EXECUTION_IDENTITY_MISMATCH"
        )

    if (
        runtime[
            "execution_scope"
        ][
            "implementation_count"
        ]
        != 2
        or runtime[
            "execution_scope"
        ][
            "selected_case_count"
        ]
        != 6
        or runtime[
            "execution_scope"
        ][
            "process_invocation_count"
        ]
        != 12
    ):
        raise GateFailure(
            "HISTORICAL_EXECUTION_SCOPE_MISMATCH"
        )

    runtime_summary(
        runtime,
        "openssl",
    )

    runtime_summary(
        runtime,
        "cloudflare-circl",
    )

    return True


def validate_existing_path_authority(root):
    doc = load_json(
        safe_path(
            root,
            PATH_AUTHORITY,
        )
    )

    cases = doc.get(
        "case_records"
    )

    aggregate = doc.get(
        "aggregate_summary"
    )

    if (
        not isinstance(
            cases,
            list,
        )
        or len(cases) != 6
        or not isinstance(
            aggregate,
            dict,
        )
        or not isinstance(
            aggregate.get(
                "path"
            ),
            str,
        )
        or doc.get(
            "relationship_to_v0_2"
        )
        != (
            "APPEND_ONLY_EVIDENCE_"
            "PATH_AUTHORITY_EXTENSION"
        )
        or doc.get(
            "path_policy",
            {},
        ).get(
            "result_independent"
        )
        is not True
        or doc.get(
            "path_policy",
            {},
        ).get(
            "digest_dependency_acyclic"
        )
        is not True
    ):
        raise GateFailure(
            "PATH_AUTHORITY_INVALID"
        )

    paths = [
        item[
            "path"
        ]
        for item in cases
    ] + [
        aggregate[
            "path"
        ]
    ]

    if len(set(paths)) != 7:
        raise GateFailure(
            "PATH_AUTHORITY_DUPLICATE"
        )

    return True


def validate_binding_document(
    root,
    doc,
):
    expected_top = {
        "schema",
        "version",
        "authority_role",
        "relationship_to_v0_2",
        "semantic_relationship",
        "predecessor_public_authority",
        "bound_existing_authorities",
        "consumer_authorities",
        "execution_environment_authority",
        "execution_scope",
        "source_acquisition_policy",
        "existing_output_path_authority",
        "supplemental_verifier",
        "result_independence",
        "publication_semantics",
    }

    if set(doc) != expected_top:
        raise GateFailure(
            "BINDING_MANIFEST_FIELDSET_MISMATCH"
        )

    if (
        doc["schema"]
        != (
            "qsv.mldsa.f7."
            "consumer-environment-binding-authority.v0.1"
        )
        or doc["version"] != "0.1"
        or doc[
            "authority_role"
        ]
        != (
            "PREDECESSOR_BOUND_CONSUMER_"
            "ENVIRONMENT_BINDING_AUTHORITY"
        )
        or doc[
            "relationship_to_v0_2"
        ]
        != "SUPPLEMENTAL_PRE_EXECUTION_GATE"
        or doc[
            "semantic_relationship"
        ]
        != "extends_without_modifying"
    ):
        raise GateFailure(
            "BINDING_MANIFEST_METADATA_MISMATCH"
        )

    if doc[
        "predecessor_public_authority"
    ] != {
        "commit":
            PREDECESSOR_COMMIT,
        "tree":
            PREDECESSOR_TREE,
    }:
        raise GateFailure(
            "BINDING_PREDECESSOR_MISMATCH"
        )

    existing = doc[
        "bound_existing_authorities"
    ]

    expected_paths = {
        "consumer_schema":
            CONSUMER_SCHEMA,

        "source_bound_acceptance_contract":
            V02_CONTRACT,

        "source_bound_acceptance_schema":
            V02_SCHEMA,

        "source_bound_acceptance_verifier":
            V02_VERIFIER,

        "acceptance_evidence_path_authority":
            PATH_AUTHORITY,

        "six_case_coverage_manifest":
            COVERAGE_MANIFEST,

        "runtime_invocation_evidence":
            RUNTIME_EVIDENCE,

        "normalized_result_evidence":
            NORMALIZED_EVIDENCE,

        "source_lineage_binding":
            SOURCE_LINEAGE,

        "normalized_result_adapter":
            NORMALIZED_ADAPTER,
        "exact_invocation_launcher":
            EXACT_INVOCATION_LAUNCHER,

        "prospective_python_execution_authority":
            PROSPECTIVE_AUTHORITY,

        "prospective_python_execution_authority_capture_controller":
            CAPTURE_CONTROLLER,

    }

    if set(existing) != set(
        expected_paths
    ):
        raise GateFailure(
            "BOUND_AUTHORITY_SET_MISMATCH"
        )

    for key, rel in (
        expected_paths.items()
    ):
        item = existing[
            key
        ]

        if (
            item.get(
                "path"
            )
            != rel
            or item.get(
                "sha256"
            )
            != sha256_file(
                safe_path(
                    root,
                    rel,
                )
            )
        ):
            raise GateFailure(
                "BOUND_AUTHORITY_DIGEST_MISMATCH:"
                + key
            )

    consumers = doc[
        "consumer_authorities"
    ]

    if (
        not isinstance(
            consumers,
            list,
        )
        or len(consumers) != 2
    ):
        raise GateFailure(
            "CONSUMER_AUTHORITY_COUNT_MISMATCH"
        )

    expected_consumers = {
        "openssl":
            OPENSSL_CONSUMER,

        "cloudflare-circl":
            CIRCL_CONSUMER,
    }

    seen = set()

    for item in consumers:
        implementation = item.get(
            "implementation_id"
        )

        if implementation not in (
            expected_consumers
        ):
            raise GateFailure(
                "UNKNOWN_CONSUMER_AUTHORITY"
            )

        if implementation in seen:
            raise GateFailure(
                "DUPLICATE_CONSUMER_AUTHORITY"
            )

        seen.add(
            implementation
        )

        rel = expected_consumers[
            implementation
        ]

        if (
            item.get(
                "path"
            )
            != rel
            or item.get(
                "sha256"
            )
            != sha256_file(
                safe_path(
                    root,
                    rel,
                )
            )
            or item.get(
                "source_to_runtime_status"
            )
            != "incomplete"
        ):
            raise GateFailure(
                "CONSUMER_AUTHORITY_BINDING_MISMATCH:"
                + implementation
            )

    if seen != set(
        expected_consumers
    ):
        raise GateFailure(
            "CONSUMER_AUTHORITY_SCOPE_MISMATCH"
        )

    environment = doc[
        "execution_environment_authority"
    ]

    if (
        environment.get(
            "path"
        )
        != ENV_AUTHORITY
        or environment.get(
            "sha256"
        )
        != sha256_file(
            safe_path(
                root,
                ENV_AUTHORITY,
            )
        )
    ):
        raise GateFailure(
            "ENVIRONMENT_AUTHORITY_BINDING_MISMATCH"
        )

    scope = doc[
        "execution_scope"
    ]

    if scope != {
        "algorithm":
            "ML-DSA",

        "operation":
            "sigVer",

        "selected_case_count":
            6,

        "implementation_count":
            2,

        "historical_process_invocation_count":
            12,

        "consumer_cardinality":
            "ONE_CONSUMER_PER_IMPLEMENTATION",

        "required_consumers": [
            "openssl",
            "cloudflare-circl",
        ],

        "silent_scope_reduction_allowed":
            False,
    }:
        raise GateFailure(
            "EXECUTION_SCOPE_MISMATCH"
        )

    acquisition = doc[
        "source_acquisition_policy"
    ]

    if not (
        acquisition.get(
            "method"
        )
        == (
            "CANONICAL_GIT_EXACT_COMMIT_FETCH_IN_"
            "EPHEMERAL_EXTERNAL_AUDIT_REPOSITORY"
        )
        and acquisition.get(
            "repository"
        )
        == EXPECTED_NIST_REPOSITORY
        and acquisition.get(
            "commit"
        )
        == EXPECTED_NIST_COMMIT
        and acquisition.get(
            "tree"
        )
        == EXPECTED_NIST_TREE
        and acquisition.get(
            "prompt",
            {},
        ).get(
            "sha256"
        )
        == EXPECTED_NIST_PROMPT_SHA
        and acquisition.get(
            "expected_results",
            {},
        ).get(
            "sha256"
        )
        == EXPECTED_NIST_EXPECTED_SHA
        and acquisition.get(
            "github_api_required"
        )
        is False
        and acquisition.get(
            "latest_branch_substitution_allowed"
        )
        is False
        and acquisition.get(
            "latest_tag_substitution_allowed"
        )
        is False
        and acquisition.get(
            "unbound_mirror_allowed"
        )
        is False
        and acquisition.get(
            "unproven_local_cache_allowed"
        )
        is False
    ):
        raise GateFailure(
            "SOURCE_ACQUISITION_POLICY_MISMATCH"
        )

    output_authority = doc[
        "existing_output_path_authority"
    ]

    if (
        output_authority.get(
            "path"
        )
        != PATH_AUTHORITY
        or output_authority.get(
            "sha256"
        )
        != sha256_file(
            safe_path(
                root,
                PATH_AUTHORITY,
            )
        )
        or output_authority.get(
            "reusable"
        )
        is not True
    ):
        raise GateFailure(
            "OUTPUT_PATH_AUTHORITY_BINDING_MISMATCH"
        )

    independence = doc[
        "result_independence"
    ]

    if independence != {
        "consumer_authority_result_independent":
            True,

        "environment_authority_result_independent":
            True,

        "future_evidence_hash_precommitment":
            False,

        "dependency_acyclic":
            True,
    }:
        raise GateFailure(
            "RESULT_INDEPENDENCE_MISMATCH"
        )

    return True


def validate_sidecars(root):
    manifest_target = safe_path(
        root,
        BINDING_MANIFEST,
    )

    manifest_sidecar = safe_path(
        root,
        BINDING_MANIFEST_SIDECAR,
    )

    manifest_digest, manifest_rel = (
        parse_sidecar(
            manifest_sidecar
        )
    )

    if (
        manifest_rel
        != BINDING_MANIFEST
        or manifest_digest
        != sha256_file(
            manifest_target
        )
    ):
        raise GateFailure(
            "BINDING_MANIFEST_SIDECAR_MISMATCH"
        )

    self_target = safe_path(
        root,
        SELF_PATH,
    )

    self_sidecar = safe_path(
        root,
        SELF_SIDECAR,
    )

    self_digest, self_rel = (
        parse_sidecar(
            self_sidecar
        )
    )

    if (
        self_rel
        != SELF_PATH
        or self_digest
        != sha256_file(
            self_target
        )
    ):
        raise GateFailure(
            "VERIFIER_SIDECAR_MISMATCH"
        )

    return True


def validate_all(root):
    root = Path(root).resolve()

    if (
        "QSV_EXECUTE_CRYPTO"
        in os.environ
    ):
        raise GateFailure(
            "QSV_EXECUTE_CRYPTO_PRESENT"
        )

    validate_predecessor(
        root
    )

    validate_historical_scope(
        root
    )

    validate_existing_path_authority(
        root
    )

    validate_consumer_path(
        root,
        OPENSSL_CONSUMER,
        "openssl",
    )

    validate_consumer_path(
        root,
        CIRCL_CONSUMER,
        "cloudflare-circl",
    )

    manifest_path = safe_path(
        root,
        BINDING_MANIFEST,
    )

    if (
        sha256_file(
            manifest_path
        )
        != EXPECTED_BINDING_MANIFEST_SHA256
    ):
        raise GateFailure(
            "BINDING_MANIFEST_SHA256_MISMATCH"
        )

    manifest_doc = load_json(
        manifest_path
    )

    validate_binding_document(
        root,
        manifest_doc,
    )

    bound = manifest_doc[
        "bound_existing_authorities"
    ]

    environment_reference = manifest_doc[
        "execution_environment_authority"
    ]

    prospective_reference = bound[
        "prospective_python_execution_authority"
    ]

    controller_reference = bound[
        "prospective_python_execution_authority_capture_controller"
    ]

    launcher_reference = bound[
        "exact_invocation_launcher"
    ]

    environment_path = verify_hash_bound_reference(
        root,
        environment_reference,
        ENV_AUTHORITY,
    )

    prospective_path = verify_hash_bound_reference(
        root,
        prospective_reference,
        PROSPECTIVE_AUTHORITY,
    )

    verify_hash_bound_reference(
        root,
        controller_reference,
        CAPTURE_CONTROLLER,
    )

    verify_hash_bound_reference(
        root,
        launcher_reference,
        EXACT_INVOCATION_LAUNCHER,
    )

    environment_doc = load_json(
        environment_path
    )

    prospective_doc = load_json(
        prospective_path
    )

    if (
        environment_doc[
            "python_authority"
        ].get(
            "authority_path"
        )
        != prospective_reference.get(
            "path"
        )
        or environment_doc[
            "python_authority"
        ].get(
            "authority_sha256"
        )
        != prospective_reference.get(
            "sha256"
        )
    ):
        raise GateFailure(
            "ENVIRONMENT_PROSPECTIVE_AUTHORITY_CROSS_BINDING_MISMATCH"
        )

    validate_environment_document(
        root,
        environment_doc,
        prospective_reference,
        prospective_doc,
        runtime_check=True,
    )

    validate_sidecars(
        root
    )

    return True


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        required=True,
    )

    args = parser.parse_args()

    try:
        validate_all(
            args.root
        )

    except (
        GateFailure,
        AssertionError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(
            "QSV_MLDSA_F7_CONSUMER_ENVIRONMENT_BINDING_VERIFIER=FAIL"
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
            "VERIFIER_NETWORK_FETCH=NO"
        )

        print(
            "CRYPTO_EXECUTION_PERFORMED=NO"
        )

        print(
            "SOURCE_BOUND_ACCEPTANCE_EXECUTED=NO"
        )

        raise SystemExit(1)

    print(
        "QSV_MLDSA_F7_CONSUMER_ENVIRONMENT_BINDING_VERIFIER=PASS"
    )

    print(
        "PREDECESSOR_BINDING=PASS"
    )

    print(
        "OPENSSL_CONSUMER_IDENTITY=PASS"
    )

    print(
        "CIRCL_CONSUMER_IDENTITY=PASS"
    )

    print(
        "EXECUTION_ENVIRONMENT_AUTHORITY=PASS"
    )

    print(
        "EXISTING_SEVEN_PATH_AUTHORITY_BINDING=PASS"
    )

    print(
        "VERIFIER_NETWORK_FETCH=NO"
    )

    print(
        "CRYPTO_EXECUTION_PERFORMED=NO"
    )

    print(
        "SOURCE_BOUND_ACCEPTANCE_EXECUTED=NO"
    )


if __name__ == "__main__":
    main()
