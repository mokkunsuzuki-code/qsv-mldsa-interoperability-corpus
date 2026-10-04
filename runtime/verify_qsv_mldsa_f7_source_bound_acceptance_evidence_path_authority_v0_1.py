#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath


EXPECTED_PREDECESSOR_COMMIT = "075f4616eb86f4331ca403f0382c5c1e957a3275"
EXPECTED_PREDECESSOR_TREE = "1bbe87847471d5af308475daebd86fe01d9e7139"
EXPECTED_TRACKED_COUNT = 160

EXPECTED_ROLE = "DEDICATED_APPEND_ONLY_EVIDENCE_PATH_AUTHORITY_MANIFEST"
EXPECTED_RELATIONSHIP = "APPEND_ONLY_EVIDENCE_PATH_AUTHORITY_EXTENSION"
EXPECTED_SEMANTIC_RELATIONSHIP = "extends_without_modifying"

EXPECTED_BOUND_AUTHORITIES = {
    "source_bound_acceptance_contract": {
        "path": "contracts/qsv-mldsa-source-bound-acceptance-contract-v0.2.json",
        "sha256": "3b3b844c364cc338f4e6c9cf24281cf850ff6a5bf6e051c34d3b6472e8909da3",
    },
    "source_bound_acceptance_schema": {
        "path": "schemas/qsv-mldsa-source-bound-acceptance-v0.2.schema.json",
        "sha256": "37c2e0e88dc54f4eb5b0e00972d05f4fb42a2c8524fd0b863fe0adc745d1c606",
    },
    "source_bound_acceptance_verifier": {
        "path": "runtime/verify_qsv_mldsa_source_bound_acceptance_v0_2.py",
        "sha256": "c780b246475868f41c928e00f8dbe25a0c429e664a1d24c9b6aaf404fb4aecd7",
    },
    "coverage_manifest": {
        "path": "manifest/qsv-mldsa-f7-sixcase-neutral-fixture-coverage-v0.1-manifest.json",
        "sha256": "1d88dbc902e5ed568b06fd9e8e001fc61afb3c8b514e70e540db289a47b9b23a",
    },
}

EXPECTED_AUTHORITY_PATHS = [
    "manifest/qsv-mldsa-f7-source-bound-acceptance-evidence-path-authority-v0.1-manifest.json",
    "manifest/qsv-mldsa-f7-source-bound-acceptance-evidence-path-authority-v0.1-manifest.json.sha256",
    "runtime/verify_qsv_mldsa_f7_source_bound_acceptance_evidence_path_authority_v0_1.py",
    "runtime/verify_qsv_mldsa_f7_source_bound_acceptance_evidence_path_authority_v0_1.py.sha256",
]

EXPECTED_CASES = [
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-44",
        "tg_id": 1,
        "tc_id": 1,
        "expected_valid": False,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa44_tg1_tc1_v0_1.json",
    },
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-44",
        "tg_id": 1,
        "tc_id": 3,
        "expected_valid": True,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa44_tg1_tc3_v0_1.json",
    },
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-65",
        "tg_id": 3,
        "tc_id": 31,
        "expected_valid": False,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa65_tg3_tc31_v0_1.json",
    },
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-65",
        "tg_id": 3,
        "tc_id": 33,
        "expected_valid": True,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa65_tg3_tc33_v0_1.json",
    },
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-87",
        "tg_id": 5,
        "tc_id": 61,
        "expected_valid": False,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa87_tg5_tc61_v0_1.json",
    },
    {
        "record_kind": "case_acceptance",
        "parameter_set": "ML-DSA-87",
        "tg_id": 5,
        "tc_id": 63,
        "expected_valid": True,
        "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa87_tg5_tc63_v0_1.json",
    },
]

EXPECTED_AGGREGATE = {
    "record_kind": "aggregate_summary",
    "path": "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_aggregate_summary_v0_1.json",
    "case_record_reference_policy": "path_plus_sha256_observed_after_execution",
}

EXPECTED_TOP_LEVEL_KEYS = {
    "schema",
    "version",
    "authority_role",
    "relationship_to_v0_2",
    "semantic_relationship",
    "predecessor_public_authority",
    "bound_authorities",
    "record_model",
    "path_policy",
    "case_records",
    "aggregate_summary",
    "sidecar_policy",
    "implementation_file_impact",
    "publication_semantics",
}

OUTCOME_TOKENS = {
    "pass",
    "fail",
    "blocked",
    "not_complete",
    "positive",
    "negative",
    "valid",
    "invalid",
}


class GateError(Exception):
    pass


def reject(message):
    raise GateError(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_json_no_duplicates(path):
    def hook(pairs):
        obj = {}

        for key, value in pairs:
            if key in obj:
                reject(
                    "DUPLICATE_JSON_KEY:"
                    + key
                )

            obj[key] = value

        return obj

    try:
        return json.loads(
            path.read_text(
                encoding="utf-8"
            ),
            object_pairs_hook=hook,
        )

    except GateError:
        raise

    except Exception as exc:
        reject(
            "JSON_PARSE_FAILURE:"
            + str(exc)
        )


def run_git(root, *args):
    proc = subprocess.run(
        [
            "/usr/bin/git",
            "-C",
            str(root),
            *args,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if proc.returncode != 0:
        reject(
            "GIT_FAILURE:"
            + " ".join(args)
            + ":"
            + proc.stderr.decode(
                "utf-8",
                "replace",
            ).strip()
        )

    return proc.stdout


def normalized_repo_path(path):
    if not isinstance(path, str):
        return False

    if not path:
        return False

    if path.startswith("/"):
        return False

    if "\\" in path:
        return False

    if "//" in path:
        return False

    parts = path.split("/")

    if any(
        item in {
            "",
            ".",
            "..",
        }
        for item in parts
    ):
        return False

    if str(
        PurePosixPath(path)
    ) != path:
        return False

    return True


def predecessor_paths(root):
    raw = run_git(
        root,
        "ls-tree",
        "-r",
        "--name-only",
        EXPECTED_PREDECESSOR_COMMIT,
    )

    return {
        line
        for line in raw.decode(
            "utf-8",
            "surrogateescape",
        ).splitlines()
        if line
    }


def predecessor_blob(root, path):
    return run_git(
        root,
        "show",
        EXPECTED_PREDECESSOR_COMMIT
        + ":"
        + path,
    )


def verify(
    manifest,
    root,
    require_future_paths_absent,
):
    if set(manifest) != EXPECTED_TOP_LEVEL_KEYS:
        reject(
            "TOP_LEVEL_KEY_SET_MISMATCH"
        )

    if manifest["schema"] != (
        "qsv.mldsa.f7."
        "source-bound-acceptance-evidence-path-authority.v0.1"
    ):
        reject(
            "SCHEMA_ID_MISMATCH"
        )

    if manifest["version"] != "0.1":
        reject(
            "VERSION_MISMATCH"
        )

    if (
        manifest["authority_role"]
        != EXPECTED_ROLE
    ):
        reject(
            "AUTHORITY_ROLE_MISMATCH"
        )

    if (
        manifest["relationship_to_v0_2"]
        != EXPECTED_RELATIONSHIP
    ):
        reject(
            "RELATIONSHIP_MISMATCH"
        )

    if (
        manifest["semantic_relationship"]
        != EXPECTED_SEMANTIC_RELATIONSHIP
    ):
        reject(
            "SEMANTIC_RELATIONSHIP_MISMATCH"
        )

    predecessor = manifest[
        "predecessor_public_authority"
    ]

    if set(predecessor) != {
        "commit",
        "tree",
    }:
        reject(
            "PREDECESSOR_KEY_SET_MISMATCH"
        )

    if (
        predecessor["commit"]
        != EXPECTED_PREDECESSOR_COMMIT
    ):
        reject(
            "PREDECESSOR_COMMIT_MISMATCH"
        )

    if (
        predecessor["tree"]
        != EXPECTED_PREDECESSOR_TREE
    ):
        reject(
            "PREDECESSOR_TREE_MISMATCH"
        )

    actual_tree = run_git(
        root,
        "rev-parse",
        EXPECTED_PREDECESSOR_COMMIT
        + "^{tree}",
    ).decode(
        "ascii"
    ).strip()

    if (
        actual_tree
        != EXPECTED_PREDECESSOR_TREE
    ):
        reject(
            "PREDECESSOR_TREE_OBJECT_MISMATCH"
        )

    bound = manifest[
        "bound_authorities"
    ]

    if bound != EXPECTED_BOUND_AUTHORITIES:
        reject(
            "BOUND_AUTHORITY_DECLARATION_MISMATCH"
        )

    for item in EXPECTED_BOUND_AUTHORITIES.values():
        data = predecessor_blob(
            root,
            item["path"],
        )

        if (
            sha256_bytes(data)
            != item["sha256"]
        ):
            reject(
                "BOUND_AUTHORITY_HASH_MISMATCH:"
                + item["path"]
            )

    model = manifest[
        "record_model"
    ]

    expected_model = {
        "case_record_count": 6,
        "aggregate_summary_count": 1,
        "total_semantic_record_count": 7,
        "future_evidence_publication_file_count": 14,
    }

    if model != expected_model:
        reject(
            "RECORD_MODEL_MISMATCH"
        )

    policy = manifest[
        "path_policy"
    ]

    expected_policy = {
        "exact_path_enumeration_required": True,
        "repository_relative_normalized_posix": True,
        "result_independent": True,
        "no_extra_path_authority": True,
        "path_authority_must_be_public_before_acceptance_execution": True,
        "future_result_predeclared": False,
        "future_evidence_digest_predeclared": False,
        "aggregate_binds_case_record_paths": True,
        "aggregate_binds_case_record_sha256": True,
        "digest_dependency_acyclic": True,
        "digest_dependency_direction": "PUBLIC_PATH_AUTHORITY_TO_CASE_RECORDS_TO_AGGREGATE_SUMMARY",
    }

    if policy != expected_policy:
        reject(
            "PATH_POLICY_MISMATCH"
        )

    cases = manifest[
        "case_records"
    ]

    if cases != EXPECTED_CASES:
        reject(
            "EXACT_CASE_AUTHORITY_MISMATCH"
        )

    aggregate = manifest[
        "aggregate_summary"
    ]

    if aggregate != EXPECTED_AGGREGATE:
        reject(
            "AGGREGATE_AUTHORITY_MISMATCH"
        )

    semantic_paths = [
        item["path"]
        for item in cases
    ] + [
        aggregate["path"]
    ]

    if len(semantic_paths) != 7:
        reject(
            "SEMANTIC_PATH_COUNT_MISMATCH"
        )

    if len(set(semantic_paths)) != 7:
        reject(
            "DUPLICATE_SEMANTIC_PATH"
        )

    if len(
        {
            path.casefold()
            for path in semantic_paths
        }
    ) != 7:
        reject(
            "CASEFOLD_SEMANTIC_PATH_COLLISION"
        )

    if not all(
        normalized_repo_path(path)
        for path in semantic_paths
    ):
        reject(
            "UNSAFE_SEMANTIC_PATH"
        )

    if (
        aggregate["path"]
        in {
            item["path"]
            for item in cases
        }
    ):
        reject(
            "AGGREGATE_CASE_PATH_COLLISION"
        )

    for path in semantic_paths:
        tokens = (
            path.lower()
            .replace("-", "_")
            .replace(".", "_")
            .replace("/", "_")
            .split("_")
        )

        if OUTCOME_TOKENS & set(tokens):
            reject(
                "RESULT_DEPENDENT_PATH:"
                + path
            )

    sidecar = manifest[
        "sidecar_policy"
    ]

    expected_sidecar = {
        "case_record_sidecar_required": True,
        "aggregate_summary_sidecar_required": True,
        "path_authority_sidecar_required": True,
        "path_authority_verifier_sidecar_required": True,
        "hash_algorithm": "SHA-256",
        "sidecar_format": "SHA256_TWO_SPACES_REPOSITORY_RELATIVE_PATH_LF",
    }

    if sidecar != expected_sidecar:
        reject(
            "SIDECAR_POLICY_MISMATCH"
        )

    impact = manifest[
        "implementation_file_impact"
    ]

    if set(impact) != {
        "must_create",
        "may_create",
        "must_modify",
        "may_modify",
        "must_not_modify_predecessor_tracked_path_count",
    }:
        reject(
            "FILE_IMPACT_KEY_SET_MISMATCH"
        )

    if (
        impact["must_create"]
        != EXPECTED_AUTHORITY_PATHS
    ):
        reject(
            "MUST_CREATE_PATH_SET_MISMATCH"
        )

    if impact["may_create"] != []:
        reject(
            "UNEXPECTED_MAY_CREATE"
        )

    if impact["must_modify"] != []:
        reject(
            "EXISTING_FILE_MODIFICATION_REQUIRED"
        )

    if impact["may_modify"] != []:
        reject(
            "UNEXPECTED_MAY_MODIFY"
        )

    if (
        impact[
            "must_not_modify_predecessor_tracked_path_count"
        ]
        != EXPECTED_TRACKED_COUNT
    ):
        reject(
            "PREDECESSOR_TRACKED_COUNT_MISMATCH"
        )

    publication = manifest[
        "publication_semantics"
    ]

    expected_publication = {
        "path_authority_publication_implies_acceptance_execution": False,
        "path_authority_publication_implies_acceptance_pass": False,
        "path_authority_publication_implies_evidence_publication": False,
    }

    if publication != expected_publication:
        reject(
            "PUBLICATION_SEMANTICS_MISMATCH"
        )

    historical_paths = predecessor_paths(
        root
    )

    if len(historical_paths) != EXPECTED_TRACKED_COUNT:
        reject(
            "PREDECESSOR_TRACKED_PATH_COUNT_MISMATCH"
        )

    historical_folded = {
        path.casefold()
        for path in historical_paths
    }

    for path in (
        semantic_paths
        + EXPECTED_AUTHORITY_PATHS
    ):
        if path in historical_paths:
            reject(
                "HISTORICAL_PATH_REUSE:"
                + path
            )

        if path.casefold() in historical_folded:
            reject(
                "HISTORICAL_CASEFOLD_COLLISION:"
                + path
            )

    all_proposed = (
        semantic_paths
        + EXPECTED_AUTHORITY_PATHS
    )

    if len(
        {
            path.casefold()
            for path in all_proposed
        }
    ) != len(all_proposed):
        reject(
            "CROSS_SET_CASEFOLD_COLLISION"
        )

    if require_future_paths_absent:
        for path in semantic_paths:
            if (
                root
                / path
            ).exists():
                reject(
                    "FUTURE_EVIDENCE_PATH_ALREADY_EXISTS:"
                    + path
                )

    return True


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "manifest",
    )

    parser.add_argument(
        "--repository-root",
        required=True,
    )

    parser.add_argument(
        "--require-future-paths-absent",
        action="store_true",
    )

    args = parser.parse_args()

    manifest_path = Path(
        args.manifest
    ).resolve()

    root = Path(
        args.repository_root
    ).resolve()

    try:
        manifest = (
            load_json_no_duplicates(
                manifest_path
            )
        )

        verify(
            manifest,
            root,
            args.require_future_paths_absent,
        )

    except GateError as exc:
        print(
            "PATH_AUTHORITY_VERIFICATION=FAIL"
        )

        print(
            "FAILURE_REASON="
            + str(exc)
        )

        return 1

    except Exception as exc:
        print(
            "PATH_AUTHORITY_VERIFICATION=FAIL"
        )

        print(
            "FAILURE_REASON=UNEXPECTED:"
            + repr(exc)
        )

        return 1

    print(
        "PATH_AUTHORITY_VERIFICATION=PASS"
    )

    print(
        "AUTHORIZED_CASE_PATH_COUNT=6"
    )

    print(
        "AUTHORIZED_AGGREGATE_PATH_COUNT=1"
    )

    print(
        "AUTHORIZED_TOTAL_SEMANTIC_EVIDENCE_PATH_COUNT=7"
    )

    print(
        "OUTPUT_PATH_RESULT_INDEPENDENT=YES"
    )

    print(
        "EVIDENCE_DIGEST_DEPENDENCY_ACYCLIC=YES"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
