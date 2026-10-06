#!/usr/bin/env python3
"""
QSV ML-DSA Interoperability Corpus
SB-2R — Phase R1 Exact Invocation Launcher v0.2

Versioned successor to launcher v0.1.

Authority model:
- CONTROL and TARGET are separate physical clones.
- CONTROL is an exact detached, externally supplied R2 publication commit.
- TARGET is exact detached SB-2R commit b491ba7...
- R2 authority bytes are read from the exact CONTROL Git object.
- R2 publication commit SHA is supplied externally at invocation.
- No future R2 SHA or containing commit is embedded in this source.
- QSV_EXECUTE_CRYPTO must be absent.
- No network source acquisition is performed.
- No new ML-DSA cryptographic execution is required.
"""

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile


CANONICAL_REPOSITORY = (
    "https://github.com/mokkunsuzuki-code/"
    "qsv-mldsa-interoperability-corpus.git"
)

TARGET_COMMIT = (
    "b491ba797df6175bcc197d28104b62623dde171f"
)

TARGET_TREE = (
    "8b684e0a4d2d9194bffae44036e50aac4c3e741b"
)

TARGET_PARENT = (
    "00f0d3cfbc6f6fef2e9eb3cec450dbe9af76497a"
)

R2_AUTHORITY_REL = (
    "contracts/"
    "qsv-mldsa-f7-execution-repository-authority-v0.1.json"
)

R2_SIDECAR_REL = (
    R2_AUTHORITY_REL
    + ".sha256"
)

R2_SCHEMA = (
    "qsv.mldsa.f7.execution-repository-authority.v0.1"
)

R2_VERSION = "0.1"

R2_ROLE = (
    "SOURCE_BOUND_EXECUTION_REPOSITORY_AUTHORITY"
)

LAUNCHER_REL = (
    "runtime/"
    "run_qsv_mldsa_f7_source_bound_acceptance_with_python_authority_v0_2.py"
)

PROSPECTIVE_AUTHORITY_REL = (
    "contracts/"
    "qsv-mldsa-f7-prospective-python-execution-authority-v0.1.json"
)

PROSPECTIVE_AUTHORITY_SHA256 = (
    "56747f65425912c0dc776e35645e779dc2c88c7728826fd7d802adb443731056"
)

ENVIRONMENT_AUTHORITY_REL = (
    "contracts/"
    "qsv-mldsa-f7-source-bound-execution-environment-authority-v0.1.json"
)

ENVIRONMENT_AUTHORITY_SHA256 = (
    "cba9a668bb0218e1702179d040603968d634d9a1406e1bc7cefba3b8d86e22b2"
)

BINDING_MANIFEST_REL = (
    "manifest/"
    "qsv-mldsa-f7-consumer-environment-binding-authority-v0.1-manifest.json"
)

BINDING_MANIFEST_SHA256 = (
    "0c11378155fb948ef86d9f2b8bae1719e99c8fb5d719ab5dab4e6f20dab81b42"
)

SUPPLEMENTAL_VERIFIER_REL = (
    "runtime/"
    "verify_qsv_mldsa_f7_consumer_environment_binding_authority_v0_1.py"
)

SUPPLEMENTAL_VERIFIER_SHA256 = (
    "aeac2acc608f2f0959cdd978c0cd05c1a62857e9478568b33aa1f607443975c8"
)

ACCEPTANCE_CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-source-bound-acceptance-contract-v0.2.json"
)

ACCEPTANCE_CONTRACT_SHA256 = (
    "3b3b844c364cc338f4e6c9cf24281cf850ff6a5bf6e051c34d3b6472e8909da3"
)

ACCEPTANCE_VERIFIER_REL = (
    "runtime/"
    "verify_qsv_mldsa_source_bound_acceptance_v0_2.py"
)

ACCEPTANCE_VERIFIER_SHA256 = (
    "c780b246475868f41c928e00f8dbe25a0c429e664a1d24c9b6aaf404fb4aecd7"
)

COVERAGE_MANIFEST_REL = (
    "manifest/"
    "qsv-mldsa-f7-sixcase-neutral-fixture-coverage-v0.1-manifest.json"
)

COVERAGE_MANIFEST_SHA256 = (
    "1d88dbc902e5ed568b06fd9e8e001fc61afb3c8b514e70e540db289a47b9b23a"
)

PATH_AUTHORITY_REL = (
    "manifest/"
    "qsv-mldsa-f7-source-bound-acceptance-evidence-path-authority-v0.1-manifest.json"
)

PATH_AUTHORITY_SHA256 = (
    "0a6c5ba367a37a1e3bbb4ab65804577abb7f0b6c6a126e949c7431010bfa5bc3"
)

EXPECTED_INTERPRETER_PATH = (
    "/Users/motohiro/.pyenv/versions/3.10.14/bin/python3.10"
)

EXPECTED_INTERPRETER_SHA256 = (
    "094f3e91845a17d403c59b020b877e3845b205cbb431e50032cce346e04d8e6a"
)

EXPECTED_IMPLEMENTATION = "cpython"
EXPECTED_PLATFORM_IMPLEMENTATION = "CPython"
EXPECTED_VERSION = (
    3,
    10,
    14,
)

NIST_PROMPT_SHA256 = (
    "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"
)

NIST_EXPECTED_SHA256 = (
    "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6"
)

FORBIDDEN_ENVIRONMENT = (
    "QSV_EXECUTE_CRYPTO",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
)

BOUND_TARGET_ARTIFACTS = (
    (
        PROSPECTIVE_AUTHORITY_REL,
        PROSPECTIVE_AUTHORITY_SHA256,
    ),
    (
        ENVIRONMENT_AUTHORITY_REL,
        ENVIRONMENT_AUTHORITY_SHA256,
    ),
    (
        BINDING_MANIFEST_REL,
        BINDING_MANIFEST_SHA256,
    ),
    (
        SUPPLEMENTAL_VERIFIER_REL,
        SUPPLEMENTAL_VERIFIER_SHA256,
    ),
    (
        ACCEPTANCE_CONTRACT_REL,
        ACCEPTANCE_CONTRACT_SHA256,
    ),
    (
        ACCEPTANCE_VERIFIER_REL,
        ACCEPTANCE_VERIFIER_SHA256,
    ),
    (
        COVERAGE_MANIFEST_REL,
        COVERAGE_MANIFEST_SHA256,
    ),
    (
        PATH_AUTHORITY_REL,
        PATH_AUTHORITY_SHA256,
    ),
)

SELECTED_CASES = (
    {
        "parameter_set": "ML-DSA-44",
        "tg_id": 1,
        "tc_id": 1,
        "expected_valid": False,
        "fixture":
            "examples/qsv-mldsa-acvp-negative-canonical-v0.3.json",
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa44_tg1_tc1_v0_1.json"
            ),
    },
    {
        "parameter_set": "ML-DSA-44",
        "tg_id": 1,
        "tc_id": 3,
        "expected_valid": True,
        "fixture":
            "examples/qsv-mldsa-acvp-positive-canonical-v0.3.json",
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa44_tg1_tc3_v0_1.json"
            ),
    },
    {
        "parameter_set": "ML-DSA-65",
        "tg_id": 3,
        "tc_id": 31,
        "expected_valid": False,
        "fixture":
            (
                "examples/"
                "qsv-mldsa-acvp-65-tg3-tc31-negative-canonical-v0.3.json"
            ),
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa65_tg3_tc31_v0_1.json"
            ),
    },
    {
        "parameter_set": "ML-DSA-65",
        "tg_id": 3,
        "tc_id": 33,
        "expected_valid": True,
        "fixture":
            (
                "examples/"
                "qsv-mldsa-acvp-65-tg3-tc33-positive-canonical-v0.3.json"
            ),
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa65_tg3_tc33_v0_1.json"
            ),
    },
    {
        "parameter_set": "ML-DSA-87",
        "tg_id": 5,
        "tc_id": 61,
        "expected_valid": False,
        "fixture":
            (
                "examples/"
                "qsv-mldsa-acvp-87-tg5-tc61-negative-canonical-v0.3.json"
            ),
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa87_tg5_tc61_v0_1.json"
            ),
    },
    {
        "parameter_set": "ML-DSA-87",
        "tg_id": 5,
        "tc_id": 63,
        "expected_valid": True,
        "fixture":
            (
                "examples/"
                "qsv-mldsa-acvp-87-tg5-tc63-positive-canonical-v0.3.json"
            ),
        "output":
            (
                "results/"
                "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
                "qsv_mldsa_f7_source_bound_acceptance_case_"
                "mldsa87_tg5_tc63_v0_1.json"
            ),
    },
)

AGGREGATE_OUTPUT_REL = (
    "results/"
    "qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/"
    "qsv_mldsa_f7_source_bound_acceptance_aggregate_summary_v0_1.json"
)

SEVEN_FINAL_OUTPUTS = (
    tuple(
        item[
            "output"
        ]
        for item in SELECTED_CASES
    )
    + (
        AGGREGATE_OUTPUT_REL,
    )
)

EXPECTED_R2_TOP_KEYS = {
    "schema",
    "version",
    "authority_role",
    "control_repository",
    "launcher",
    "target_repository",
    "prospective_python_authority",
    "execution_environment_authority",
    "binding_manifest",
    "supplemental_verifier",
    "source_bound_acceptance_contract",
    "source_bound_acceptance_verifier",
    "selected_scope_authority",
    "path_authority",
    "publication_semantics",
    "execution_semantics",
    "historical_claim_boundary",
}

EXPECTED_PUBLICATION_SEMANTICS = {
    "authority_publication_implies_acceptance_execution":
        False,
    "authority_publication_implies_acceptance_pass":
        False,
    "authority_publication_implies_crypto_execution":
        False,
}

EXPECTED_EXECUTION_SEMANTICS = {
    "control_target_separate_physical_clones_required":
        True,
    "r2_containing_commit_embedded":
        False,
    "r2_publication_commit_supplied_externally":
        True,
    "target_pre_execution_clean_required":
        True,
    "seven_output_absence_required":
        True,
    "output_overwrite_allowed":
        False,
    "new_crypto_execution_required":
        False,
    "qsv_execute_crypto_must_be_absent":
        True,
    "launcher_network_access_required":
        False,
    "acceptance_verifier_network_access_required":
        False,
}

EXPECTED_HISTORICAL_CLAIM_BOUNDARY = {
    "public_historical_python_version_evidence":
        "Python 3.12.3",
    "public_historical_python_implementation_authority":
        "UNRESOLVED",
    "retroactive_cpython_claim_allowed":
        False,
    "prospective_python_applies_to_future_sb2r_only":
        True,
    "source_to_runtime_provenance_completed":
        False,
}

HEX = set(
    "0123456789abcdef"
)


class LauncherError(Exception):
    pass


def fail(message):
    raise LauncherError(
        message
    )


def sha256_bytes(value):
    return hashlib.sha256(
        value
    ).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as handle:
        while True:
            chunk = handle.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


def is_hex(value, length):
    return (
        isinstance(
            value,
            str,
        )
        and len(
            value
        )
        == length
        and all(
            char in HEX
            for char in value
        )
    )


def run_git_read_only(
    repository_root,
    arguments,
    allow_nonzero=False,
):
    if not arguments:
        fail(
            "EMPTY_GIT_ARGUMENTS"
        )

    command = arguments[
        0
    ]

    allowed_commands = {
        "branch",
        "cat-file",
        "diff",
        "diff-tree",
        "ls-files",
        "ls-tree",
        "remote",
        "rev-parse",
        "show",
    }

    if command not in allowed_commands:
        fail(
            "DISALLOWED_GIT_COMMAND="
            + command
        )

    if command == "branch":
        if tuple(
            arguments
        ) != (
            "branch",
            "--show-current",
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "remote":
        if tuple(
            arguments
        ) != (
            "remote",
            "get-url",
            "origin",
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "diff":
        allowed = {
            (
                "diff",
                "--name-only",
                "-z",
            ),
            (
                "diff",
                "--cached",
                "--name-only",
                "-z",
            ),
        }

        if tuple(
            arguments
        ) not in allowed:
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "ls-files":
        if tuple(
            arguments
        ) != (
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "rev-parse":
        if len(
            arguments
        ) != 2:
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

        operand = arguments[
            1
        ]

        static_allowed = {
            "--show-toplevel",
            "HEAD",
            "HEAD^{tree}",
            "HEAD^",
        }

        dynamic_tree = (
            isinstance(
                operand,
                str,
            )
            and operand.endswith(
                "^{tree}"
            )
            and is_hex(
                operand[
                    :-7
                ],
                40,
            )
        )

        if (
            operand
            not in static_allowed
            and not dynamic_tree
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "cat-file":
        if (
            len(
                arguments
            )
            != 3
            or arguments[
                1
            ]
            != "-t"
            or not is_hex(
                arguments[
                    2
                ],
                40,
            )
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "ls-tree":
        if (
            len(
                arguments
            )
            != 4
            or not is_hex(
                arguments[
                    1
                ],
                40,
            )
            or arguments[
                2
            ]
            != "--"
            or not isinstance(
                arguments[
                    3
                ],
                str,
            )
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "show":
        if len(
            arguments
        ) != 2:
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

        spec = arguments[
            1
        ]

        if ":" not in spec:
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

        commit, rel = spec.split(
            ":",
            1,
        )

        if (
            not is_hex(
                commit,
                40,
            )
            or not rel
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    if command == "diff-tree":
        if (
            len(
                arguments
            )
            != 6
            or tuple(
                arguments[
                    1:5
                ]
            )
            != (
                "--no-commit-id",
                "--name-status",
                "-r",
                "--root",
            )
            or not is_hex(
                arguments[
                    5
                ],
                40,
            )
        ):
            fail(
                "DISALLOWED_GIT_ARGUMENTS="
                + repr(
                    tuple(
                        arguments
                    )
                )
            )

    process = subprocess.run(
        [
            "/usr/bin/git",
            *arguments,
        ],
        cwd=str(
            repository_root
        ),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=os.environ.copy(),
        shell=False,
    )

    if (
        process.returncode
        != 0
        and not allow_nonzero
    ):
        fail(
            "READ_ONLY_GIT_QUERY_FAILED="
            + repr(
                tuple(
                    arguments
                )
            )
            + ":"
            + process.stderr.decode(
                "utf-8",
                "replace",
            ).strip()
        )

    return process


def git_text(
    repository_root,
    arguments,
):
    return (
        run_git_read_only(
            repository_root,
            arguments,
        )
        .stdout
        .decode(
            "utf-8",
            "surrogateescape",
        )
        .strip()
    )


def git_paths(
    repository_root,
    arguments,
):
    return tuple(
        sorted(
            item.decode(
                "utf-8",
                "surrogateescape",
            )
            for item
            in run_git_read_only(
                repository_root,
                arguments,
            ).stdout.split(
                b"\0"
            )
            if item
        )
    )


def verify_environment():
    for name in FORBIDDEN_ENVIRONMENT:
        if name in os.environ:
            fail(
                "FORBIDDEN_ENVIRONMENT_PRESENT="
                + name
            )

    if (
        os.environ.get(
            "PYTHONDONTWRITEBYTECODE"
        )
        != "1"
    ):
        fail(
            "PYTHONDONTWRITEBYTECODE_MUST_EQUAL_1"
        )


def resolve_git_root(
    requested_root,
):
    root = pathlib.Path(
        requested_root
    )

    if not root.is_absolute():
        fail(
            "REPOSITORY_ROOT_NOT_ABSOLUTE"
        )

    resolved = root.resolve()

    actual = pathlib.Path(
        git_text(
            resolved,
            (
                "rev-parse",
                "--show-toplevel",
            ),
        )
    ).resolve()

    if actual != resolved:
        fail(
            "REPOSITORY_ROOT_MISMATCH"
        )

    return resolved


def verify_origin(
    root,
):
    origin = git_text(
        root,
        (
            "remote",
            "get-url",
            "origin",
        ),
    )

    if origin != CANONICAL_REPOSITORY:
        fail(
            "REPOSITORY_ORIGIN_MISMATCH"
        )


def verify_detached(
    root,
):
    branch = git_text(
        root,
        (
            "branch",
            "--show-current",
        ),
    )

    if branch != "":
        fail(
            "DETACHED_HEAD_REQUIRED"
        )


def verify_clean_repository(
    root,
    require_untracked_empty=True,
):
    staged = git_paths(
        root,
        (
            "diff",
            "--cached",
            "--name-only",
            "-z",
        ),
    )

    unstaged = git_paths(
        root,
        (
            "diff",
            "--name-only",
            "-z",
        ),
    )

    untracked = git_paths(
        root,
        (
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ),
    )

    if staged:
        fail(
            "STAGED_PATH_PRESENT"
        )

    if unstaged:
        fail(
            "TRACKED_WORKTREE_DIRTY"
        )

    if (
        require_untracked_empty
        and untracked
    ):
        fail(
            "UNTRACKED_PATH_PRESENT"
        )

    return untracked


def validate_control_repository(
    control_root,
    r2_publication_commit,
):
    root = resolve_git_root(
        control_root
    )

    verify_origin(
        root
    )

    verify_detached(
        root
    )

    verify_clean_repository(
        root,
        require_untracked_empty=True,
    )

    if not is_hex(
        r2_publication_commit,
        40,
    ):
        fail(
            "R2_PUBLICATION_COMMIT_INVALID"
        )

    head = git_text(
        root,
        (
            "rev-parse",
            "HEAD",
        ),
    )

    if head != r2_publication_commit:
        fail(
            "CONTROL_HEAD_R2_PUBLICATION_COMMIT_MISMATCH"
        )

    head_tree = git_text(
        root,
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    )

    parent = git_text(
        root,
        (
            "rev-parse",
            "HEAD^",
        ),
    )

    return {
        "root":
            root,

        "head":
            head,

        "head_tree":
            head_tree,

        "parent":
            parent,
    }


def parse_ls_tree_entry(
    line,
    expected_path,
):
    parts = line.split(
        None,
        3,
    )

    if len(
        parts
    ) != 4:
        fail(
            "GIT_TREE_ENTRY_INVALID"
        )

    mode, object_type, object_id, path = (
        parts
    )

    if path != expected_path:
        fail(
            "GIT_TREE_ENTRY_PATH_MISMATCH"
        )

    return {
        "mode":
            mode,

        "type":
            object_type,

        "object_id":
            object_id,

        "path":
            path,
    }


def git_object_bytes(
    root,
    commit,
    rel,
    expected_mode,
):
    entry_text = git_text(
        root,
        (
            "ls-tree",
            commit,
            "--",
            rel,
        ),
    )

    if not entry_text:
        fail(
            "GIT_TREE_ENTRY_MISSING="
            + rel
        )

    entry = parse_ls_tree_entry(
        entry_text,
        rel,
    )

    if entry[
        "type"
    ] != "blob":
        fail(
            "GIT_TREE_ENTRY_NOT_BLOB="
            + rel
        )

    if entry[
        "mode"
    ] != expected_mode:
        fail(
            "GIT_TREE_ENTRY_MODE_MISMATCH="
            + rel
        )

    return run_git_read_only(
        root,
        (
            "show",
            commit
            + ":"
            + rel,
        ),
    ).stdout


def parse_sidecar_bytes(
    sidecar_bytes,
    expected_target_rel,
):
    try:
        text = sidecar_bytes.decode(
            "utf-8",
            "strict",
        )
    except UnicodeDecodeError as exc:
        fail(
            "SIDECAR_UTF8_INVALID="
            + repr(
                exc
            )
        )

    suffix = (
        "  "
        + expected_target_rel
        + "\n"
    )

    if not text.endswith(
        suffix
    ):
        fail(
            "SIDECAR_FORMAT_OR_TARGET_MISMATCH"
        )

    declared = text[
        :-len(
            suffix
        )
    ]

    if not is_hex(
        declared,
        64,
    ):
        fail(
            "SIDECAR_SHA256_INVALID"
        )

    if text != (
        declared
        + suffix
    ):
        fail(
            "SIDECAR_NONCANONICAL"
        )

    return declared


def load_r2_authority_from_git_object(
    control,
):
    authority_bytes = git_object_bytes(
        control[
            "root"
        ],
        control[
            "head"
        ],
        R2_AUTHORITY_REL,
        "100644",
    )

    sidecar_bytes = git_object_bytes(
        control[
            "root"
        ],
        control[
            "head"
        ],
        R2_SIDECAR_REL,
        "100644",
    )

    declared = parse_sidecar_bytes(
        sidecar_bytes,
        R2_AUTHORITY_REL,
    )

    observed = sha256_bytes(
        authority_bytes
    )

    if declared != observed:
        fail(
            "R2_SIDECAR_BINDING_MISMATCH"
        )

    try:
        authority = json.loads(
            authority_bytes.decode(
                "utf-8",
                "strict",
            )
        )
    except Exception as exc:
        fail(
            "R2_AUTHORITY_JSON_INVALID="
            + repr(
                exc
            )
        )

    return (
        authority,
        observed,
    )


def require_exact_reference(
    doc,
    key,
    path,
    sha256,
):
    value = doc.get(
        key
    )

    if not isinstance(
        value,
        dict,
    ):
        fail(
            "R2_REFERENCE_NOT_OBJECT="
            + key
        )

    if set(
        value
    ) != {
        "path",
        "sha256",
    }:
        fail(
            "R2_REFERENCE_KEY_SET_MISMATCH="
            + key
        )

    if value[
        "path"
    ] != path:
        fail(
            "R2_REFERENCE_PATH_MISMATCH="
            + key
        )

    if value[
        "sha256"
    ] != sha256:
        fail(
            "R2_REFERENCE_SHA256_MISMATCH="
            + key
        )


def validate_r2_authority(
    authority,
):
    if not isinstance(
        authority,
        dict,
    ):
        fail(
            "R2_AUTHORITY_NOT_OBJECT"
        )

    if set(
        authority
    ) != EXPECTED_R2_TOP_KEYS:
        fail(
            "R2_TOP_LEVEL_KEY_SET_MISMATCH"
        )

    if authority[
        "schema"
    ] != R2_SCHEMA:
        fail(
            "R2_SCHEMA_MISMATCH"
        )

    if authority[
        "version"
    ] != R2_VERSION:
        fail(
            "R2_VERSION_MISMATCH"
        )

    if authority[
        "authority_role"
    ] != R2_ROLE:
        fail(
            "R2_ROLE_MISMATCH"
        )

    control = authority[
        "control_repository"
    ]

    if (
        not isinstance(
            control,
            dict,
        )
        or set(
            control
        )
        != {
            "repository",
            "commit",
            "tree",
        }
        or control[
            "repository"
        ]
        != CANONICAL_REPOSITORY
        or not is_hex(
            control[
                "commit"
            ],
            40,
        )
        or not is_hex(
            control[
                "tree"
            ],
            40,
        )
    ):
        fail(
            "R2_CONTROL_REPOSITORY_INVALID"
        )

    launcher = authority[
        "launcher"
    ]

    if (
        not isinstance(
            launcher,
            dict,
        )
        or set(
            launcher
        )
        != {
            "path",
            "sha256",
        }
        or launcher[
            "path"
        ]
        != LAUNCHER_REL
        or not is_hex(
            launcher[
                "sha256"
            ],
            64,
        )
    ):
        fail(
            "R2_LAUNCHER_INVALID"
        )

    if authority[
        "target_repository"
    ] != {
        "repository":
            CANONICAL_REPOSITORY,

        "commit":
            TARGET_COMMIT,

        "tree":
            TARGET_TREE,
    }:
        fail(
            "R2_TARGET_REPOSITORY_MISMATCH"
        )

    require_exact_reference(
        authority,
        "prospective_python_authority",
        PROSPECTIVE_AUTHORITY_REL,
        PROSPECTIVE_AUTHORITY_SHA256,
    )

    require_exact_reference(
        authority,
        "execution_environment_authority",
        ENVIRONMENT_AUTHORITY_REL,
        ENVIRONMENT_AUTHORITY_SHA256,
    )

    require_exact_reference(
        authority,
        "binding_manifest",
        BINDING_MANIFEST_REL,
        BINDING_MANIFEST_SHA256,
    )

    require_exact_reference(
        authority,
        "supplemental_verifier",
        SUPPLEMENTAL_VERIFIER_REL,
        SUPPLEMENTAL_VERIFIER_SHA256,
    )

    require_exact_reference(
        authority,
        "source_bound_acceptance_contract",
        ACCEPTANCE_CONTRACT_REL,
        ACCEPTANCE_CONTRACT_SHA256,
    )

    require_exact_reference(
        authority,
        "source_bound_acceptance_verifier",
        ACCEPTANCE_VERIFIER_REL,
        ACCEPTANCE_VERIFIER_SHA256,
    )

    require_exact_reference(
        authority,
        "selected_scope_authority",
        COVERAGE_MANIFEST_REL,
        COVERAGE_MANIFEST_SHA256,
    )

    require_exact_reference(
        authority,
        "path_authority",
        PATH_AUTHORITY_REL,
        PATH_AUTHORITY_SHA256,
    )

    if authority[
        "publication_semantics"
    ] != EXPECTED_PUBLICATION_SEMANTICS:
        fail(
            "R2_PUBLICATION_SEMANTICS_MISMATCH"
        )

    if authority[
        "execution_semantics"
    ] != EXPECTED_EXECUTION_SEMANTICS:
        fail(
            "R2_EXECUTION_SEMANTICS_MISMATCH"
        )

    if authority[
        "historical_claim_boundary"
    ] != EXPECTED_HISTORICAL_CLAIM_BOUNDARY:
        fail(
            "R2_HISTORICAL_CLAIM_BOUNDARY_MISMATCH"
        )

    return authority


def validate_r2_publication_relation(
    control,
    authority,
):
    r1_commit = authority[
        "control_repository"
    ][
        "commit"
    ]

    r1_tree = authority[
        "control_repository"
    ][
        "tree"
    ]

    if control[
        "parent"
    ] != r1_commit:
        fail(
            "R2_NOT_DIRECT_CHILD_OF_DECLARED_R1"
        )

    observed_r1_tree = git_text(
        control[
            "root"
        ],
        (
            "rev-parse",
            r1_commit
            + "^{tree}",
        ),
    )

    if observed_r1_tree != r1_tree:
        fail(
            "R1_TREE_MISMATCH"
        )

    status = git_text(
        control[
            "root"
        ],
        (
            "diff-tree",
            "--no-commit-id",
            "--name-status",
            "-r",
            "--root",
            control[
                "head"
            ],
        ),
    )

    observed = tuple(
        sorted(
            line
            for line in status.splitlines()
            if line
        )
    )

    expected = tuple(
        sorted(
            (
                "A\t"
                + R2_AUTHORITY_REL,

                "A\t"
                + R2_SIDECAR_REL,
            )
        )
    )

    if observed != expected:
        fail(
            "R2_PUBLICATION_DIFF_NOT_MINIMAL"
        )


def validate_launcher_self_binding(
    control,
    authority,
):
    r1_commit = authority[
        "control_repository"
    ][
        "commit"
    ]

    expected_sha = authority[
        "launcher"
    ][
        "sha256"
    ]

    r1_launcher_bytes = git_object_bytes(
        control[
            "root"
        ],
        r1_commit,
        LAUNCHER_REL,
        "100755",
    )

    if sha256_bytes(
        r1_launcher_bytes
    ) != expected_sha:
        fail(
            "R1_LAUNCHER_SHA256_MISMATCH"
        )

    current_path = pathlib.Path(
        __file__
    )

    if current_path.is_symlink():
        fail(
            "CURRENT_LAUNCHER_SYMLINK_NOT_ALLOWED"
        )

    resolved = current_path.resolve()

    expected_current = (
        control[
            "root"
        ]
        / LAUNCHER_REL
    ).resolve()

    if resolved != expected_current:
        fail(
            "CURRENT_LAUNCHER_PATH_MISMATCH"
        )

    if not resolved.is_file():
        fail(
            "CURRENT_LAUNCHER_NOT_REGULAR_FILE"
        )

    if sha256_file(
        resolved
    ) != expected_sha:
        fail(
            "CURRENT_LAUNCHER_SHA256_MISMATCH"
        )


def validate_target_repository(
    target_root,
):
    root = resolve_git_root(
        target_root
    )

    verify_origin(
        root
    )

    verify_detached(
        root
    )

    verify_clean_repository(
        root,
        require_untracked_empty=True,
    )

    head = git_text(
        root,
        (
            "rev-parse",
            "HEAD",
        ),
    )

    tree = git_text(
        root,
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    )

    parent = git_text(
        root,
        (
            "rev-parse",
            "HEAD^",
        ),
    )

    if head != TARGET_COMMIT:
        fail(
            "TARGET_COMMIT_MISMATCH"
        )

    if tree != TARGET_TREE:
        fail(
            "TARGET_TREE_MISMATCH"
        )

    if parent != TARGET_PARENT:
        fail(
            "TARGET_PARENT_MISMATCH"
        )

    return {
        "root":
            root,

        "head":
            head,

        "tree":
            tree,

        "parent":
            parent,
    }


def ensure_control_target_separate(
    control_root,
    target_root,
):
    if (
        control_root.resolve()
        == target_root.resolve()
    ):
        fail(
            "CONTROL_TARGET_SAME_REALPATH"
        )


def validate_bound_target_artifacts(
    target,
    authority,
):
    expected_by_key = {
        "prospective_python_authority":
            (
                PROSPECTIVE_AUTHORITY_REL,
                PROSPECTIVE_AUTHORITY_SHA256,
            ),

        "execution_environment_authority":
            (
                ENVIRONMENT_AUTHORITY_REL,
                ENVIRONMENT_AUTHORITY_SHA256,
            ),

        "binding_manifest":
            (
                BINDING_MANIFEST_REL,
                BINDING_MANIFEST_SHA256,
            ),

        "supplemental_verifier":
            (
                SUPPLEMENTAL_VERIFIER_REL,
                SUPPLEMENTAL_VERIFIER_SHA256,
            ),

        "source_bound_acceptance_contract":
            (
                ACCEPTANCE_CONTRACT_REL,
                ACCEPTANCE_CONTRACT_SHA256,
            ),

        "source_bound_acceptance_verifier":
            (
                ACCEPTANCE_VERIFIER_REL,
                ACCEPTANCE_VERIFIER_SHA256,
            ),

        "selected_scope_authority":
            (
                COVERAGE_MANIFEST_REL,
                COVERAGE_MANIFEST_SHA256,
            ),

        "path_authority":
            (
                PATH_AUTHORITY_REL,
                PATH_AUTHORITY_SHA256,
            ),
    }

    for key, pair in expected_by_key.items():
        rel, expected_sha = pair

        if authority[
            key
        ] != {
            "path":
                rel,

            "sha256":
                expected_sha,
        }:
            fail(
                "R2_BOUND_REFERENCE_MISMATCH="
                + key
            )

        path = (
            target[
                "root"
            ]
            / rel
        )

        if (
            path.is_symlink()
            or not path.is_file()
        ):
            fail(
                "TARGET_BOUND_ARTIFACT_TYPE_INVALID="
                + rel
            )

        if sha256_file(
            path
        ) != expected_sha:
            fail(
                "TARGET_BOUND_ARTIFACT_SHA256_MISMATCH="
                + rel
            )


def validate_prospective_authority(
    target,
):
    path = (
        target[
            "root"
        ]
        / PROSPECTIVE_AUTHORITY_REL
    )

    try:
        authority = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "PROSPECTIVE_AUTHORITY_JSON_INVALID="
            + repr(
                exc
            )
        )

    candidate = (
        authority.get(
            "captured",
            {},
        )
        .get(
            "candidate",
            {},
        )
    )

    if authority.get(
        "role"
    ) != (
        "PROSPECTIVE_PRE_EXECUTION_PYTHON_EXECUTION_AUTHORITY"
    ):
        fail(
            "PROSPECTIVE_AUTHORITY_ROLE_MISMATCH"
        )

    if authority.get(
        "prospective"
    ) is not True:
        fail(
            "PROSPECTIVE_AUTHORITY_FLAG_MISMATCH"
        )

    if authority.get(
        "retroactive_claim"
    ) is not False:
        fail(
            "PROSPECTIVE_RETROACTIVE_FLAG_MISMATCH"
        )

    if authority.get(
        "historical_f7_implementation_claimed"
    ) is not False:
        fail(
            "PROSPECTIVE_HISTORICAL_IMPLEMENTATION_CLAIM_MISMATCH"
        )

    if candidate.get(
        "invocation_path"
    ) != EXPECTED_INTERPRETER_PATH:
        fail(
            "PROSPECTIVE_INVOCATION_PATH_MISMATCH"
        )

    if candidate.get(
        "invocation_path_is_symlink"
    ) is not False:
        fail(
            "PROSPECTIVE_INTERPRETER_SYMLINK_FLAG_MISMATCH"
        )

    if candidate.get(
        "resolved_executable_path"
    ) != EXPECTED_INTERPRETER_PATH:
        fail(
            "PROSPECTIVE_RESOLVED_PATH_MISMATCH"
        )

    if candidate.get(
        "resolved_executable_sha256"
    ) != EXPECTED_INTERPRETER_SHA256:
        fail(
            "PROSPECTIVE_INTERPRETER_SHA256_MISMATCH"
        )

    if candidate.get(
        "sys_implementation_name"
    ) != EXPECTED_IMPLEMENTATION:
        fail(
            "PROSPECTIVE_IMPLEMENTATION_MISMATCH"
        )

    if candidate.get(
        "platform_python_implementation"
    ) != EXPECTED_PLATFORM_IMPLEMENTATION:
        fail(
            "PROSPECTIVE_PLATFORM_IMPLEMENTATION_MISMATCH"
        )

    if candidate.get(
        "version_info"
    ) != list(
        EXPECTED_VERSION
    ):
        fail(
            "PROSPECTIVE_VERSION_INFO_MISMATCH"
        )

    if candidate.get(
        "platform_python_version"
    ) != "3.10.14":
        fail(
            "PROSPECTIVE_PLATFORM_VERSION_MISMATCH"
        )

    non_guarantees = authority.get(
        "non_guarantees",
        {},
    )

    if non_guarantees.get(
        "executable_sha256_is_complete_runtime_provenance"
    ) is not False:
        fail(
            "PROSPECTIVE_RUNTIME_PROVENANCE_BOUNDARY_MISMATCH"
        )

    if non_guarantees.get(
        "python_source_to_runtime_provenance_proven"
    ) is not False:
        fail(
            "PROSPECTIVE_SOURCE_RUNTIME_BOUNDARY_MISMATCH"
        )


def candidate_self_report(
    interpreter_path,
):
    code = (
        "import json,platform,sys;"
        "print(json.dumps({"
        "'sys_executable':sys.executable,"
        "'sys_implementation_name':sys.implementation.name,"
        "'platform_python_implementation':"
        "platform.python_implementation(),"
        "'version_info':["
        "sys.version_info.major,"
        "sys.version_info.minor,"
        "sys.version_info.micro],"
        "'platform_python_version':"
        "platform.python_version()"
        "},sort_keys=True))"
    )

    environment = os.environ.copy()

    environment[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    process = subprocess.run(
        [
            str(
                interpreter_path
            ),
            "-I",
            "-S",
            "-c",
            code,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
        shell=False,
    )

    if process.returncode != 0:
        fail(
            "INTERPRETER_SELF_REPORT_FAILED"
        )

    try:
        return json.loads(
            process.stdout.decode(
                "utf-8",
                "strict",
            )
        )
    except Exception as exc:
        fail(
            "INTERPRETER_SELF_REPORT_JSON_INVALID="
            + repr(
                exc
            )
        )


def verify_interpreter():
    interpreter = pathlib.Path(
        EXPECTED_INTERPRETER_PATH
    )

    if not interpreter.is_absolute():
        fail(
            "INTERPRETER_PATH_NOT_ABSOLUTE"
        )

    if not os.path.lexists(
        str(
            interpreter
        )
    ):
        fail(
            "INTERPRETER_PATH_MISSING"
        )

    if interpreter.is_symlink():
        fail(
            "INTERPRETER_SYMLINK_NOT_ALLOWED"
        )

    resolved = pathlib.Path(
        os.path.realpath(
            str(
                interpreter
            )
        )
    )

    if resolved != interpreter:
        fail(
            "INTERPRETER_REALPATH_MISMATCH"
        )

    if not resolved.is_file():
        fail(
            "INTERPRETER_NOT_REGULAR_FILE"
        )

    if not stat.S_ISREG(
        resolved.stat().st_mode
    ):
        fail(
            "INTERPRETER_NOT_REGULAR_FILE"
        )

    if not os.access(
        str(
            resolved
        ),
        os.X_OK,
    ):
        fail(
            "INTERPRETER_NOT_EXECUTABLE"
        )

    if sha256_file(
        resolved
    ) != EXPECTED_INTERPRETER_SHA256:
        fail(
            "INTERPRETER_SHA256_MISMATCH"
        )

    report = candidate_self_report(
        resolved
    )

    if os.path.realpath(
        report[
            "sys_executable"
        ]
    ) != str(
        resolved
    ):
        fail(
            "INTERPRETER_SYS_EXECUTABLE_REALPATH_MISMATCH"
        )

    if report[
        "sys_implementation_name"
    ] != EXPECTED_IMPLEMENTATION:
        fail(
            "INTERPRETER_IMPLEMENTATION_MISMATCH"
        )

    if report[
        "platform_python_implementation"
    ] != EXPECTED_PLATFORM_IMPLEMENTATION:
        fail(
            "INTERPRETER_PLATFORM_IMPLEMENTATION_MISMATCH"
        )

    if tuple(
        report[
            "version_info"
        ]
    ) != EXPECTED_VERSION:
        fail(
            "INTERPRETER_VERSION_MISMATCH"
        )

    if report[
        "platform_python_version"
    ] != "3.10.14":
        fail(
            "INTERPRETER_PLATFORM_VERSION_MISMATCH"
        )

    return resolved


def validate_path_authority(
    target,
):
    path = (
        target[
            "root"
        ]
        / PATH_AUTHORITY_REL
    )

    try:
        authority = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "PATH_AUTHORITY_JSON_INVALID="
            + repr(
                exc
            )
        )

    cases = authority.get(
        "case_records"
    )

    aggregate = authority.get(
        "aggregate_summary"
    )

    if (
        not isinstance(
            cases,
            list,
        )
        or len(
            cases
        )
        != 6
    ):
        fail(
            "PATH_AUTHORITY_CASE_COUNT_MISMATCH"
        )

    if not isinstance(
        aggregate,
        dict,
    ):
        fail(
            "PATH_AUTHORITY_AGGREGATE_INVALID"
        )

    observed = (
        tuple(
            item.get(
                "path"
            )
            for item in cases
        )
        + (
            aggregate.get(
                "path"
            ),
        )
    )

    if observed != SEVEN_FINAL_OUTPUTS:
        fail(
            "SEVEN_OUTPUT_PATH_AUTHORITY_MISMATCH"
        )


def validate_six_case_scope(
    target,
):
    contract = json.loads(
        (
            target[
                "root"
            ]
            / ACCEPTANCE_CONTRACT_REL
        ).read_text(
            encoding="utf-8"
        )
    )

    coverage = json.loads(
        (
            target[
                "root"
            ]
            / COVERAGE_MANIFEST_REL
        ).read_text(
            encoding="utf-8"
        )
    )

    contract_cases = tuple(
        (
            entry[
                "parameter_set"
            ],
            int(
                entry[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tg_id"
                ]
            ),
            int(
                entry[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tc_id"
                ]
            ),
            bool(
                entry[
                    "expected_valid"
                ]
            ),
            entry[
                "path"
            ],
        )
        for entry
        in contract[
            "covered_fixtures"
        ]
    )

    coverage_cases = tuple(
        (
            entry[
                "parameter_set"
            ],
            int(
                entry[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tg_id"
                ]
            ),
            int(
                entry[
                    "case_identity"
                ][
                    "coordinates"
                ][
                    "tc_id"
                ]
            ),
            bool(
                entry[
                    "expected_valid"
                ]
            ),
            entry[
                "fixture_path"
            ],
        )
        for entry
        in coverage[
            "cases"
        ]
    )

    expected_cases = tuple(
        (
            item[
                "parameter_set"
            ],
            item[
                "tg_id"
            ],
            item[
                "tc_id"
            ],
            item[
                "expected_valid"
            ],
            item[
                "fixture"
            ],
        )
        for item
        in SELECTED_CASES
    )

    if contract_cases != expected_cases:
        fail(
            "ACCEPTANCE_CONTRACT_SIX_CASE_SCOPE_MISMATCH"
        )

    if coverage_cases != expected_cases:
        fail(
            "COVERAGE_MANIFEST_SIX_CASE_SCOPE_MISMATCH"
        )


def validate_seven_output_absence(
    target,
):
    for rel in SEVEN_FINAL_OUTPUTS:
        path = (
            target[
                "root"
            ]
            / rel
        )

        if os.path.lexists(
            str(
                path
            )
        ):
            fail(
                "PREEXISTING_ACCEPTANCE_OUTPUT="
                + rel
            )


def validate_nist_input(
    path_value,
    expected_sha,
    label,
):
    path = pathlib.Path(
        path_value
    )

    if not path.is_absolute():
        fail(
            label
            + "_PATH_NOT_ABSOLUTE"
        )

    if path.is_symlink():
        fail(
            label
            + "_SYMLINK_NOT_ALLOWED"
        )

    if not path.is_file():
        fail(
            label
            + "_NOT_REGULAR_FILE"
        )

    if sha256_file(
        path
    ) != expected_sha:
        fail(
            label
            + "_SHA256_MISMATCH"
        )

    return path


def child_environment():
    verify_environment()

    environment = os.environ.copy()

    environment[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    for name in FORBIDDEN_ENVIRONMENT:
        if name in environment:
            fail(
                "FORBIDDEN_ENVIRONMENT_PROPAGATION="
                + name
            )

    return environment


def run_exact_python_child(
    interpreter,
    script,
    arguments,
    cwd,
    environment,
    label,
):
    if sha256_file(
        pathlib.Path(
            interpreter
        )
    ) != EXPECTED_INTERPRETER_SHA256:
        fail(
            "INTERPRETER_CHANGED_BEFORE_CHILD"
        )

    if (
        script.is_symlink()
        or not script.is_file()
    ):
        fail(
            label
            + "_SCRIPT_TYPE_INVALID"
        )

    process = subprocess.run(
        [
            str(
                interpreter
            ),
            str(
                script
            ),
            *arguments,
        ],
        cwd=str(
            cwd
        ),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        shell=False,
    )

    if process.returncode != 0:
        fail(
            label
            + "_FAILED:"
            + process.stdout.decode(
                "utf-8",
                "replace",
            )
            + process.stderr.decode(
                "utf-8",
                "replace",
            )
        )

    return process


def run_supplemental_verifier(
    target,
    interpreter,
    environment,
):
    script = (
        target[
            "root"
        ]
        / SUPPLEMENTAL_VERIFIER_REL
    )

    if sha256_file(
        script
    ) != SUPPLEMENTAL_VERIFIER_SHA256:
        fail(
            "SUPPLEMENTAL_VERIFIER_PRE_CHILD_SHA256_MISMATCH"
        )

    run_exact_python_child(
        interpreter,
        script,
        [
            "--root",
            str(
                target[
                    "root"
                ]
            ),
        ],
        target[
            "root"
        ],
        environment,
        "SUPPLEMENTAL_VERIFIER",
    )


def verify_temp_case_record(
    path,
    case,
):
    if (
        path.is_symlink()
        or not path.is_file()
    ):
        fail(
            "CASE_TEMP_OUTPUT_TYPE_INVALID"
        )

    try:
        record = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "CASE_TEMP_OUTPUT_JSON_INVALID="
            + repr(
                exc
            )
        )

    if record.get(
        "record_kind"
    ) != "case_acceptance":
        fail(
            "CASE_TEMP_OUTPUT_KIND_MISMATCH"
        )

    if record.get(
        "source_bound_verification_state"
    ) != "PASS":
        fail(
            "CASE_TEMP_OUTPUT_STATE_NOT_PASS"
        )

    if record.get(
        "reason_code"
    ) != "PASS":
        fail(
            "CASE_TEMP_OUTPUT_REASON_NOT_PASS"
        )

    identity = record.get(
        "case_identity"
    )

    expected_identity = {
        "parameter_set":
            case[
                "parameter_set"
            ],

        "primary":
            (
                "tg"
                + str(
                    case[
                        "tg_id"
                    ]
                )
                + "-tc"
                + str(
                    case[
                        "tc_id"
                    ]
                )
            ),

        "coordinates": {
            "tg_id":
                case[
                    "tg_id"
                ],

            "tc_id":
                case[
                    "tc_id"
                ],
        },

        "expected_valid":
            case[
                "expected_valid"
            ],
    }

    if identity != expected_identity:
        fail(
            "CASE_TEMP_OUTPUT_IDENTITY_MISMATCH"
        )


def verify_temp_aggregate(
    path,
):
    if (
        path.is_symlink()
        or not path.is_file()
    ):
        fail(
            "AGGREGATE_TEMP_OUTPUT_TYPE_INVALID"
        )

    try:
        record = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "AGGREGATE_TEMP_OUTPUT_JSON_INVALID="
            + repr(
                exc
            )
        )

    if record.get(
        "record_kind"
    ) != "aggregate_summary":
        fail(
            "AGGREGATE_TEMP_OUTPUT_KIND_MISMATCH"
        )

    if record.get(
        "expected_case_count"
    ) != 6:
        fail(
            "AGGREGATE_TEMP_OUTPUT_CASE_COUNT_MISMATCH"
        )

    if record.get(
        "aggregate_state"
    ) != "PASS":
        fail(
            "AGGREGATE_TEMP_OUTPUT_STATE_NOT_PASS"
        )

    if record.get(
        "global_f7_source_bound_acceptance"
    ) is not True:
        fail(
            "AGGREGATE_TEMP_OUTPUT_GLOBAL_ACCEPTANCE_NOT_TRUE"
        )

    if record.get(
        "source_bound_acceptance_complete"
    ) is not True:
        fail(
            "AGGREGATE_TEMP_OUTPUT_COMPLETE_NOT_TRUE"
        )


def finalize_no_overwrite(
    temp_path,
    final_path,
):
    if (
        temp_path.is_symlink()
        or not temp_path.is_file()
    ):
        fail(
            "TEMP_OUTPUT_TYPE_INVALID"
        )

    if os.path.lexists(
        str(
            final_path
        )
    ):
        fail(
            "FINAL_OUTPUT_ALREADY_EXISTS"
        )

    try:
        os.link(
            str(
                temp_path
            ),
            str(
                final_path
            ),
        )
    except FileExistsError:
        fail(
            "FINAL_OUTPUT_COLLISION"
        )
    except OSError as exc:
        fail(
            "FINAL_OUTPUT_LINK_FAILED="
            + repr(
                exc
            )
        )

    if (
        not final_path.is_file()
        or final_path.is_symlink()
    ):
        fail(
            "FINAL_OUTPUT_TYPE_INVALID_AFTER_LINK"
        )

    try:
        os.unlink(
            str(
                temp_path
            )
        )
    except OSError as exc:
        fail(
            "TEMP_NAME_REMOVAL_FAILED="
            + repr(
                exc
            )
        )


def revalidate_target_pre_child(
    target,
):
    verify_clean_repository(
        target[
            "root"
        ],
        require_untracked_empty=True,
    )

    if git_text(
        target[
            "root"
        ],
        (
            "rev-parse",
            "HEAD",
        ),
    ) != TARGET_COMMIT:
        fail(
            "TARGET_COMMIT_CHANGED_BEFORE_CHILD"
        )

    if git_text(
        target[
            "root"
        ],
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    ) != TARGET_TREE:
        fail(
            "TARGET_TREE_CHANGED_BEFORE_CHILD"
        )

    validate_seven_output_absence(
        target
    )


def run_case(
    target,
    interpreter,
    environment,
    nist_prompt,
    nist_expected,
    case,
    temp_output,
):
    script = (
        target[
            "root"
        ]
        / ACCEPTANCE_VERIFIER_REL
    )

    if sha256_file(
        script
    ) != ACCEPTANCE_VERIFIER_SHA256:
        fail(
            "ACCEPTANCE_VERIFIER_PRE_CHILD_SHA256_MISMATCH"
        )

    run_exact_python_child(
        interpreter,
        script,
        [
            "--root",
            str(
                target[
                    "root"
                ]
            ),
            "--mode",
            "case",
            "--fixture",
            case[
                "fixture"
            ],
            "--source-bound-requested",
            "yes",
            "--nist-prompt",
            str(
                nist_prompt
            ),
            "--nist-expected",
            str(
                nist_expected
            ),
            "--comparison-mode",
            "byte_identical_serialized_file_bytes",
            "--output",
            str(
                temp_output
            ),
        ],
        target[
            "root"
        ],
        environment,
        "ACCEPTANCE_CASE",
    )

    verify_temp_case_record(
        temp_output,
        case,
    )


def run_aggregate(
    target,
    interpreter,
    environment,
    temp_output,
):
    script = (
        target[
            "root"
        ]
        / ACCEPTANCE_VERIFIER_REL
    )

    if sha256_file(
        script
    ) != ACCEPTANCE_VERIFIER_SHA256:
        fail(
            "ACCEPTANCE_VERIFIER_PRE_AGGREGATE_SHA256_MISMATCH"
        )

    arguments = [
        "--root",
        str(
            target[
                "root"
            ]
        ),
        "--mode",
        "aggregate",
    ]

    for case in SELECTED_CASES:
        arguments.extend(
            [
                "--case-record",
                case[
                    "output"
                ],
            ]
        )

    arguments.extend(
        [
            "--output",
            str(
                temp_output
            ),
        ]
    )

    run_exact_python_child(
        interpreter,
        script,
        arguments,
        target[
            "root"
        ],
        environment,
        "ACCEPTANCE_AGGREGATE",
    )

    verify_temp_aggregate(
        temp_output
    )


def post_execution_audit(
    target,
):
    if git_text(
        target[
            "root"
        ],
        (
            "rev-parse",
            "HEAD",
        ),
    ) != TARGET_COMMIT:
        fail(
            "POST_EXECUTION_TARGET_COMMIT_CHANGED"
        )

    if git_text(
        target[
            "root"
        ],
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    ) != TARGET_TREE:
        fail(
            "POST_EXECUTION_TARGET_TREE_CHANGED"
        )

    staged = git_paths(
        target[
            "root"
        ],
        (
            "diff",
            "--cached",
            "--name-only",
            "-z",
        ),
    )

    unstaged = git_paths(
        target[
            "root"
        ],
        (
            "diff",
            "--name-only",
            "-z",
        ),
    )

    untracked = git_paths(
        target[
            "root"
        ],
        (
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
        ),
    )

    if staged:
        fail(
            "POST_EXECUTION_STAGED_PATH_PRESENT"
        )

    if unstaged:
        fail(
            "POST_EXECUTION_TRACKED_WORKTREE_DIRTY"
        )

    if untracked != tuple(
        sorted(
            SEVEN_FINAL_OUTPUTS
        )
    ):
        fail(
            "POST_EXECUTION_UNTRACKED_SET_MISMATCH"
        )


def execute_acceptance_session(
    control,
    target,
    authority,
    nist_prompt,
    nist_expected,
):
    validate_r2_publication_relation(
        control,
        authority,
    )

    validate_launcher_self_binding(
        control,
        authority,
    )

    ensure_control_target_separate(
        control[
            "root"
        ],
        target[
            "root"
        ],
    )

    validate_bound_target_artifacts(
        target,
        authority,
    )

    validate_prospective_authority(
        target
    )

    validate_six_case_scope(
        target
    )

    validate_path_authority(
        target
    )

    validate_seven_output_absence(
        target
    )

    interpreter = verify_interpreter()

    prompt_path = validate_nist_input(
        nist_prompt,
        NIST_PROMPT_SHA256,
        "NIST_PROMPT",
    )

    expected_path = validate_nist_input(
        nist_expected,
        NIST_EXPECTED_SHA256,
        "NIST_EXPECTED",
    )

    if (
        prompt_path.resolve()
        == expected_path.resolve()
    ):
        fail(
            "NIST_SOURCE_PATHS_MUST_BE_DISTINCT"
        )

    environment = child_environment()

    run_supplemental_verifier(
        target,
        interpreter,
        environment,
    )

    revalidate_target_pre_child(
        target
    )

    if sha256_file(
        interpreter
    ) != EXPECTED_INTERPRETER_SHA256:
        fail(
            "INTERPRETER_CHANGED_BEFORE_ACCEPTANCE_CHILD"
        )

    output_dir = (
        target[
            "root"
        ]
        / pathlib.PurePosixPath(
            AGGREGATE_OUTPUT_REL
        ).parent
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tempfile.TemporaryDirectory(
        prefix=".qsv-sb2r-r1-",
        dir=str(
            output_dir
        ),
    ) as temp_name:
        temp_root = pathlib.Path(
            temp_name
        )

        for index, case in enumerate(
            SELECTED_CASES,
            start=1,
        ):
            temp_output = (
                temp_root
                / (
                    "case-"
                    + str(
                        index
                    )
                    + ".json"
                )
            )

            run_case(
                target,
                interpreter,
                environment,
                prompt_path,
                expected_path,
                case,
                temp_output,
            )

            final_path = (
                target[
                    "root"
                ]
                / case[
                    "output"
                ]
            )

            finalize_no_overwrite(
                temp_output,
                final_path,
            )

        aggregate_temp = (
            temp_root
            / "aggregate.json"
        )

        run_aggregate(
            target,
            interpreter,
            environment,
            aggregate_temp,
        )

        finalize_no_overwrite(
            aggregate_temp,
            (
                target[
                    "root"
                ]
                / AGGREGATE_OUTPUT_REL
            ),
        )

    post_execution_audit(
        target
    )


def parse_arguments():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--control-root",
        required=True,
    )

    parser.add_argument(
        "--target-root",
        required=True,
    )

    parser.add_argument(
        "--execution-authority-commit",
        required=True,
    )

    parser.add_argument(
        "--nist-prompt",
        required=True,
    )

    parser.add_argument(
        "--nist-expected",
        required=True,
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    try:
        verify_environment()

        control = validate_control_repository(
            args.control_root,
            args.execution_authority_commit,
        )

        authority, _ = (
            load_r2_authority_from_git_object(
                control
            )
        )

        validate_r2_authority(
            authority
        )

        target = validate_target_repository(
            args.target_root
        )

        execute_acceptance_session(
            control,
            target,
            authority,
            args.nist_prompt,
            args.nist_expected,
        )

    except (
        LauncherError,
        AssertionError,
        KeyError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(
            "QSV_SB2R_EXACT_INVOCATION_LAUNCHER_V0_2=BLOCKED",
            file=sys.stderr,
        )

        print(
            "BLOCKER="
            + (
                str(
                    exc
                )
                if str(
                    exc
                )
                else exc.__class__.__name__
            ),
            file=sys.stderr,
        )

        print(
            "NEW_CRYPTO_EXECUTION_PERFORMED=NO",
            file=sys.stderr,
        )

        return 1

    print(
        "QSV_SB2R_EXACT_INVOCATION_LAUNCHER_V0_2=PASS"
    )

    print(
        "SOURCE_BOUND_ACCEPTANCE_SESSION_COMPLETE=YES"
    )

    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
