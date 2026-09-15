#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
from typing import Any, Dict, List


EVIDENCE_SCHEMA = (
    "qsv.mldsa.f7-instrumented-sixcase-runtime-evidence.v0.1"
)

INVOCATION_SCHEMA = (
    "qsv.mldsa.f7-runtime-invocation-evidence.v0.1"
)

CONTRACT_SCHEMA = (
    "qsv.mldsa.f7-exact-invocation-evidence-capture-contract.v0.1"
)

FIXTURE_SCHEMA = (
    "qsv.mldsa.runtime-sixcase-metadata.v0.1"
)

HEX40 = re.compile(
    r"^[0-9a-f]{40}$"
)

HEX64 = re.compile(
    r"^[0-9a-f]{64}$"
)

EXPECTED_CASES = {
    "ML-DSA-44-tg1-tc1":
        ("ML-DSA-44", 1, 1, False),

    "ML-DSA-44-tg1-tc3":
        ("ML-DSA-44", 1, 3, True),

    "ML-DSA-65-tg3-tc31":
        ("ML-DSA-65", 3, 31, False),

    "ML-DSA-65-tg3-tc33":
        ("ML-DSA-65", 3, 33, True),

    "ML-DSA-87-tg5-tc61":
        ("ML-DSA-87", 5, 61, False),

    "ML-DSA-87-tg5-tc63":
        ("ML-DSA-87", 5, 63, True),
}

ROLE_TO_FIXTURE_PREFIX = {
    "public_key": "pk",
    "message": "message",
    "context": "context",
    "signature": "signature",
}

EXPECTED_RUNTIME_METHOD = (
    "same_python_argv_object_recorded_and_passed_to_"
    "subprocess_run_shell_false"
)


class VerificationError(Exception):
    pass


def require(
    condition: bool,
    label: str,
) -> None:
    if not condition:
        raise VerificationError(label)


def read_json(
    path: Path,
) -> Dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        raise VerificationError(
            f"json_read_failed:{path}:{exc}"
        ) from exc

    require(
        isinstance(value, dict),
        f"json_root_not_object:{path}",
    )

    return value


def sha256_bytes(
    data: bytes,
) -> str:
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(
    path: Path,
) -> str:
    require(
        path.is_file(),
        f"missing_file:{path}",
    )

    h = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def require_hex40(
    value: Any,
    label: str,
) -> None:
    require(
        isinstance(value, str)
        and HEX40.fullmatch(value)
        is not None,
        label,
    )


def require_hex64(
    value: Any,
    label: str,
) -> None:
    require(
        isinstance(value, str)
        and HEX64.fullmatch(value)
        is not None,
        label,
    )


def verify_sidecar(
    target: Path,
) -> None:
    sidecar = target.with_name(
        target.name + ".sha256"
    )

    require(
        sidecar.is_file(),
        "evidence_sidecar_missing",
    )

    parts = sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    require(
        len(parts) == 2,
        "evidence_sidecar_token_count",
    )

    declared_hash = parts[0]
    declared_target = parts[1]

    actual_hash = sha256_file(
        target
    )

    require(
        declared_hash == actual_hash,
        "evidence_sidecar_hash_mismatch",
    )

    require(
        declared_target
        in {
            target.name,
            target.as_posix(),
        },
        "evidence_sidecar_target_mismatch",
    )


def verify_static_identity(
    identity: Dict[str, Any],
    actual_path: Path,
    expected_path: str,
    label: str,
) -> str:
    require(
        isinstance(identity, dict),
        f"{label}_identity_not_object",
    )

    require(
        identity.get("path")
        == expected_path,
        f"{label}_path_mismatch",
    )

    actual_sha = sha256_file(
        actual_path
    )

    require(
        identity.get("sha256")
        == actual_sha,
        f"{label}_sha256_mismatch",
    )

    return actual_sha


def fixture_case_map(
    fixture: Dict[str, Any],
) -> Dict[str, Dict[str, Any]]:
    require(
        fixture.get("schema")
        == FIXTURE_SCHEMA,
        "fixture_schema",
    )

    require(
        fixture.get("payload_embedded")
        is False,
        "fixture_payload_embedded",
    )

    require(
        fixture.get(
            "runtime_payload_emitted"
        )
        is True,
        "fixture_runtime_payload_emitted",
    )

    require(
        fixture.get("case_count")
        == 6,
        "fixture_case_count",
    )

    cases = fixture.get("cases")

    require(
        isinstance(cases, list)
        and len(cases) == 6,
        "fixture_cases_shape",
    )

    result: Dict[
        str,
        Dict[str, Any],
    ] = {}

    for case in cases:
        require(
            isinstance(case, dict),
            "fixture_case_not_object",
        )

        parameter_set = case.get(
            "parameter_set"
        )

        tg_id = case.get("tg_id")
        tc_id = case.get("tc_id")
        expected_valid = case.get(
            "expected_valid"
        )

        case_id = (
            f"{parameter_set}"
            f"-tg{tg_id}"
            f"-tc{tc_id}"
        )

        require(
            case_id
            in EXPECTED_CASES,
            f"fixture_case_out_of_scope:{case_id}",
        )

        require(
            EXPECTED_CASES[
                case_id
            ]
            == (
                parameter_set,
                tg_id,
                tc_id,
                expected_valid,
            ),
            f"fixture_case_semantics:{case_id}",
        )

        require(
            case_id not in result,
            f"fixture_duplicate_case:{case_id}",
        )

        for prefix in (
            "pk",
            "message",
            "context",
            "signature",
        ):
            require_hex64(
                case.get(
                    prefix + "_sha256"
                ),
                (
                    f"fixture_{prefix}"
                    f"_sha256:{case_id}"
                ),
            )

            size = case.get(
                prefix + "_size_bytes"
            )

            require(
                isinstance(size, int)
                and not isinstance(
                    size,
                    bool,
                )
                and size >= 0,
                (
                    f"fixture_{prefix}"
                    f"_size:{case_id}"
                ),
            )

        result[case_id] = case

    require(
        set(result)
        == set(EXPECTED_CASES),
        "fixture_exact_case_set",
    )

    return result


def verify_contract(
    contract: Dict[str, Any],
) -> None:
    require(
        contract.get("schema")
        == CONTRACT_SCHEMA,
        "contract_schema",
    )

    prior = contract.get(
        "prior_ogc_3_state"
    )

    require(
        isinstance(prior, dict),
        "contract_prior_ogc3",
    )

    require(
        prior.get(
            "ogc_3_final_decision"
        )
        == "PATH_B",
        "contract_ogc3_path_b",
    )

    require(
        prior.get(
            "existing_run_id"
        )
        == 34183766166,
        "contract_historical_run_id",
    )

    require(
        prior.get(
            "existing_job_id"
        )
        == 101927914418,
        "contract_historical_job_id",
    )

    require(
        prior.get(
            "existing_exact_command_proven"
        )
        is False,
        "contract_historical_exact_not_proven",
    )

    require(
        prior.get(
            "existing_exact_command_reconstructed"
        )
        is False,
        "contract_historical_exact_not_reconstructed",
    )

    require(
        prior.get(
            "historical_run_exact_command_must_not_be_backfilled"
        )
        is True,
        "contract_no_historical_backfill",
    )

    capture = contract.get(
        "runtime_capture"
    )

    require(
        isinstance(capture, dict),
        "contract_runtime_capture",
    )

    require(
        capture.get("shell")
        is False,
        "contract_shell_false",
    )

    require(
        capture.get(
            "argv_for_execution_equals_argv_recorded_as_evidence"
        )
        is True,
        "contract_same_argv_object",
    )

    require(
        capture.get(
            "captured_at_execution"
        )
        is True,
        "contract_captured_at_execution",
    )

    require(
        capture.get(
            "reconstructed_after_execution"
        )
        is False,
        "contract_not_reconstructed",
    )

    require(
        capture.get(
            "execution_environment_policy"
        )
        == (
            "inherit_parent_environment_plus_"
            "explicit_allowlisted_overrides"
        ),
        "contract_execution_environment_policy",
    )

    require(
        capture.get(
            "public_environment_capture_policy"
        )
        == "explicit_allowlist_only",
        "contract_public_environment_policy",
    )

    require(
        capture.get(
            "inherited_parent_environment_published"
        )
        is False,
        "contract_parent_environment_not_published",
    )


def verify_invocation(
    invocation: Dict[str, Any],
    required_fields: List[str],
    fixture_cases: Dict[
        str,
        Dict[str, Any],
    ],
    contract: Dict[str, Any],
    workflow_sha: str,
    launcher_sha: str,
    expected_commit: str,
    expected_tree: str,
    build_observations: Dict[
        str,
        Any,
    ],
    metadata_only_post_run: bool,
) -> tuple[str, str]:
    require(
        isinstance(invocation, dict),
        "invocation_not_object",
    )

    missing = [
        field
        for field in required_fields
        if field not in invocation
    ]

    require(
        not missing,
        "invocation_required_fields_missing:"
        + ",".join(missing),
    )

    require(
        invocation["schema"]
        == INVOCATION_SCHEMA,
        "invocation_schema",
    )

    require(
        invocation[
            "format_version"
        ]
        == "0.1",
        "invocation_format_version",
    )

    invocation_id = invocation[
        "invocation_id"
    ]

    require(
        isinstance(invocation_id, str)
        and bool(invocation_id),
        "invocation_id",
    )

    implementation = invocation[
        "implementation"
    ]

    require(
        implementation
        in {
            "openssl",
            "cloudflare-circl",
        },
        f"implementation:{invocation_id}",
    )

    covered = invocation[
        "covered_case_ids"
    ]

    require(
        isinstance(covered, list)
        and len(covered) == 1,
        f"covered_case_ids:{invocation_id}",
    )

    case_id = covered[0]

    require(
        case_id in fixture_cases,
        f"case_not_in_fixture:{invocation_id}",
    )

    require(
        case_id in EXPECTED_CASES,
        f"case_not_in_scope:{invocation_id}",
    )

    parameter_set, tg_id, tc_id, expected_valid = (
        EXPECTED_CASES[case_id]
    )

    scope = invocation[
        "execution_scope"
    ]

    require(
        isinstance(scope, dict),
        f"scope_not_object:{invocation_id}",
    )

    require(
        scope.get("algorithm")
        == "ML-DSA",
        f"scope_algorithm:{invocation_id}",
    )

    require(
        scope.get("operation")
        == "sigVer",
        f"scope_operation:{invocation_id}",
    )

    require(
        scope.get("case_id")
        == case_id,
        f"scope_case_id:{invocation_id}",
    )

    require(
        scope.get("parameter_set")
        == parameter_set,
        f"scope_parameter_set:{invocation_id}",
    )

    require(
        scope.get("tg_id")
        == tg_id,
        f"scope_tg_id:{invocation_id}",
    )

    require(
        scope.get("tc_id")
        == tc_id,
        f"scope_tc_id:{invocation_id}",
    )

    require(
        scope.get("expected_valid")
        is expected_valid,
        f"scope_expected_valid:{invocation_id}",
    )

    require(
        invocation[
            "captured_at_execution"
        ]
        is True,
        f"captured_at_execution:{invocation_id}",
    )

    require(
        invocation[
            "reconstructed_after_execution"
        ]
        is False,
        f"reconstructed_after_execution:{invocation_id}",
    )

    require(
        invocation["shell"]
        is False,
        f"shell_false:{invocation_id}",
    )

    require(
        invocation[
            "runtime_capture_method"
        ]
        == EXPECTED_RUNTIME_METHOD,
        f"capture_method:{invocation_id}",
    )

    require(
        invocation[
            "cryptographic_execution"
        ]
        is True,
        f"cryptographic_execution:{invocation_id}",
    )

    require(
        invocation[
            "metadata_only_publication"
        ]
        is True,
        f"metadata_only:{invocation_id}",
    )

    require(
        invocation[
            "process_started"
        ]
        is True,
        f"process_started:{invocation_id}",
    )

    require(
        invocation[
            "launch_error"
        ]
        is None,
        f"launch_error:{invocation_id}",
    )

    exit_code = invocation[
        "exit_code"
    ]

    require(
        isinstance(exit_code, int)
        and not isinstance(
            exit_code,
            bool,
        ),
        f"exit_code_type:{invocation_id}",
    )

    result_state = invocation[
        "result_state"
    ]

    allowed_states = {
        "process_exit_success",
        "process_exit_error",
        "process_launch_error",
    }

    require(
        result_state
        in allowed_states,
        f"unknown_result_state:{invocation_id}",
    )

    if result_state == (
        "process_exit_success"
    ):
        require(
            exit_code == 0,
            (
                "success_with_nonzero_exit:"
                + invocation_id
            ),
        )

    require(
        result_state
        == "process_exit_success",
        (
            "invocation_not_success:"
            + invocation_id
        ),
    )

    exact_argv = invocation[
        "exact_argv"
    ]

    require(
        isinstance(exact_argv, list)
        and len(exact_argv) > 0
        and all(
            isinstance(item, str)
            for item in exact_argv
        ),
        f"exact_argv:{invocation_id}",
    )

    exact_command = invocation[
        "exact_command"
    ]

    require(
        isinstance(exact_command, str)
        and bool(exact_command),
        f"exact_command_empty:{invocation_id}",
    )

    require(
        exact_command
        == shlex.join(
            exact_argv
        ),
        (
            "exact_command_argv_mismatch:"
            + invocation_id
        ),
    )

    resolved_executable_path = invocation[
        "resolved_executable_path"
    ]

    require(
        isinstance(
            resolved_executable_path,
            str,
        )
        and bool(
            resolved_executable_path
        ),
        (
            "resolved_executable_path:"
            + invocation_id
        ),
    )

    resolved_executable = Path(
        resolved_executable_path
    )

    resolved_executable_sha256 = invocation[
        "resolved_executable_sha256"
    ]

    require_hex64(
        resolved_executable_sha256,
        (
            "resolved_executable_sha256:"
            + invocation_id
        ),
    )

    require(
        exact_argv[0]
        == resolved_executable_path,
        (
            "argv0_executable_mismatch:"
            + invocation_id
        ),
    )

    if not metadata_only_post_run:
        require(
            resolved_executable.is_file(),
            (
                "resolved_executable_missing:"
                + invocation_id
            ),
        )

        require(
            sha256_file(
                resolved_executable
            )
            == resolved_executable_sha256,
            (
                "resolved_executable_runtime_hash:"
                + invocation_id
            ),
        )

    require(
        len(exact_argv) == 7,
        (
            "harness_argv_length:"
            + invocation_id
        ),
    )

    require(
        exact_argv[1]
        == parameter_set,
        (
            "argv_parameter_set:"
            + invocation_id
        ),
    )

    require(
        exact_argv[6]
        == (
            "true"
            if expected_valid
            else "false"
        ),
        (
            "argv_expected_valid:"
            + invocation_id
        ),
    )

    require(
        invocation[
            "repository_commit"
        ]
        == expected_commit,
        (
            "invocation_commit_binding:"
            + invocation_id
        ),
    )

    require(
        invocation[
            "repository_tree"
        ]
        == expected_tree,
        (
            "invocation_tree_binding:"
            + invocation_id
        ),
    )

    workflow_identity = invocation[
        "workflow_identity"
    ]

    require(
        isinstance(
            workflow_identity,
            dict,
        ),
        (
            "workflow_identity:"
            + invocation_id
        ),
    )

    require(
        workflow_identity.get(
            "sha256"
        )
        == workflow_sha,
        (
            "workflow_sha_mismatch:"
            + invocation_id
        ),
    )

    launcher_identity = invocation[
        "capture_launcher_identity"
    ]

    require(
        isinstance(
            launcher_identity,
            dict,
        ),
        (
            "launcher_identity:"
            + invocation_id
        ),
    )

    require(
        launcher_identity.get(
            "sha256"
        )
        == launcher_sha,
        (
            "launcher_sha_mismatch:"
            + invocation_id
        ),
    )

    require(
        invocation[
            "allowlisted_environment"
        ]
        == {
            "QSV_EXECUTE_CRYPTO":
                "YES"
        },
        (
            "allowlisted_environment:"
            + invocation_id
        ),
    )

    require(
        invocation.get(
            "execution_environment_policy"
        )
        == (
            "inherit_parent_environment_plus_"
            "explicit_allowlisted_overrides"
        ),
        (
            "execution_environment_policy:"
            + invocation_id
        ),
    )

    require(
        invocation.get(
            "public_environment_capture_policy"
        )
        == "explicit_allowlist_only",
        (
            "public_environment_policy:"
            + invocation_id
        ),
    )

    require(
        invocation.get(
            "inherited_parent_environment_published"
        )
        is False,
        (
            "inherited_environment_published:"
            + invocation_id
        ),
    )

    artifacts = invocation[
        "input_artifacts"
    ]

    require(
        isinstance(artifacts, list)
        and len(artifacts) == 4,
        (
            "input_artifact_count:"
            + invocation_id
        ),
    )

    by_role: Dict[
        str,
        Dict[str, Any],
    ] = {}

    for artifact in artifacts:
        require(
            isinstance(artifact, dict),
            (
                "input_artifact_not_object:"
                + invocation_id
            ),
        )

        role = artifact.get("role")

        require(
            role
            in ROLE_TO_FIXTURE_PREFIX,
            (
                "input_artifact_role:"
                + invocation_id
            ),
        )

        require(
            role not in by_role,
            (
                "duplicate_input_role:"
                + invocation_id
            ),
        )

        by_role[role] = artifact

    require(
        set(by_role)
        == set(ROLE_TO_FIXTURE_PREFIX),
        (
            "input_artifact_roles:"
            + invocation_id
        ),
    )

    fixture_case = fixture_cases[
        case_id
    ]

    ordered_roles = (
        "public_key",
        "message",
        "context",
        "signature",
    )

    actual_argv_paths = []

    for role in ordered_roles:
        artifact = by_role[role]

        artifact_path_text = artifact.get(
            "path"
        )

        require(
            isinstance(
                artifact_path_text,
                str,
            )
            and bool(
                artifact_path_text
            ),
            (
                "input_artifact_path:"
                + invocation_id
                + ":"
                + role
            ),
        )

        artifact_sha256 = artifact.get(
            "sha256"
        )

        require_hex64(
            artifact_sha256,
            (
                "input_artifact_sha256:"
                + invocation_id
                + ":"
                + role
            ),
        )

        artifact_byte_count = artifact.get(
            "byte_count"
        )

        require(
            isinstance(
                artifact_byte_count,
                int,
            )
            and not isinstance(
                artifact_byte_count,
                bool,
            )
            and artifact_byte_count >= 0,
            (
                "input_artifact_byte_count:"
                + invocation_id
                + ":"
                + role
            ),
        )

        prefix = (
            ROLE_TO_FIXTURE_PREFIX[
                role
            ]
        )

        expected_hash = fixture_case[
            prefix + "_sha256"
        ]

        expected_size = fixture_case[
            prefix + "_size_bytes"
        ]

        require(
            artifact_sha256
            == expected_hash,
            (
                "input_fixture_hash_mismatch:"
                + invocation_id
                + ":"
                + role
            ),
        )

        require(
            artifact_byte_count
            == expected_size,
            (
                "input_fixture_size:"
                + invocation_id
                + ":"
                + role
            ),
        )

        if not metadata_only_post_run:
            artifact_path = Path(
                artifact_path_text
            )

            require(
                artifact_path.is_file(),
                (
                    "input_file_missing:"
                    + invocation_id
                    + ":"
                    + role
                ),
            )

            require(
                sha256_file(
                    artifact_path
                )
                == artifact_sha256,
                (
                    "input_artifact_actual_hash:"
                    + invocation_id
                    + ":"
                    + role
                ),
            )

            require(
                artifact_path.stat().st_size
                == artifact_byte_count,
                (
                    "input_actual_size:"
                    + invocation_id
                    + ":"
                    + role
                ),
            )

        actual_argv_paths.append(
            artifact_path_text
        )

    require(
        exact_argv[2:6]
        == actual_argv_paths,
        (
            "argv_input_path_binding:"
            + invocation_id
        ),
    )

    stdout_hash = invocation[
        "stdout_sha256"
    ]

    stderr_hash = invocation[
        "stderr_sha256"
    ]

    require_hex64(
        stdout_hash,
        (
            "stdout_sha256:"
            + invocation_id
        ),
    )

    require_hex64(
        stderr_hash,
        (
            "stderr_sha256:"
            + invocation_id
        ),
    )

    for label in (
        "stdout_byte_count",
        "stderr_byte_count",
    ):
        value = invocation[label]

        require(
            isinstance(value, int)
            and not isinstance(
                value,
                bool,
            )
            and value >= 0,
            (
                label
                + ":"
                + invocation_id
            ),
        )

    require(
        "stdout" not in invocation,
        (
            "raw_stdout_embedded:"
            + invocation_id
        ),
    )

    require(
        "stderr" not in invocation,
        (
            "raw_stderr_embedded:"
            + invocation_id
        ),
    )

    source_authority = invocation[
        "implementation_source_authority"
    ]

    require(
        isinstance(
            source_authority,
            dict,
        ),
        (
            "source_authority:"
            + invocation_id
        ),
    )

    authorities = contract[
        "implementation_authorities"
    ]

    if implementation == "openssl":
        expected_authority = authorities[
            "openssl"
        ]

        require(
            invocation[
                "implementation_version"
            ]
            == expected_authority[
                "runtime_version_required"
            ],
            (
                "openssl_version:"
                + invocation_id
            ),
        )

        expected_binary_hash = (
            build_observations[
                "openssl_harness_binary_sha256"
            ]
        )

    else:
        expected_authority = authorities[
            "circl"
        ]

        require(
            invocation[
                "implementation_version"
            ]
            == expected_authority[
                "implementation_version_identifier"
            ],
            (
                "circl_version:"
                + invocation_id
            ),
        )

        expected_binary_hash = (
            build_observations[
                "circl_harness_binary_sha256"
            ]
        )

    require(
        source_authority.get(
            "repository"
        )
        == expected_authority[
            "repository"
        ],
        (
            "source_repository:"
            + invocation_id
        ),
    )

    require(
        source_authority.get(
            "commit"
        )
        == expected_authority[
            "source_commit"
        ],
        (
            "source_commit:"
            + invocation_id
        ),
    )

    require(
        source_authority.get(
            "tree"
        )
        == expected_authority[
            "source_tree"
        ],
        (
            "source_tree:"
            + invocation_id
        ),
    )

    require_hex64(
        expected_binary_hash,
        "expected_harness_binary_hash",
    )

    require(
        resolved_executable_sha256
        == expected_binary_hash,
        (
            "harness_binary_hash:"
            + invocation_id
        ),
    )

    github = invocation[
        "github"
    ]

    require(
        isinstance(github, dict),
        (
            "github_binding:"
            + invocation_id
        ),
    )

    require(
        github.get(
            "GITHUB_SHA"
        )
        == expected_commit,
        (
            "github_sha:"
            + invocation_id
        ),
    )

    require(
        github.get(
            "GITHUB_REF"
        )
        == "refs/heads/main",
        (
            "github_ref:"
            + invocation_id
        ),
    )

    job_id = github.get(
        "github_job_id_numeric"
    )

    job_status = github.get(
        "job_id_binding_status"
    )

    if job_id is None:
        require(
            job_status
            == "post_run_binding_required",
            (
                "job_binding_status:"
                + invocation_id
            ),
        )
    else:
        require(
            isinstance(job_id, int)
            and not isinstance(
                job_id,
                bool,
            )
            and job_id > 0,
            (
                "numeric_job_id:"
                + invocation_id
            ),
        )

        require(
            job_status
            == "runtime_bound",
            (
                "runtime_job_binding_status:"
                + invocation_id
            ),
        )

    return (
        implementation,
        case_id,
    )


def verify(
    args: argparse.Namespace,
) -> None:
    evidence_path = Path(
        args.evidence
    )

    contract_path = Path(
        args.contract
    )

    workflow_path = Path(
        args.workflow
    )

    launcher_path = Path(
        args.capture_launcher
    )

    fixture_path = Path(
        args.fixture_manifest
    )

    verifier_path = Path(
        __file__
    ).resolve(
        strict=True
    )

    require_hex40(
        args.expected_repository_commit,
        "expected_repository_commit",
    )

    require_hex40(
        args.expected_repository_tree,
        "expected_repository_tree",
    )

    evidence = read_json(
        evidence_path
    )

    contract = read_json(
        contract_path
    )

    fixture = read_json(
        fixture_path
    )

    verify_sidecar(
        evidence_path
    )

    verify_contract(
        contract
    )

    workflow_sha = sha256_file(
        workflow_path
    )

    launcher_sha = sha256_file(
        launcher_path
    )

    contract_sha = sha256_file(
        contract_path
    )

    verifier_sha = sha256_file(
        verifier_path
    )

    planned = contract[
        "planned_phase_a_static_artifacts"
    ]

    verify_static_identity(
        evidence[
            "workflow_identity"
        ],
        workflow_path,
        planned[
            "manual_workflow"
        ][
            "path"
        ],
        "workflow",
    )

    verify_static_identity(
        evidence[
            "capture_launcher_identity"
        ],
        launcher_path,
        planned[
            "capture_launcher"
        ][
            "path"
        ],
        "capture_launcher",
    )

    verify_static_identity(
        evidence[
            "capture_contract_identity"
        ],
        contract_path,
        planned[
            "this_contract"
        ][
            "path"
        ],
        "capture_contract",
    )

    verify_static_identity(
        evidence[
            "offline_verifier_identity"
        ],
        verifier_path,
        planned[
            "offline_verifier"
        ][
            "path"
        ],
        "offline_verifier",
    )

    require(
        evidence.get("schema")
        == EVIDENCE_SCHEMA,
        "evidence_schema",
    )

    require(
        evidence.get(
            "format_version"
        )
        == "0.1",
        "evidence_format_version",
    )

    if args.test_only_synthetic:
        require(
            evidence.get("status")
            == (
                "test_only_synthetic_future_shape_"
                "not_runtime_evidence"
            ),
            "synthetic_test_status",
        )
    else:
        require(
            evidence.get("status")
            == (
                "first_party_instrumented_"
                "reproduction_runtime_evidence"
            ),
            "runtime_evidence_status",
        )

    require(
        evidence.get(
            "repository_commit"
        )
        == args.expected_repository_commit,
        "aggregate_commit_binding",
    )

    require(
        evidence.get(
            "repository_tree"
        )
        == args.expected_repository_tree,
        "aggregate_tree_binding",
    )

    fixture_bytes = (
        fixture_path.read_bytes()
    )

    fixture_identity = evidence[
        "fixture_manifest"
    ]

    require(
        isinstance(
            fixture_identity,
            dict,
        ),
        "fixture_identity",
    )

    require(
        fixture_identity.get(
            "sha256"
        )
        == sha256_bytes(
            fixture_bytes
        ),
        "fixture_manifest_sha256",
    )

    fixture_cases = fixture_case_map(
        fixture
    )

    require(
        fixture_identity.get(
            "schema"
        )
        == FIXTURE_SCHEMA,
        "fixture_identity_schema",
    )

    require(
        fixture_identity.get(
            "payload_embedded"
        )
        is False,
        "fixture_identity_payload",
    )

    require(
        fixture_identity.get(
            "runtime_payload_emitted"
        )
        is True,
        "fixture_identity_runtime_payload",
    )

    require(
        fixture_identity.get(
            "case_count"
        )
        == 6,
        "fixture_identity_case_count",
    )

    require(
        fixture_identity.get(
            "cases"
        )
        == fixture.get("cases"),
        "fixture_identity_cases",
    )

    scope = evidence[
        "execution_scope"
    ]

    require(
        scope
        == {
            "algorithm": "ML-DSA",
            "implementation_count": 2,
            "operation": "sigVer",
            "process_invocation_count": 12,
            "selected_case_count": 6,
        },
        "aggregate_execution_scope",
    )

    build = evidence[
        "build_observations"
    ]

    require(
        isinstance(build, dict),
        "build_observations",
    )

    for field in (
        "openssl_built_binary_sha256",
        "openssl_built_libcrypto_sha256",
        "openssl_harness_binary_sha256",
        "circl_harness_binary_sha256",
    ):
        require_hex64(
            build.get(field),
            (
                "build_observation_"
                + field
            ),
        )

    invocations = evidence[
        "invocations"
    ]

    require(
        isinstance(invocations, list)
        and len(invocations) == 12,
        "invocation_list_count",
    )

    require(
        evidence.get(
            "invocation_count"
        )
        == 12,
        "aggregate_invocation_count",
    )

    required_fields = contract[
        "runtime_evidence_record"
    ][
        "required_fields"
    ]

    require(
        isinstance(
            required_fields,
            list,
        )
        and len(
            required_fields
        ) > 0,
        "contract_required_fields",
    )

    implementation_counts = {
        "openssl": 0,
        "cloudflare-circl": 0,
    }

    case_counts = {
        case_id: 0
        for case_id
        in EXPECTED_CASES
    }

    invocation_ids = set()

    for invocation in invocations:
        invocation_id = invocation.get(
            "invocation_id"
        )

        require(
            invocation_id
            not in invocation_ids,
            (
                "duplicate_invocation_id:"
                + str(
                    invocation_id
                )
            ),
        )

        invocation_ids.add(
            invocation_id
        )

        implementation, case_id = (
            verify_invocation(
                invocation,
                required_fields,
                fixture_cases,
                contract,
                workflow_sha,
                launcher_sha,
                args.expected_repository_commit,
                args.expected_repository_tree,
                build,
                args.metadata_only_post_run,
            )
        )

        implementation_counts[
            implementation
        ] += 1

        case_counts[
            case_id
        ] += 1

    require(
        implementation_counts
        == {
            "openssl": 6,
            "cloudflare-circl": 6,
        },
        "implementation_invocation_counts",
    )

    require(
        all(
            value == 2
            for value
            in case_counts.values()
        ),
        "per_case_invocation_counts",
    )

    summary = evidence[
        "summary"
    ]

    require(
        summary
        == {
            "case_count": 6,
            "circl_invocation_count": 6,
            "nonzero_exit_count": 0,
            "openssl_invocation_count": 6,
            "per_case_invocation_count": 2,
            "process_launch_error_count": 0,
        },
        "aggregate_summary",
    )

    semantics = evidence[
        "evidence_semantics"
    ]

    required_semantics = {
        "captured_at_execution":
            True,

        "reconstructed_after_execution":
            False,

        "process_launch_boundary_capture":
            True,

        "exact_argv_normative":
            True,

        "exact_command_derived_from_runtime_argv":
            True,

        "shell":
            False,

        "metadata_only_publication":
            True,

        "historical_run_exact_command_backfilled":
            False,

        "first_party_instrumented_reproduction":
            True,

        "third_party_independent_reproduction":
            False,
    }

    require(
        semantics
        == required_semantics,
        "evidence_semantics",
    )

    nonclaims = evidence[
        "nonclaims"
    ]

    require(
        nonclaims
        == {
            "absolute_immutability":
                False,

            "complete_fips_204_conformance":
                False,

            "complete_sigver_coverage":
                False,

            "entire_system_quantum_safe":
                False,

            "fips_204_certification":
                False,

            "formal_security_proof":
                False,

            "nist_validation":
                False,

            "vulnerability_free":
                False,
        },
        "nonclaims",
    )

    github = evidence[
        "github"
    ]

    require(
        isinstance(github, dict),
        "aggregate_github",
    )

    require(
        github.get(
            "github_sha"
        )
        == args.expected_repository_commit,
        "aggregate_github_sha",
    )

    require(
        github.get(
            "github_ref"
        )
        == "refs/heads/main",
        "aggregate_github_ref",
    )

    aggregate_job_id = github.get(
        "github_job_id_numeric"
    )

    aggregate_job_status = github.get(
        "job_id_binding_status"
    )

    if aggregate_job_id is None:
        require(
            aggregate_job_status
            == "post_run_binding_required",
            "aggregate_job_binding_status",
        )

        fully_bound = False

    else:
        require(
            isinstance(
                aggregate_job_id,
                int,
            )
            and not isinstance(
                aggregate_job_id,
                bool,
            )
            and aggregate_job_id > 0,
            "aggregate_numeric_job_id",
        )

        require(
            aggregate_job_status
            == "runtime_bound",
            "aggregate_runtime_job_status",
        )

        fully_bound = True

    print(
        "F7_OFFLINE_VERIFIER=PASS"
    )

    print(
        "F7_RUNTIME_INVOCATION_RECORD_COUNT=12"
    )

    print(
        "F7_OPENSSL_INVOCATION_COUNT=6"
    )

    print(
        "F7_CIRCL_INVOCATION_COUNT=6"
    )

    print(
        "F7_CASE_COUNT=6"
    )

    print(
        "F7_EACH_CASE_BOUND_TO_TWO_IMPLEMENTATION_INVOCATIONS=YES"
    )

    print(
        "F7_EXACT_ARGV_VERIFIED=YES"
    )

    print(
        "F7_EXACT_COMMAND_FROM_ARGV_VERIFIED=YES"
    )

    print(
        "F7_SHELL_FALSE_VERIFIED=YES"
    )

    print(
        "F7_CAPTURED_AT_EXECUTION_VERIFIED=YES"
    )

    print(
        "F7_RECONSTRUCTED_AFTER_EXECUTION=false"
    )

    print(
        "F7_INPUT_ARTIFACT_ACTUAL_SHA256_VERIFIED=YES"
    )

    print(
        "F7_INPUT_ARTIFACT_FIXTURE_BINDING_VERIFIED=YES"
    )

    print(
        "F7_WORKFLOW_SHA256_VERIFIED="
        + workflow_sha
    )

    print(
        "F7_CAPTURE_LAUNCHER_SHA256_VERIFIED="
        + launcher_sha
    )

    print(
        "F7_CAPTURE_CONTRACT_SHA256_VERIFIED="
        + contract_sha
    )

    print(
        "F7_OFFLINE_VERIFIER_SHA256_VERIFIED="
        + verifier_sha
    )

    print(
        "F7_REPOSITORY_COMMIT_BINDING_VERIFIED=YES"
    )

    print(
        "F7_REPOSITORY_TREE_BINDING_VERIFIED=YES"
    )

    print(
        "F7_SUCCESS_WITH_NONZERO_EXIT_ACCEPTED=NO"
    )

    print(
        "F7_UNKNOWN_STATE_PROMOTED_TO_PASS=NO"
    )

    if fully_bound:
        print(
            "F7_NUMERIC_GITHUB_JOB_ID_BOUND=YES"
        )

        print(
            "F7_EVIDENCE_FULLY_BOUND=YES"
        )

        print(
            "F7_EVIDENCE_VERIFICATION_STATE="
            "runtime_capture_verified_and_job_id_bound"
        )

    else:
        print(
            "F7_NUMERIC_GITHUB_JOB_ID_BOUND=NO"
        )

        print(
            "F7_POST_RUN_JOB_ID_BINDING_REQUIRED=YES"
        )

        print(
            "F7_EVIDENCE_FULLY_BOUND=NO"
        )

        print(
            "F7_EVIDENCE_VERIFICATION_STATE="
            "runtime_capture_verified_post_run_job_id_binding_required"
        )

    print(
        "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false"
    )

    print(
        "F7_FULL_CLOSURE=NO"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--evidence",
        required=True,
    )

    parser.add_argument(
        "--contract",
        required=True,
    )

    parser.add_argument(
        "--workflow",
        required=True,
    )

    parser.add_argument(
        "--capture-launcher",
        required=True,
    )

    parser.add_argument(
        "--fixture-manifest",
        required=True,
    )

    parser.add_argument(
        "--expected-repository-commit",
        required=True,
    )

    parser.add_argument(
        "--expected-repository-tree",
        required=True,
    )

    parser.add_argument(
        "--metadata-only-post-run",
        action="store_true",
        help=(
            "Verify F7 metadata-only runtime evidence "
            "without requiring ephemeral runtime input "
            "or harness files."
        ),
    )

    parser.add_argument(
        "--test-only-synthetic",
        action="store_true",
        help=(
            "Permit only the explicit synthetic "
            "self-test status. Never used by the "
            "production F7 workflow."
        ),
    )

    return parser


def main() -> int:
    parser = build_parser()

    args = parser.parse_args()

    try:
        verify(args)

    except VerificationError as exc:
        print(
            "F7_OFFLINE_VERIFIER=FAIL"
        )

        print(
            "F7_VERIFICATION_ERROR="
            + str(exc)
        )

        print(
            "F7_EVIDENCE_FULLY_BOUND=NO"
        )

        print(
            "F7_FULL_CLOSURE=NO"
        )

        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
