#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
from typing import Dict, List, Optional


FORMAT_IDENTIFIER = "qsv.mldsa.f7-runtime-invocation-evidence.v0.1"
FORMAT_VERSION = "0.1"

CAPTURE_METHOD = (
    "same_python_argv_object_recorded_and_passed_to_"
    "subprocess_run_shell_false"
)

ALLOWED_CHILD_ENVIRONMENT_NAMES = {
    "QSV_EXECUTE_CRYPTO",
}

GITHUB_ENVIRONMENT_NAMES = (
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_SHA",
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_JOB",
)

ALLOWED_PARAMETER_SETS = {
    "ML-DSA-44",
    "ML-DSA-65",
    "ML-DSA-87",
}

ALLOWED_IMPLEMENTATIONS = {
    "openssl",
    "cloudflare-circl",
}

ALLOWED_CASE_IDS = {
    "ML-DSA-44-tg1-tc1",
    "ML-DSA-44-tg1-tc3",
    "ML-DSA-65-tg3-tc31",
    "ML-DSA-65-tg3-tc33",
    "ML-DSA-87-tg5-tc61",
    "ML-DSA-87-tg5-tc63",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(1024 * 1024),
            b"",
        ):
            h.update(chunk)
    return h.hexdigest()


def parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError(
        "boolean value must be exactly true or false"
    )


def parse_env_assignment(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError(
            "environment assignment must be NAME=VALUE"
        )

    name, env_value = value.split("=", 1)

    if name not in ALLOWED_CHILD_ENVIRONMENT_NAMES:
        raise argparse.ArgumentTypeError(
            "environment variable is not allowlisted: "
            + name
        )

    return name, env_value


def regular_file(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            f"{label} cannot be resolved: {exc}"
        ) from exc

    if not resolved.is_file():
        raise ValueError(
            f"{label} is not a regular file"
        )

    return resolved


def resolve_executable(path: Path) -> Path:
    resolved = regular_file(
        path,
        "executable",
    )

    mode = resolved.stat().st_mode

    if not (
        mode
        & (
            stat.S_IXUSR
            | stat.S_IXGRP
            | stat.S_IXOTH
        )
    ):
        raise ValueError(
            "resolved executable is not executable"
        )

    return resolved


def artifact_identity(
    role: str,
    path: Path,
) -> Dict[str, object]:
    resolved = regular_file(
        path,
        role,
    )

    return {
        "role": role,
        "path": str(resolved),
        "sha256": sha256_file(resolved),
        "byte_count": resolved.stat().st_size,
    }


def github_binding() -> Dict[str, object]:
    values = {
        name: os.environ.get(name)
        for name in GITHUB_ENVIRONMENT_NAMES
    }

    numeric_job_id = None

    values["github_job_id_numeric"] = numeric_job_id

    if numeric_job_id is None:
        values[
            "job_id_binding_status"
        ] = "post_run_binding_required"
    else:
        values[
            "job_id_binding_status"
        ] = "runtime_bound"

    return values


def atomic_write_json(
    target: Path,
    value: Dict[str, object],
) -> None:
    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = target.with_name(
        target.name + ".tmp"
    )

    encoded = (
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    temporary.write_bytes(encoded)

    os.replace(
        temporary,
        target,
    )


def write_ephemeral_output(
    path_text: Optional[str],
    data: bytes,
) -> None:
    if path_text is None:
        return

    target = Path(path_text)

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    target.write_bytes(data)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--mode",
        required=True,
        choices=(
            "non-crypto-self-test",
            "instrumented-sixcase-crypto",
        ),
    )

    parser.add_argument(
        "--evidence-output",
        required=True,
    )

    parser.add_argument(
        "--invocation-id",
        required=True,
    )

    parser.add_argument(
        "--implementation",
        required=True,
    )

    parser.add_argument(
        "--implementation-version",
        required=True,
    )

    parser.add_argument(
        "--source-repository",
        required=True,
    )

    parser.add_argument(
        "--source-commit",
        required=True,
    )

    parser.add_argument(
        "--source-tree",
        required=True,
    )

    parser.add_argument(
        "--repository-commit",
        required=True,
    )

    parser.add_argument(
        "--repository-tree",
        required=True,
    )

    parser.add_argument(
        "--workflow-path",
        required=True,
    )

    parser.add_argument(
        "--expected-workflow-sha256",
        required=True,
    )

    parser.add_argument(
        "--expected-capture-launcher-sha256",
        required=True,
    )

    parser.add_argument(
        "--executable",
        required=True,
    )

    parser.add_argument(
        "--case-id",
        required=True,
    )

    parser.add_argument(
        "--parameter-set",
        required=True,
    )

    parser.add_argument(
        "--tg-id",
        required=True,
        type=int,
    )

    parser.add_argument(
        "--tc-id",
        required=True,
        type=int,
    )

    parser.add_argument(
        "--expected-valid",
        required=True,
        type=parse_bool,
    )

    parser.add_argument(
        "--public-key",
    )

    parser.add_argument(
        "--message",
    )

    parser.add_argument(
        "--context",
    )

    parser.add_argument(
        "--signature",
    )

    parser.add_argument(
        "--child-env",
        action="append",
        default=[],
        type=parse_env_assignment,
    )

    parser.add_argument(
        "--ephemeral-stdout-path",
    )

    parser.add_argument(
        "--ephemeral-stderr-path",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    launcher_path = Path(__file__).resolve(
        strict=True
    )

    launcher_sha256 = sha256_file(
        launcher_path
    )

    if (
        launcher_sha256
        != args.expected_capture_launcher_sha256
    ):
        raise SystemExit(
            "capture launcher SHA-256 mismatch"
        )

    workflow_path = regular_file(
        Path(args.workflow_path),
        "workflow",
    )

    workflow_sha256 = sha256_file(
        workflow_path
    )

    if (
        workflow_sha256
        != args.expected_workflow_sha256
    ):
        raise SystemExit(
            "workflow SHA-256 mismatch"
        )

    resolved_executable = resolve_executable(
        Path(args.executable)
    )

    child_environment = {}

    for name, value in args.child_env:
        if name in child_environment:
            raise SystemExit(
                "duplicate child environment variable: "
                + name
            )
        child_environment[name] = value

    # Preserve the existing workflow process semantics:
    #
    #     env QSV_EXECUTE_CRYPTO=YES <binary> ...
    #
    # inherits the parent process environment and overrides only the
    # explicitly supplied variable.  The complete inherited execution
    # environment is NEVER serialized into public evidence.
    execution_environment = os.environ.copy()
    execution_environment.update(
        child_environment
    )

    input_artifacts: List[
        Dict[str, object]
    ] = []

    if args.mode == "non-crypto-self-test":
        if str(resolved_executable) != "/usr/bin/printf":
            raise SystemExit(
                "non-crypto self-test executable must be "
                "/usr/bin/printf"
            )

        if child_environment:
            raise SystemExit(
                "non-crypto self-test child environment "
                "must be empty"
            )

        if any(
            value is not None
            for value in (
                args.public_key,
                args.message,
                args.context,
                args.signature,
            )
        ):
            raise SystemExit(
                "non-crypto self-test must not receive "
                "cryptographic input artifacts"
            )

        resolved_executable_sha256 = sha256_file(
            resolved_executable
        )

        argv_for_execution = [
            str(resolved_executable),
            "%s",
            "F7_CAPTURE_SELF_TEST",
        ]

        cryptographic_execution = False

        execution_scope = {
            "algorithm":
                "NONE",
            "operation":
                "non_crypto_capture_self_test",
            "case_id":
                args.case_id,
            "parameter_set":
                "NONE",
            "tg_id":
                args.tg_id,
            "tc_id":
                args.tc_id,
            "expected_valid":
                args.expected_valid,
        }

    else:
        if args.implementation not in ALLOWED_IMPLEMENTATIONS:
            raise SystemExit(
                "unsupported implementation"
            )

        if args.parameter_set not in ALLOWED_PARAMETER_SETS:
            raise SystemExit(
                "unsupported ML-DSA parameter set"
            )

        if args.case_id not in ALLOWED_CASE_IDS:
            raise SystemExit(
                "case ID is outside the fixed six-case scope"
            )

        expected_case_id = (
            f"{args.parameter_set}"
            f"-tg{args.tg_id}"
            f"-tc{args.tc_id}"
        )

        if args.case_id != expected_case_id:
            raise SystemExit(
                "case ID does not match parameter/tg/tc locator"
            )

        required_inputs = {
            "public_key": args.public_key,
            "message": args.message,
            "context": args.context,
            "signature": args.signature,
        }

        if any(
            value is None
            for value in required_inputs.values()
        ):
            raise SystemExit(
                "all four sigVer input artifacts are required"
            )

        if (
            child_environment.get(
                "QSV_EXECUTE_CRYPTO"
            )
            != "YES"
        ):
            raise SystemExit(
                "instrumented crypto execution requires "
                "allowlisted QSV_EXECUTE_CRYPTO=YES"
            )

        input_artifacts = [
            artifact_identity(
                role,
                Path(path_text),
            )
            for role, path_text
            in required_inputs.items()
        ]

        artifact_paths = {
            item["role"]: item["path"]
            for item in input_artifacts
        }

        resolved_executable_sha256 = sha256_file(
            resolved_executable
        )

        argv_for_execution = [
            str(resolved_executable),
            args.parameter_set,
            str(
                artifact_paths[
                    "public_key"
                ]
            ),
            str(
                artifact_paths[
                    "message"
                ]
            ),
            str(
                artifact_paths[
                    "context"
                ]
            ),
            str(
                artifact_paths[
                    "signature"
                ]
            ),
            (
                "true"
                if args.expected_valid
                else "false"
            ),
        ]

        cryptographic_execution = True

        execution_scope = {
            "algorithm":
                "ML-DSA",
            "operation":
                "sigVer",
            "case_id":
                args.case_id,
            "parameter_set":
                args.parameter_set,
            "tg_id":
                args.tg_id,
            "tc_id":
                args.tc_id,
            "expected_valid":
                args.expected_valid,
        }

    # Normative runtime invocation representation.
    #
    # This exact same list object is:
    #   1. bound into the evidence object below, and
    #   2. passed directly to subprocess.run(..., shell=False).
    #
    # It is not reconstructed after execution.
    exact_argv = argv_for_execution

    exact_command = shlex.join(
        exact_argv
    )

    evidence: Dict[str, object] = {
        "schema":
            FORMAT_IDENTIFIER,

        "format_version":
            FORMAT_VERSION,

        "invocation_id":
            args.invocation_id,

        "implementation":
            args.implementation,

        "implementation_version":
            args.implementation_version,

        "implementation_source_authority": {
            "repository":
                args.source_repository,
            "commit":
                args.source_commit,
            "tree":
                args.source_tree,
        },

        "execution_scope":
            execution_scope,

        "covered_case_ids": [
            args.case_id,
        ],

        "executable":
            args.executable,

        "resolved_executable_path":
            str(resolved_executable),

        "resolved_executable_sha256":
            resolved_executable_sha256,

        "exact_argv":
            exact_argv,

        "exact_command":
            exact_command,

        "shell":
            False,

        "cwd":
            os.getcwd(),

        "allowlisted_environment":
            dict(
                sorted(
                    child_environment.items()
                )
            ),

        "execution_environment_policy":
            (
                "inherit_parent_environment_plus_"
                "explicit_allowlisted_overrides"
            ),

        "public_environment_capture_policy":
            "explicit_allowlist_only",

        "inherited_parent_environment_published":
            False,

        "input_artifacts":
            input_artifacts,

        "workflow_identity": {
            "path":
                str(workflow_path),
            "sha256":
                workflow_sha256,
        },

        "capture_launcher_identity": {
            "path":
                str(launcher_path),
            "sha256":
                launcher_sha256,
        },

        "repository_commit":
            args.repository_commit,

        "repository_tree":
            args.repository_tree,

        "github":
            github_binding(),

        "process_started":
            False,

        "launch_error":
            None,

        "exit_code":
            None,

        "stdout_sha256":
            None,

        "stdout_byte_count":
            None,

        "stderr_sha256":
            None,

        "stderr_byte_count":
            None,

        "result_state":
            "pending_process_launch",

        "captured_at_execution":
            True,

        "reconstructed_after_execution":
            False,

        "runtime_capture_method":
            CAPTURE_METHOD,

        "cryptographic_execution":
            cryptographic_execution,

        "metadata_only_publication":
            True,
    }

    stdout = b""
    stderr = b""

    try:
        process = subprocess.run(
            exact_argv,
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=execution_environment,
        )

        stdout = process.stdout
        stderr = process.stderr

        evidence["process_started"] = True
        evidence["exit_code"] = (
            process.returncode
        )

        if process.returncode == 0:
            evidence[
                "result_state"
            ] = "process_exit_success"
        else:
            evidence[
                "result_state"
            ] = "process_exit_error"

    except OSError as exc:
        evidence["process_started"] = False

        evidence["launch_error"] = {
            "type":
                type(exc).__name__,
            "message":
                str(exc),
        }

        evidence[
            "result_state"
        ] = "process_launch_error"

    evidence["stdout_sha256"] = sha256_bytes(
        stdout
    )

    evidence["stdout_byte_count"] = len(
        stdout
    )

    evidence["stderr_sha256"] = sha256_bytes(
        stderr
    )

    evidence["stderr_byte_count"] = len(
        stderr
    )

    write_ephemeral_output(
        args.ephemeral_stdout_path,
        stdout,
    )

    write_ephemeral_output(
        args.ephemeral_stderr_path,
        stderr,
    )

    atomic_write_json(
        Path(args.evidence_output),
        evidence,
    )

    print(
        "F7_CAPTURE_INVOCATION_ID="
        + args.invocation_id
    )

    print(
        "F7_CAPTURE_PROCESS_STARTED="
        + (
            "YES"
            if evidence["process_started"]
            else "NO"
        )
    )

    print(
        "F7_CAPTURE_EXIT_CODE="
        + str(evidence["exit_code"])
    )

    print(
        "F7_CAPTURE_RESULT_STATE="
        + str(evidence["result_state"])
    )

    print(
        "F7_CAPTURE_STDOUT_SHA256="
        + str(evidence["stdout_sha256"])
    )

    print(
        "F7_CAPTURE_STDERR_SHA256="
        + str(evidence["stderr_sha256"])
    )

    print(
        "F7_CAPTURE_RAW_OUTPUT_PUBLISHED=NO"
    )

    if (
        evidence["process_started"]
        and evidence["exit_code"] == 0
    ):
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
