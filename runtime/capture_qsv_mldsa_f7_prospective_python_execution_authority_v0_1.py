#!/usr/bin/env python3
"""
QSV ML-DSA Interoperability Corpus
SB-2R — Prospective Python Execution Authority Capture Controller v0.1

Role:
    External read-only controller for prospective Python execution authority
    capture.

Important boundaries:
    - prospective only
    - no historical F7 implementation claim
    - no crypto execution
    - no source regeneration
    - no source-bound acceptance
    - no network
    - no Git mutation
    - stdout only; this program does not write authority artifacts itself

Python feature baseline:
    Python 3.10 compatible
"""

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
from pathlib import Path


EXPECTED_PREDECESSOR_COMMIT = (
    "00f0d3cfbc6f6fef2e9eb3cec450dbe9af76497a"
)

EXPECTED_PREDECESSOR_TREE = (
    "b7603a2cc969ca171b3f43425b33f6d6f413ce25"
)

EXPECTED_PREDECESSOR_PARENT = (
    "075f4616eb86f4331ca403f0382c5c1e957a3275"
)

EXPECTED_IMPLEMENTATION = "cpython"

EXPECTED_VERSION = (
    3,
    10,
    14,
)

EXPECTED_EXECUTABLE_SHA256 = (
    "094f3e91845a17d403c59b020b877e3845b205cbb431e50032cce346e04d8e6a"
)

AUTHORITY_ROLE = (
    "PROSPECTIVE_PRE_EXECUTION_PYTHON_EXECUTION_AUTHORITY"
)

AUTHORITY_SUBJECT = (
    "EXPLICIT_CANDIDATE_INTERPRETER_RUNTIME_IDENTITY_AND_"
    "RESOLVED_EXECUTABLE_IDENTITY_FOR_FUTURE_SB2R_ACCEPTANCE"
)

POLICY_NAME = (
    "MINIMUM_SUFFICIENT_EXECUTION_BASELINE"
)

PROJECT_FEATURE_BASELINE = (
    "PYTHON_3_10_COMPATIBLE"
)

FORBIDDEN_ENVIRONMENT_VARIABLES = (
    "QSV_EXECUTE_CRYPTO",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
)

RECORDED_ENVIRONMENT_VARIABLES = (
    "PYTHONWARNINGS",
    "PYTHONHASHSEED",
    "LC_ALL",
    "LANG",
    "TZ",
)


class CaptureError(Exception):
    pass


def fail(message):
    raise CaptureError(message)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def run_read_only_git(repository_root, arguments):
    allowed = {
        ("rev-parse", "HEAD"),
        ("rev-parse", "HEAD^{tree}"),
        ("rev-parse", "HEAD^"),
        ("rev-parse", "--show-toplevel"),
    }

    command_tuple = tuple(arguments)

    if command_tuple not in allowed:
        fail(
            "DISALLOWED_GIT_ARGUMENTS="
            + repr(command_tuple)
        )

    process = subprocess.run(
        ["/usr/bin/git"] + list(arguments),
        cwd=str(repository_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=os.environ.copy(),
    )

    if process.returncode != 0:
        fail(
            "READ_ONLY_GIT_QUERY_FAILED="
            + repr(command_tuple)
            + ";stderr="
            + process.stderr.decode(
                "utf-8",
                "backslashreplace",
            ).strip()
        )

    return process.stdout.decode(
        "utf-8",
        "strict",
    ).strip()


def check_environment():
    forbidden_observed = {}

    for name in FORBIDDEN_ENVIRONMENT_VARIABLES:
        if name in os.environ:
            forbidden_observed[name] = os.environ.get(name)

    if forbidden_observed:
        fail(
            "FORBIDDEN_ENVIRONMENT_PRESENT="
            + json.dumps(
                forbidden_observed,
                sort_keys=True,
            )
        )

    if os.environ.get(
        "PYTHONDONTWRITEBYTECODE"
    ) != "1":
        fail(
            "PYTHONDONTWRITEBYTECODE_MUST_EQUAL_1"
        )

    recorded = {}

    for name in RECORDED_ENVIRONMENT_VARIABLES:
        recorded[name] = os.environ.get(name)

    return recorded


def candidate_self_report(candidate_path):
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

    child_environment = os.environ.copy()
    child_environment[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    for name in FORBIDDEN_ENVIRONMENT_VARIABLES:
        child_environment.pop(
            name,
            None,
        )

    process = subprocess.run(
        [
            str(candidate_path),
            "-I",
            "-S",
            "-c",
            code,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=child_environment,
    )

    if process.returncode != 0:
        fail(
            "CANDIDATE_SELF_REPORT_FAILED="
            + process.stderr.decode(
                "utf-8",
                "backslashreplace",
            ).strip()
        )

    try:
        report = json.loads(
            process.stdout.decode(
                "utf-8",
                "strict",
            )
        )
    except Exception as exc:
        fail(
            "CANDIDATE_SELF_REPORT_JSON_INVALID="
            + repr(exc)
        )

    return report


def inspect_candidate(candidate_argument):
    invocation_path = Path(
        candidate_argument
    ).expanduser()

    if not invocation_path.is_absolute():
        fail(
            "CANDIDATE_INVOCATION_PATH_NOT_ABSOLUTE"
        )

    if not os.path.lexists(
        str(invocation_path)
    ):
        fail(
            "CANDIDATE_INVOCATION_PATH_ABSENT"
        )

    invocation_lstat = os.lstat(
        str(invocation_path)
    )

    invocation_is_symlink = stat.S_ISLNK(
        invocation_lstat.st_mode
    )

    symlink_target = None

    if invocation_is_symlink:
        symlink_target = os.readlink(
            str(invocation_path)
        )

    resolved_path = Path(
        os.path.realpath(
            str(invocation_path)
        )
    )

    if not resolved_path.exists():
        fail(
            "CANDIDATE_RESOLVED_EXECUTABLE_ABSENT"
        )

    resolved_stat = resolved_path.stat()

    if not stat.S_ISREG(
        resolved_stat.st_mode
    ):
        fail(
            "CANDIDATE_RESOLVED_EXECUTABLE_NOT_REGULAR_FILE"
        )

    if not os.access(
        str(resolved_path),
        os.X_OK,
    ):
        fail(
            "CANDIDATE_RESOLVED_EXECUTABLE_NOT_EXECUTABLE"
        )

    executable_sha256 = sha256_file(
        resolved_path
    )

    if (
        executable_sha256
        != EXPECTED_EXECUTABLE_SHA256
    ):
        fail(
            "CANDIDATE_EXECUTABLE_SHA256_MISMATCH"
        )

    report = candidate_self_report(
        resolved_path
    )

    sys_executable_realpath = os.path.realpath(
        report["sys_executable"]
    )

    if (
        str(resolved_path)
        != sys_executable_realpath
    ):
        fail(
            "RESOLVED_PATH_DOES_NOT_EQUAL_"
            "SYS_EXECUTABLE_REALPATH"
        )

    implementation_name = report[
        "sys_implementation_name"
    ]

    platform_implementation = report[
        "platform_python_implementation"
    ]

    if implementation_name != EXPECTED_IMPLEMENTATION:
        fail(
            "CANONICAL_IMPLEMENTATION_MISMATCH"
        )

    if (
        platform_implementation.lower()
        != EXPECTED_IMPLEMENTATION
    ):
        fail(
            "PLATFORM_IMPLEMENTATION_MISMATCH"
        )

    version_info = tuple(
        report["version_info"]
    )

    if version_info != EXPECTED_VERSION:
        fail(
            "CANONICAL_VERSION_MISMATCH"
        )

    expected_version_string = ".".join(
        str(value)
        for value in EXPECTED_VERSION
    )

    if (
        report["platform_python_version"]
        != expected_version_string
    ):
        fail(
            "PLATFORM_VERSION_MISMATCH"
        )

    return {
        "invocation_path": str(
            invocation_path
        ),
        "resolved_executable_path": str(
            resolved_path
        ),
        "invocation_path_is_symlink":
            invocation_is_symlink,
        "symlink_target_if_any":
            symlink_target,
        "resolved_executable_regular_file":
            True,
        "resolved_executable_mode":
            format(
                stat.S_IMODE(
                    resolved_stat.st_mode
                ),
                "04o",
            ),
        "resolved_executable_size":
            resolved_stat.st_size,
        "resolved_executable_sha256":
            executable_sha256,
        "sys_executable_realpath":
            sys_executable_realpath,
        "sys_implementation_name":
            implementation_name,
        "platform_python_implementation":
            platform_implementation,
        "version_info":
            list(version_info),
        "platform_python_version":
            report["platform_python_version"],
        "implementation_cross_check":
            "PASS",
        "version_cross_check":
            "PASS",
    }


def inspect_repository(repository_root):
    requested_root = repository_root.resolve()

    actual_root = Path(
        run_read_only_git(
            requested_root,
            (
                "rev-parse",
                "--show-toplevel",
            ),
        )
    ).resolve()

    if requested_root != actual_root:
        fail(
            "REQUESTED_REPOSITORY_ROOT_DOES_NOT_"
            "EQUAL_GIT_TOPLEVEL"
        )

    current_commit = run_read_only_git(
        actual_root,
        (
            "rev-parse",
            "HEAD",
        ),
    )

    current_tree = run_read_only_git(
        actual_root,
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    )

    current_parent = run_read_only_git(
        actual_root,
        (
            "rev-parse",
            "HEAD^",
        ),
    )

    if current_commit != EXPECTED_PREDECESSOR_COMMIT:
        fail(
            "PREDECESSOR_COMMIT_MISMATCH"
        )

    if current_tree != EXPECTED_PREDECESSOR_TREE:
        fail(
            "PREDECESSOR_TREE_MISMATCH"
        )

    if current_parent != EXPECTED_PREDECESSOR_PARENT:
        fail(
            "PREDECESSOR_PARENT_MISMATCH"
        )

    return {
        "repository_root":
            str(actual_root),
        "predecessor_commit":
            current_commit,
        "predecessor_tree":
            current_tree,
        "predecessor_parent":
            current_parent,
    }


def build_authority(
    candidate,
    repository,
    recorded_environment,
):
    return {
        "schema_version": "0.1",
        "role": AUTHORITY_ROLE,
        "subject": AUTHORITY_SUBJECT,

        "prospective": True,
        "retroactive_claim": False,
        "historical_f7_implementation_claimed":
            False,

        "selection_policy": {
            "name": POLICY_NAME,
            "classification":
                "PROSPECTIVE_NORMATIVE_PROJECT_POLICY",
            "purpose":
                "MINIMIZE_UNNECESSARY_RUNTIME_VERSION_ASSUMPTIONS",
            "selection_domain":
                "EVALUATED_LOCAL_DIRECT_INTERPRETER_CANDIDATE_SET",
            "project_declared_minimum_feature_baseline":
                PROJECT_FEATURE_BASELINE,
            "proven_global_minimum_python_version":
                False,
            "global_python_interpreter_minimum_claimed":
                False,
            "premature_artifact_match_used_as_selection_authority":
                False,
            "historical_f7_runtime_match_used_as_selection_authority":
                False,
        },

        "captured": {
            "candidate": candidate,
            "repository": repository,
            "environment": {
                "required": {
                    "QSV_EXECUTE_CRYPTO":
                        "MUST_BE_ABSENT",
                    "PYTHONPATH":
                        "MUST_BE_ABSENT",
                    "PYTHONHOME":
                        "MUST_BE_ABSENT",
                    "PYTHONSTARTUP":
                        "MUST_BE_ABSENT",
                    "PYTHONINSPECT":
                        "MUST_BE_ABSENT",
                    "PYTHONDONTWRITEBYTECODE":
                        "MUST_BE_FIXED_TO_1",
                },
                "recorded":
                    recorded_environment,
            },
        },

        "historical_claim_boundary": {
            "public_historical_python_version_evidence":
                "Python 3.12.3",
            "public_historical_python_implementation_authority":
                "UNRESOLVED",
            "historical_runtime_fact_equals_future_execution_requirement":
                False,
            "retroactive_cpython_claim_allowed":
                False,
        },

        "non_guarantees": {
            "executable_sha256_is_complete_runtime_provenance":
                False,
            "python_source_to_runtime_provenance_proven":
                False,
            "local_interpreter_persistence_guaranteed":
                False,
            "global_path_portability_claimed":
                False,
            "full_python_build_provenance_proven":
                False,
            "historical_f7_python_implementation_resolved":
                False,
        },

        "execution_boundary": {
            "network_required_for_authority_capture":
                False,
            "network_required_for_authority_verification":
                False,
            "crypto_execution_authorized":
                False,
            "source_regeneration_authorized":
                False,
            "source_bound_acceptance_authorized":
                False,
        },
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--candidate",
        required=True,
    )

    parser.add_argument(
        "--repository-root",
        required=True,
    )

    args = parser.parse_args()

    try:
        recorded_environment = (
            check_environment()
        )

        candidate = inspect_candidate(
            args.candidate
        )

        repository = inspect_repository(
            Path(
                args.repository_root
            )
        )

        authority = build_authority(
            candidate,
            repository,
            recorded_environment,
        )

    except CaptureError as exc:
        print(
            "PROSPECTIVE_PYTHON_AUTHORITY_CAPTURE=FAIL",
            file=os.sys.stderr,
        )

        print(
            "BLOCKER="
            + str(exc),
            file=os.sys.stderr,
        )

        return 1

    print(
        json.dumps(
            authority,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
