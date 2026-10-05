#!/usr/bin/env python3
"""
QSV ML-DSA Interoperability Corpus
SB-2R — Exact Invocation Launcher v0.1

Purpose:
    Revalidate the prospective Python execution authority immediately
    before a future explicitly authorized source-bound acceptance run.

This launcher is fail-closed.

It MUST NOT be interpreted as authorization to execute:
    - OpenSSL
    - CIRCL
    - ML-DSA
    - source regeneration
    - source-bound acceptance

Those operations require a separate explicit approval.

Python feature baseline:
    Python 3.10 compatible.
"""

import argparse
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys


EXPECTED_REPOSITORY_COMMIT = (
    "00f0d3cfbc6f6fef2e9eb3cec450dbe9af76497a"
)

EXPECTED_REPOSITORY_TREE = (
    "b7603a2cc969ca171b3f43425b33f6d6f413ce25"
)

EXPECTED_REPOSITORY_PARENT = (
    "075f4616eb86f4331ca403f0382c5c1e957a3275"
)

EXPECTED_AUTHORITY_PATH = (
    "contracts/"
    "qsv-mldsa-f7-prospective-python-execution-authority-v0.1.json"
)

EXPECTED_AUTHORITY_SHA256 = (
    "56747f65425912c0dc776e35645e779dc2c88c7728826fd7d802adb443731056"
)

EXPECTED_INTERPRETER_PATH = (
    "/Users/motohiro/.pyenv/versions/3.10.14/bin/python3.10"
)

EXPECTED_INTERPRETER_SHA256 = (
    "094f3e91845a17d403c59b020b877e3845b205cbb431e50032cce346e04d8e6a"
)

EXPECTED_IMPLEMENTATION = "cpython"

EXPECTED_VERSION = (
    3,
    10,
    14,
)

FORBIDDEN_ENVIRONMENT = (
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
)


class LauncherError(Exception):
    pass


def fail(message):
    raise LauncherError(message)


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def run_git_read_only(repository_root, arguments):
    allowed = {
        ("rev-parse", "HEAD"),
        ("rev-parse", "HEAD^{tree}"),
        ("rev-parse", "HEAD^"),
        ("rev-parse", "--show-toplevel"),
    }

    args_tuple = tuple(arguments)

    if args_tuple not in allowed:
        fail(
            "DISALLOWED_GIT_ARGUMENTS="
            + repr(args_tuple)
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
            + repr(args_tuple)
        )

    return process.stdout.decode(
        "utf-8",
        "strict",
    ).strip()


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

    # Future source-bound acceptance execution must be a separate
    # explicitly authorized act.
    #
    # The launcher requires this variable only when actual execution
    # is specifically approved.
    execute_crypto = os.environ.get(
        "QSV_EXECUTE_CRYPTO"
    )

    if execute_crypto != "YES":
        fail(
            "QSV_EXECUTE_CRYPTO_EXPLICIT_ENABLEMENT_REQUIRED"
        )


def verify_repository(repository_root):
    requested_root = repository_root.resolve()

    actual_root = pathlib.Path(
        run_git_read_only(
            requested_root,
            (
                "rev-parse",
                "--show-toplevel",
            ),
        )
    ).resolve()

    if actual_root != requested_root:
        fail(
            "REPOSITORY_ROOT_MISMATCH"
        )

    commit = run_git_read_only(
        actual_root,
        (
            "rev-parse",
            "HEAD",
        ),
    )

    tree = run_git_read_only(
        actual_root,
        (
            "rev-parse",
            "HEAD^{tree}",
        ),
    )

    parent = run_git_read_only(
        actual_root,
        (
            "rev-parse",
            "HEAD^",
        ),
    )

    if commit != EXPECTED_REPOSITORY_COMMIT:
        fail(
            "REPOSITORY_COMMIT_MISMATCH"
        )

    if tree != EXPECTED_REPOSITORY_TREE:
        fail(
            "REPOSITORY_TREE_MISMATCH"
        )

    if parent != EXPECTED_REPOSITORY_PARENT:
        fail(
            "REPOSITORY_PARENT_MISMATCH"
        )

    return actual_root


def verify_authority(repository_root):
    authority_path = (
        repository_root
        / EXPECTED_AUTHORITY_PATH
    )

    if not authority_path.is_file():
        fail(
            "AUTHORITY_FILE_MISSING"
        )

    authority_sha = sha256_file(
        authority_path
    )

    if (
        authority_sha
        != EXPECTED_AUTHORITY_SHA256
    ):
        fail(
            "AUTHORITY_SHA256_MISMATCH"
        )

    try:
        authority = json.loads(
            authority_path.read_text(
                encoding="utf-8"
            )
        )
    except Exception as exc:
        fail(
            "AUTHORITY_JSON_INVALID="
            + repr(exc)
        )

    if (
        authority.get("role")
        != "PROSPECTIVE_PRE_EXECUTION_PYTHON_EXECUTION_AUTHORITY"
    ):
        fail(
            "AUTHORITY_ROLE_MISMATCH"
        )

    if authority.get(
        "prospective"
    ) is not True:
        fail(
            "AUTHORITY_PROSPECTIVE_FLAG_INVALID"
        )

    if authority.get(
        "retroactive_claim"
    ) is not False:
        fail(
            "AUTHORITY_RETROACTIVE_FLAG_INVALID"
        )

    candidate = authority.get(
        "captured",
        {},
    ).get(
        "candidate",
        {},
    )

    if (
        candidate.get(
            "sys_implementation_name"
        )
        != EXPECTED_IMPLEMENTATION
    ):
        fail(
            "AUTHORITY_IMPLEMENTATION_MISMATCH"
        )

    if (
        candidate.get(
            "version_info"
        )
        != list(EXPECTED_VERSION)
    ):
        fail(
            "AUTHORITY_VERSION_MISMATCH"
        )

    if (
        candidate.get(
            "resolved_executable_path"
        )
        != EXPECTED_INTERPRETER_PATH
    ):
        fail(
            "AUTHORITY_INTERPRETER_PATH_MISMATCH"
        )

    if (
        candidate.get(
            "resolved_executable_sha256"
        )
        != EXPECTED_INTERPRETER_SHA256
    ):
        fail(
            "AUTHORITY_INTERPRETER_SHA_MISMATCH"
        )


def candidate_self_report(interpreter_path):
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

    environment.pop(
        "QSV_EXECUTE_CRYPTO",
        None,
    )

    for name in FORBIDDEN_ENVIRONMENT:
        environment.pop(
            name,
            None,
        )

    process = subprocess.run(
        [
            str(interpreter_path),
            "-I",
            "-S",
            "-c",
            code,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
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
            + repr(exc)
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
        str(interpreter)
    ):
        fail(
            "INTERPRETER_PATH_MISSING"
        )

    resolved = pathlib.Path(
        os.path.realpath(
            str(interpreter)
        )
    )

    if not resolved.is_file():
        fail(
            "RESOLVED_INTERPRETER_NOT_REGULAR_FILE"
        )

    resolved_stat = resolved.stat()

    if not stat.S_ISREG(
        resolved_stat.st_mode
    ):
        fail(
            "RESOLVED_INTERPRETER_NOT_REGULAR_FILE"
        )

    if not os.access(
        str(resolved),
        os.X_OK,
    ):
        fail(
            "RESOLVED_INTERPRETER_NOT_EXECUTABLE"
        )

    observed_sha = sha256_file(
        resolved
    )

    if (
        observed_sha
        != EXPECTED_INTERPRETER_SHA256
    ):
        fail(
            "INTERPRETER_SHA256_MISMATCH"
        )

    report = candidate_self_report(
        resolved
    )

    sys_executable_realpath = (
        os.path.realpath(
            report[
                "sys_executable"
            ]
        )
    )

    if (
        sys_executable_realpath
        != str(resolved)
    ):
        fail(
            "INTERPRETER_SYS_EXECUTABLE_REALPATH_MISMATCH"
        )

    if (
        report[
            "sys_implementation_name"
        ]
        != EXPECTED_IMPLEMENTATION
    ):
        fail(
            "INTERPRETER_IMPLEMENTATION_MISMATCH"
        )

    if (
        report[
            "platform_python_implementation"
        ].lower()
        != EXPECTED_IMPLEMENTATION
    ):
        fail(
            "INTERPRETER_PLATFORM_IMPLEMENTATION_MISMATCH"
        )

    if (
        tuple(
            report[
                "version_info"
            ]
        )
        != EXPECTED_VERSION
    ):
        fail(
            "INTERPRETER_VERSION_MISMATCH"
        )

    expected_version_string = ".".join(
        str(value)
        for value in EXPECTED_VERSION
    )

    if (
        report[
            "platform_python_version"
        ]
        != expected_version_string
    ):
        fail(
            "INTERPRETER_PLATFORM_VERSION_MISMATCH"
        )

    return resolved


def validate_target(repository_root, target):
    target_path = pathlib.Path(
        target
    )

    if not target_path.is_absolute():
        target_path = (
            repository_root
            / target_path
        )

    resolved_target = pathlib.Path(
        os.path.realpath(
            str(target_path)
        )
    )

    if not resolved_target.is_file():
        fail(
            "TARGET_SCRIPT_NOT_REGULAR_FILE"
        )

    try:
        resolved_target.relative_to(
            repository_root
        )
    except ValueError:
        fail(
            "TARGET_SCRIPT_OUTSIDE_REPOSITORY"
        )

    return resolved_target


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--repository-root",
        required=True,
    )

    parser.add_argument(
        "--target",
        required=True,
    )

    parser.add_argument(
        "target_args",
        nargs=argparse.REMAINDER,
    )

    args = parser.parse_args()

    try:
        verify_environment()

        repository_root = verify_repository(
            pathlib.Path(
                args.repository_root
            )
        )

        verify_authority(
            repository_root
        )

        interpreter = verify_interpreter()

        target = validate_target(
            repository_root,
            args.target,
        )

    except LauncherError as exc:
        print(
            "EXACT_INVOCATION_LAUNCHER=BLOCKED",
            file=sys.stderr,
        )

        print(
            "BLOCKER="
            + str(exc),
            file=sys.stderr,
        )

        return 1

    # Important:
    # No generic "python", "python3", /usr/bin/env, shell, PATH lookup,
    # or shim is used here.
    #
    # os.execve replaces the launcher process with the exact validated
    # interpreter. This reduces, but does not eliminate, the temporal
    # gap between validation and execution. No atomic TOCTOU guarantee
    # is claimed.
    execution_environment = os.environ.copy()

    execution_environment[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    for name in FORBIDDEN_ENVIRONMENT:
        execution_environment.pop(
            name,
            None,
        )

    argv = [
        str(interpreter),
        str(target),
    ]

    argv.extend(
        args.target_args
    )

    os.execve(
        str(interpreter),
        argv,
        execution_environment,
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
