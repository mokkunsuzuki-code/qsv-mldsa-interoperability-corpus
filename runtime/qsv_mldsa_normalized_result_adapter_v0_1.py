#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shlex
from pathlib import Path


SOURCE_EVIDENCE_REL = (
    "results/"
    "qsv_mldsa_f7_runtime_invocation_evidence_v0_1/"
    "qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json"
)

MANIFEST_REL = (
    "results/"
    "qsv_mldsa_f7_runtime_invocation_evidence_v0_1/"
    "runtime-sixcase-manifest.json"
)

RUNNER_REL = (
    "runners/"
    "qsv-mldsa-runner-interface-v0.1.json"
)

SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-fixture-v0.2.schema.json"
)

OPENSSL_HARNESS_REL = (
    "runtime/"
    "qsv_mldsa_openssl_sigver_harness_v0_1.c"
)

CIRCL_HARNESS_REL = (
    "runtime/"
    "qsv_mldsa_circl_sigver_harness_v0_1.go"
)

HARNESS_CONTRACT_REL = (
    "runtime/"
    "qsv_mldsa_runtime_harness_contract_v0_1.json"
)

ADAPTER_REL = (
    "runtime/"
    "qsv_mldsa_normalized_result_adapter_v0_1.py"
)

EXPECTED_EXECUTION_COMMIT = (
    "e7c2f85a6cdf49c39a42cccdd96ba6ab1a8da6cd"
)

EXPECTED_EXECUTION_TREE = (
    "e97833bc5a06a49309a30f292dfdc84436668836"
)

EXPECTED_PUBLIC_EVIDENCE_COMMIT = (
    "dfb1bc5849340d791b60a29f531952e6a0707e2d"
)

EXPECTED_RUN_ID = "34968252038"
EXPECTED_RUN_ATTEMPT = "1"
EXPECTED_JOB_ID = 104377847614

DERIVATION_METHOD = (
    "pinned_harness_semantics_plus_exact_runtime_argv_"
    "plus_actual_exit_status_plus_stdout_sha256_commitment"
)

EXPECTED_RUNNER_FIELDS = [
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
]


def fail(message):
    raise SystemExit(
        "FAIL: " + message
    )


def sha256_bytes(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_path(path):
    return sha256_bytes(
        path.read_bytes()
    )


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def bool_text(value):
    return (
        "true"
        if value
        else "false"
    )


def fixture_id(
    case_id,
    manifest_sha,
):
    payload = (
        "qsv-f7-fixture-v0.2\n"
        + manifest_sha
        + "\n"
        + case_id
        + "\n"
    ).encode(
        "utf-8"
    )

    return (
        "qsv-f7-"
        + sha256_bytes(
            payload
        )[:24]
    )


def require_fragments(
    text,
    fragments,
    label,
):
    for fragment in fragments:
        if fragment not in text:
            fail(
                label
                + " semantic fragment missing: "
                + fragment
            )


def derive(root):
    if "QSV_EXECUTE_CRYPTO" in os.environ:
        fail(
            "QSV_EXECUTE_CRYPTO must be absent"
        )

    source_path = (
        root
        / SOURCE_EVIDENCE_REL
    )

    manifest_path = (
        root
        / MANIFEST_REL
    )

    runner_path = (
        root
        / RUNNER_REL
    )

    schema_path = (
        root
        / SCHEMA_REL
    )

    openssl_path = (
        root
        / OPENSSL_HARNESS_REL
    )

    circl_path = (
        root
        / CIRCL_HARNESS_REL
    )

    contract_path = (
        root
        / HARNESS_CONTRACT_REL
    )

    adapter_path = (
        root
        / ADAPTER_REL
    )

    for path in [
        source_path,
        manifest_path,
        runner_path,
        schema_path,
        openssl_path,
        circl_path,
        contract_path,
        adapter_path,
    ]:
        if not path.is_file():
            fail(
                "missing source authority: "
                + str(path)
            )

    source_sha = sha256_path(
        source_path
    )

    manifest_sha = sha256_path(
        manifest_path
    )

    runner_sha = sha256_path(
        runner_path
    )

    schema_sha = sha256_path(
        schema_path
    )

    adapter_sha = sha256_path(
        adapter_path
    )

    source = load_json(
        source_path
    )

    manifest = load_json(
        manifest_path
    )

    runner = load_json(
        runner_path
    )

    contract = load_json(
        contract_path
    )

    if (
        runner["output"][
            "required_fields"
        ]
        != EXPECTED_RUNNER_FIELDS
    ):
        fail(
            "runner output contract changed"
        )

    if (
        source[
            "repository_commit"
        ]
        != EXPECTED_EXECUTION_COMMIT
        or source[
            "repository_tree"
        ]
        != EXPECTED_EXECUTION_TREE
    ):
        fail(
            "execution commit/tree mismatch"
        )

    github = source[
        "github"
    ]

    if (
        github[
            "github_run_id"
        ]
        != EXPECTED_RUN_ID
        or github[
            "github_run_attempt"
        ]
        != EXPECTED_RUN_ATTEMPT
        or github[
            "github_job_id_numeric"
        ]
        != EXPECTED_JOB_ID
        or github[
            "job_id_binding_status"
        ]
        != "runtime_bound"
    ):
        fail(
            "GitHub run/job binding mismatch"
        )

    if source[
        "invocation_count"
    ] != 12:
        fail(
            "expected exactly 12 invocations"
        )

    invocations = source[
        "invocations"
    ]

    if len(invocations) != 12:
        fail(
            "invocation array count mismatch"
        )

    if manifest[
        "case_count"
    ] != 6:
        fail(
            "manifest case count mismatch"
        )

    if manifest[
        "payload_embedded"
    ] is not False:
        fail(
            "manifest payload boundary mismatch"
        )

    artifact_hashes = contract[
        "artifact_hashes"
    ]

    if (
        sha256_path(
            openssl_path
        )
        != artifact_hashes[
            "openssl_harness_source_sha256"
        ]
    ):
        fail(
            "OpenSSL harness source hash mismatch"
        )

    if (
        sha256_path(
            circl_path
        )
        != artifact_hashes[
            "circl_harness_source_sha256"
        ]
    ):
        fail(
            "CIRCL harness source hash mismatch"
        )

    openssl_source = (
        openssl_path.read_text(
            encoding="utf-8"
        )
    )

    circl_source = (
        circl_path.read_text(
            encoding="utf-8"
        )
    )

    require_fragments(
        circl_source,
        [
            "strconv.ParseBool(",
            "os.Args[6]",
            "actual, err = verify44(",
            "actual, err = verify65(",
            "actual, err = verify87(",
            "if actual != expected",
            "CIRCL_EXPECTATION_MATCH=NO",
            "os.Exit(1)",
            "CIRCL_EXPECTATION_MATCH=YES",
        ],
        "CIRCL",
    )

    require_fragments(
        openssl_source,
        [
            'strcmp(argv[6], "true")',
            'strcmp(argv[6], "false")',
            "ret = EVP_PKEY_verify(",
            "actual_valid = (",
            "ret == 1",
            "actual_valid",
            "!= expected_valid",
            "OPENSSL_EXPECTATION_MATCH=NO",
            "ret = 1;",
            "OPENSSL_EXPECTATION_MATCH=YES",
            "ret = 0;",
        ],
        "OpenSSL",
    )

    manifest_cases = {}

    for case in manifest[
        "cases"
    ]:
        case_id = (
            f'{case["parameter_set"]}'
            f'-tg{case["tg_id"]}'
            f'-tc{case["tc_id"]}'
        )

        if case_id in manifest_cases:
            fail(
                "duplicate manifest case"
            )

        manifest_cases[
            case_id
        ] = case

    build = source[
        "build_observations"
    ]

    executable_hashes = {
        "cloudflare-circl":
        build[
            "circl_harness_binary_sha256"
        ],

        "openssl":
        build[
            "openssl_harness_binary_sha256"
        ],
    }

    records = []

    true_count = 0
    false_count = 0
    pass_count = 0
    reject_count = 0

    for invocation in invocations:
        implementation = invocation[
            "implementation"
        ]

        if implementation not in (
            "cloudflare-circl",
            "openssl",
        ):
            fail(
                "unsupported implementation"
            )

        scope = invocation[
            "execution_scope"
        ]

        case_id = scope[
            "case_id"
        ]

        if case_id not in manifest_cases:
            fail(
                "runtime case missing from manifest"
            )

        case = manifest_cases[
            case_id
        ]

        if invocation[
            "covered_case_ids"
        ] != [case_id]:
            fail(
                "covered case mismatch"
            )

        if (
            scope[
                "parameter_set"
            ]
            != case[
                "parameter_set"
            ]
            or scope[
                "tg_id"
            ]
            != case[
                "tg_id"
            ]
            or scope[
                "tc_id"
            ]
            != case[
                "tc_id"
            ]
            or scope[
                "expected_valid"
            ]
            != case[
                "expected_valid"
            ]
        ):
            fail(
                "runtime/manifest case binding mismatch"
            )

        if (
            invocation[
                "captured_at_execution"
            ]
            is not True
            or invocation[
                "reconstructed_after_execution"
            ]
            is not False
            or invocation[
                "cryptographic_execution"
            ]
            is not True
            or invocation[
                "process_started"
            ]
            is not True
            or invocation[
                "launch_error"
            ]
            is not None
            or invocation[
                "shell"
            ]
            is not False
            or invocation[
                "exit_code"
            ]
            != 0
            or invocation[
                "result_state"
            ]
            != "process_exit_success"
        ):
            fail(
                "runtime execution authority mismatch"
            )

        argv = invocation[
            "exact_argv"
        ]

        if (
            not isinstance(
                argv,
                list,
            )
            or len(argv) != 7
        ):
            fail(
                "exact argv malformed"
            )

        if (
            argv[0]
            != invocation[
                "executable"
            ]
            or argv[0]
            != invocation[
                "resolved_executable_path"
            ]
        ):
            fail(
                "executable/argv mismatch"
            )

        if (
            invocation[
                "exact_command"
            ]
            != shlex.join(
                argv
            )
        ):
            fail(
                "recorded exact command mismatch"
            )

        cli_expected_text = argv[6]

        if cli_expected_text not in (
            "true",
            "false",
        ):
            fail(
                "expected boolean argv malformed"
            )

        cli_expected = (
            cli_expected_text
            == "true"
        )

        if (
            cli_expected
            != case[
                "expected_valid"
            ]
        ):
            fail(
                "argv expectation/source expectation mismatch"
            )

        if (
            invocation[
                "resolved_executable_sha256"
            ]
            != executable_hashes[
                implementation
            ]
        ):
            fail(
                "runtime executable/build observation mismatch"
            )

        prefix = (
            "CIRCL"
            if implementation
            == "cloudflare-circl"
            else "OPENSSL"
        )

        # Exit 0 from the pinned harness proves actual == argv[6].
        # This is not an unconditional expected_valid -> observed copy.
        observed = cli_expected

        expected_stdout = (
            f"{prefix}_ACTUAL_VALID="
            f"{bool_text(observed)}\n"
            f"{prefix}_EXPECTED_VALID="
            f"{bool_text(cli_expected)}\n"
            f"{prefix}_EXPECTATION_MATCH=YES\n"
        ).encode(
            "utf-8"
        )

        if (
            invocation[
                "stdout_sha256"
            ]
            != sha256_bytes(
                expected_stdout
            )
            or invocation[
                "stdout_byte_count"
            ]
            != len(
                expected_stdout
            )
        ):
            fail(
                "stdout commitment mismatch"
            )

        if (
            invocation[
                "stderr_byte_count"
            ]
            != 0
            or invocation[
                "stderr_sha256"
            ]
            != sha256_bytes(
                b""
            )
        ):
            fail(
                "stderr success-path mismatch"
            )

        artifacts = {
            item[
                "role"
            ]:
            item

            for item
            in invocation[
                "input_artifacts"
            ]
        }

        if set(
            artifacts
        ) != {
            "public_key",
            "message",
            "context",
            "signature",
        }:
            fail(
                "input artifact role mismatch"
            )

        source_map = {
            "public_key": (
                case[
                    "pk_sha256"
                ],
                case[
                    "pk_size_bytes"
                ],
            ),
            "message": (
                case[
                    "message_sha256"
                ],
                case[
                    "message_size_bytes"
                ],
            ),
            "context": (
                case[
                    "context_sha256"
                ],
                case[
                    "context_size_bytes"
                ],
            ),
            "signature": (
                case[
                    "signature_sha256"
                ],
                case[
                    "signature_size_bytes"
                ],
            ),
        }

        normalized_artifacts = {}

        for role, (
            expected_sha,
            expected_size,
        ) in source_map.items():

            item = artifacts[
                role
            ]

            if (
                item[
                    "sha256"
                ]
                != expected_sha
                or item[
                    "byte_count"
                ]
                != expected_size
            ):
                fail(
                    "input artifact/manifest mismatch"
                )

            normalized_artifacts[
                role
            ] = {
                "sha256":
                item[
                    "sha256"
                ],

                "byte_count":
                item[
                    "byte_count"
                ],
            }

        if observed == case[
            "expected_valid"
        ]:
            result_state = (
                "pass"
                if observed
                else "expected_reject"
            )
        elif observed:
            result_state = (
                "unexpected_accept"
            )
        else:
            result_state = (
                "unexpected_reject"
            )

        if observed:
            true_count += 1
        else:
            false_count += 1

        if result_state == "pass":
            pass_count += 1

        if (
            result_state
            == "expected_reject"
        ):
            reject_count += 1

        record = {
            "fixture_id":
            fixture_id(
                case_id,
                manifest_sha,
            ),

            "implementation":
            implementation,

            "operation":
            "sigVer",

            "result_state":
            result_state,

            "observed_acceptance":
            observed,

            # Normative value copied exactly from F7 runtime capture.
            "exact_command":
            invocation[
                "exact_command"
            ],

            "inputs": {
                "case": {
                    "case_id":
                    case_id,

                    "parameter_set":
                    case[
                        "parameter_set"
                    ],

                    "tg_id":
                    case[
                        "tg_id"
                    ],

                    "tc_id":
                    case[
                        "tc_id"
                    ],

                    "source_expected_valid":
                    case[
                        "expected_valid"
                    ],
                },

                "artifacts":
                normalized_artifacts,
            },

            "output": {
                "stdout_sha256":
                invocation[
                    "stdout_sha256"
                ],

                "stdout_byte_count":
                invocation[
                    "stdout_byte_count"
                ],

                "stderr_sha256":
                invocation[
                    "stderr_sha256"
                ],

                "stderr_byte_count":
                invocation[
                    "stderr_byte_count"
                ],

                "observation_derivation": {
                    "method":
                    DERIVATION_METHOD,

                    "observation_is_derived":
                    True,

                    "direct_runtime_actual_value_published":
                    False,

                    "pinned_harness_semantics_verified":
                    True,

                    "stdout_commitment_verified":
                    True,

                    "expected_valid_used_as_unconditional_observed_value":
                    False,

                    "workflow_conclusion_used":
                    False,
                },
            },

            "exit_status": {
                "code":
                invocation[
                    "exit_code"
                ],

                "process_started":
                invocation[
                    "process_started"
                ],

                "launch_error":
                invocation[
                    "launch_error"
                ],
            },

            "artifact_hashes": {
                "resolved_executable_sha256":
                invocation[
                    "resolved_executable_sha256"
                ],

                "workflow_sha256":
                invocation[
                    "workflow_identity"
                ][
                    "sha256"
                ],

                "capture_launcher_sha256":
                invocation[
                    "capture_launcher_identity"
                ][
                    "sha256"
                ],

                "runtime_manifest_sha256":
                manifest_sha,

                "source_evidence_sha256":
                source_sha,
            },

            "environment": {
                "allowlisted":
                invocation[
                    "allowlisted_environment"
                ],

                "inherited_parent_environment_published":
                invocation[
                    "inherited_parent_environment_published"
                ],

                "public_environment_capture_policy":
                invocation[
                    "public_environment_capture_policy"
                ],
            },
        }

        if (
            list(
                record.keys()
            )
            != EXPECTED_RUNNER_FIELDS
        ):
            fail(
                "normalized record key order/contract mismatch"
            )

        records.append(
            record
        )

    if (
        true_count != 6
        or false_count != 6
        or pass_count != 6
        or reject_count != 6
    ):
        fail(
            "normalized count authority mismatch"
        )

    result = {
        "schema":
        "qsv.mldsa.f7-normalized-result-evidence.v0.1",

        "source_authority": {
            "public_evidence_commit":
            EXPECTED_PUBLIC_EVIDENCE_COMMIT,

            "execution_commit":
            EXPECTED_EXECUTION_COMMIT,

            "execution_tree":
            EXPECTED_EXECUTION_TREE,

            "github_run_id":
            EXPECTED_RUN_ID,

            "github_run_attempt":
            EXPECTED_RUN_ATTEMPT,

            "github_job_id_numeric":
            EXPECTED_JOB_ID,

            "bound_runtime_evidence_path":
            SOURCE_EVIDENCE_REL,

            "bound_runtime_evidence_sha256":
            source_sha,

            "runtime_manifest_path":
            MANIFEST_REL,

            "runtime_manifest_sha256":
            manifest_sha,
        },

        "normalization_authority": {
            "runner_interface_path":
            RUNNER_REL,

            "runner_interface_sha256":
            runner_sha,

            "record_schema_path":
            SCHEMA_REL,

            "record_schema_sha256":
            schema_sha,

            "adapter_path":
            ADAPTER_REL,

            "adapter_sha256":
            adapter_sha,

            "fixture_id_derivation":
            "qsv-f7- + first24(sha256('qsv-f7-fixture-v0.2\\n' + runtime_manifest_sha256 + '\\n' + case_id + '\\n')))",

            "observed_acceptance_derivation":
            DERIVATION_METHOD,

            "direct_observed_acceptance_field_in_f7":
            False,

            "new_cryptographic_execution_performed":
            False,
        },

        "records":
        records,

        "summary": {
            "record_count":
            12,

            "implementation_count":
            2,

            "selected_case_count":
            6,

            "observed_acceptance_true_count":
            true_count,

            "observed_acceptance_false_count":
            false_count,

            "result_state_pass_count":
            pass_count,

            "result_state_expected_reject_count":
            reject_count,

            "unexpected_accept_count":
            0,

            "unexpected_reject_count":
            0,

            "error_count":
            0,

            "decision":
            "f7_normalized_result_evidence_derived_and_verified",
        },

        "material_boundary": {
            "metadata_only":
            True,

            "raw_vector_payload_published":
            False,

            "raw_stdout_published":
            False,

            "raw_stderr_published":
            False,

            "private_key_material_published":
            False,

            "secret_key_material_published":
            False,

            "harness_binary_published":
            False,
        },

        "truth_boundaries": {
            "result_implies_nist_validation":
            False,

            "result_implies_fips_204_certification":
            False,

            "result_implies_complete_fips_204_conformance":
            False,

            "result_implies_complete_sigver_coverage":
            False,

            "result_implies_universal_mldsa_correctness":
            False,

            "result_proves_security_vulnerability_absence":
            False,

            "result_proves_system_wide_quantum_safety":
            False,

            "third_party_independent_reproduction":
            False,

            "historical_run_exact_command_backfilled":
            False,
        },
    }

    return result


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        default=str(
            Path(__file__).resolve().parent.parent
        ),
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args = parser.parse_args()

    root = Path(
        args.root
    ).resolve()

    output = Path(
        args.output
    )

    result = derive(
        root
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "QSV_MLDSA_NORMALIZED_RESULT_ADAPTER=PASS"
    )
    print(
        "NORMALIZED_RESULT_RECORD_COUNT=12"
    )
    print(
        "OBSERVED_ACCEPTANCE_TRUE_COUNT=6"
    )
    print(
        "OBSERVED_ACCEPTANCE_FALSE_COUNT=6"
    )
    print(
        "RESULT_STATE_PASS_COUNT=6"
    )
    print(
        "RESULT_STATE_EXPECTED_REJECT_COUNT=6"
    )
    print(
        "OBSERVED_ACCEPTANCE_DERIVATION=DETERMINISTIC"
    )
    print(
        "DIRECT_EXPECTED_VALID_COPY=NO"
    )
    print(
        "WORKFLOW_SUCCESS_AS_OBSERVATION=NO"
    )
    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )


if __name__ == "__main__":
    main()
