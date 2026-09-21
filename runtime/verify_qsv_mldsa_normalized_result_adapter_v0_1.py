#!/usr/bin/env python3

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ADAPTER_REL = (
    "runtime/"
    "qsv_mldsa_normalized_result_adapter_v0_1.py"
)

ADAPTER_SC_REL = (
    ADAPTER_REL
    + ".sha256"
)

SELF_REL = (
    "runtime/"
    "verify_qsv_mldsa_normalized_result_adapter_v0_1.py"
)

SELF_SC_REL = (
    SELF_REL
    + ".sha256"
)

SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-fixture-v0.2.schema.json"
)

TEMPLATE_REL = (
    "templates/"
    "qsv-mldsa-fixture-template-v0.2.json"
)

RUNNER_REL = (
    "runners/"
    "qsv-mldsa-runner-interface-v0.1.json"
)

RESULT_REL = (
    "results/"
    "qsv_mldsa_f7_normalized_result_evidence_v0_1/"
    "qsv_mldsa_f7_normalized_result_evidence_v0_1.json"
)

RESULT_SC_REL = (
    RESULT_REL
    + ".sha256"
)

EXPECTED_FIELDS = [
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

HEX64 = re.compile(
    r"^[0-9a-f]{64}$"
)

FIXTURE_ID = re.compile(
    r"^qsv-f7-[0-9a-f]{24}$"
)

DERIVATION_METHOD = (
    "pinned_harness_semantics_plus_exact_runtime_argv_"
    "plus_actual_exit_status_plus_stdout_sha256_commitment"
)


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def verify_sidecar(
    root,
    rel,
):
    path = root / rel
    sidecar = root / (rel + ".sha256")

    assert path.is_file()
    assert sidecar.is_file()

    tokens = sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    assert len(tokens) == 2
    assert tokens[0] == sha256(path)
    assert tokens[1] == rel


def validate_record(
    record,
):
    assert set(
        record.keys()
    ) == set(
        EXPECTED_FIELDS
    )

    assert FIXTURE_ID.fullmatch(
        record[
            "fixture_id"
        ]
    )

    assert record[
        "implementation"
    ] in {
        "cloudflare-circl",
        "openssl",
    }

    assert record[
        "operation"
    ] == "sigVer"

    assert record[
        "result_state"
    ] in {
        "pass",
        "expected_reject",
        "unexpected_accept",
        "unexpected_reject",
        "unsupported",
        "error",
        "blocked",
    }

    assert isinstance(
        record[
            "observed_acceptance"
        ],
        bool,
    )

    assert isinstance(
        record[
            "exact_command"
        ],
        str,
    )

    assert record[
        "exact_command"
    ]

    inputs = record[
        "inputs"
    ]

    assert set(
        inputs.keys()
    ) == {
        "case",
        "artifacts",
    }

    case = inputs[
        "case"
    ]

    assert set(
        case.keys()
    ) == {
        "case_id",
        "parameter_set",
        "tg_id",
        "tc_id",
        "source_expected_valid",
    }

    assert case[
        "parameter_set"
    ] in {
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    }

    assert isinstance(
        case[
            "source_expected_valid"
        ],
        bool,
    )

    artifacts = inputs[
        "artifacts"
    ]

    assert set(
        artifacts.keys()
    ) == {
        "public_key",
        "message",
        "context",
        "signature",
    }

    for item in artifacts.values():
        assert set(
            item.keys()
        ) == {
            "sha256",
            "byte_count",
        }

        assert HEX64.fullmatch(
            item[
                "sha256"
            ]
        )

        assert isinstance(
            item[
                "byte_count"
            ],
            int,
        )

        assert item[
            "byte_count"
        ] >= 0

    output = record[
        "output"
    ]

    assert set(
        output.keys()
    ) == {
        "stdout_sha256",
        "stdout_byte_count",
        "stderr_sha256",
        "stderr_byte_count",
        "observation_derivation",
    }

    assert HEX64.fullmatch(
        output[
            "stdout_sha256"
        ]
    )

    assert HEX64.fullmatch(
        output[
            "stderr_sha256"
        ]
    )

    assert output[
        "stdout_byte_count"
    ] >= 0

    assert output[
        "stderr_byte_count"
    ] >= 0

    derivation = output[
        "observation_derivation"
    ]

    assert derivation == {
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
    }

    exit_status = record[
        "exit_status"
    ]

    assert set(
        exit_status.keys()
    ) == {
        "code",
        "process_started",
        "launch_error",
    }

    assert exit_status[
        "code"
    ] == 0

    assert exit_status[
        "process_started"
    ] is True

    assert exit_status[
        "launch_error"
    ] is None

    hashes = record[
        "artifact_hashes"
    ]

    assert set(
        hashes.keys()
    ) == {
        "resolved_executable_sha256",
        "workflow_sha256",
        "capture_launcher_sha256",
        "runtime_manifest_sha256",
        "source_evidence_sha256",
    }

    for value in hashes.values():
        assert HEX64.fullmatch(
            value
        )

    env = record[
        "environment"
    ]

    assert env == {
        "allowlisted": {
            "QSV_EXECUTE_CRYPTO":
            "YES",
        },
        "inherited_parent_environment_published":
        False,
        "public_environment_capture_policy":
        "explicit_allowlist_only",
    }


def main():
    if "QSV_EXECUTE_CRYPTO" in os.environ:
        raise SystemExit(
            "FAIL: QSV_EXECUTE_CRYPTO must be absent"
        )

    root = (
        Path(
            sys.argv[1]
        ).resolve()
        if len(sys.argv) == 2
        else Path(
            __file__
        ).resolve().parent.parent
    )

    adapter = root / ADAPTER_REL
    self_path = root / SELF_REL
    schema_path = root / SCHEMA_REL
    template_path = root / TEMPLATE_REL
    runner_path = root / RUNNER_REL
    result_path = root / RESULT_REL

    for path in [
        adapter,
        self_path,
        schema_path,
        template_path,
        runner_path,
        result_path,
    ]:
        assert path.is_file()

    verify_sidecar(
        root,
        ADAPTER_REL,
    )

    verify_sidecar(
        root,
        SELF_REL,
    )

    verify_sidecar(
        root,
        RESULT_REL,
    )

    schema = load(
        schema_path
    )

    template = load(
        template_path
    )

    runner = load(
        runner_path
    )

    result = load(
        result_path
    )

    assert schema[
        "$id"
    ] == (
        "urn:qsv:mldsa:"
        "normalized-result-record:0.2"
    )

    assert schema[
        "additionalProperties"
    ] is False

    assert schema[
        "required"
    ] == EXPECTED_FIELDS

    assert set(
        schema[
            "properties"
        ]
    ) == set(
        EXPECTED_FIELDS
    )

    assert runner[
        "output"
    ][
        "required_fields"
    ] == EXPECTED_FIELDS

    assert set(
        template.keys()
    ) == set(
        EXPECTED_FIELDS
    )

    assert (
        "execution_state"
        not in template
    )

    assert (
        "observed_acceptance"
        in template
    )

    assert set(
        result.keys()
    ) == {
        "schema",
        "source_authority",
        "normalization_authority",
        "records",
        "summary",
        "material_boundary",
        "truth_boundaries",
    }

    assert result[
        "schema"
    ] == (
        "qsv.mldsa."
        "f7-normalized-result-evidence.v0.1"
    )

    source = result[
        "source_authority"
    ]

    assert source[
        "public_evidence_commit"
    ] == (
        "dfb1bc5849340d791b60a29f531952e6a0707e2d"
    )

    assert source[
        "execution_commit"
    ] == (
        "e7c2f85a6cdf49c39a42cccdd96ba6ab1a8da6cd"
    )

    assert source[
        "execution_tree"
    ] == (
        "e97833bc5a06a49309a30f292dfdc84436668836"
    )

    assert source[
        "github_run_id"
    ] == "34968252038"

    assert source[
        "github_run_attempt"
    ] == "1"

    assert source[
        "github_job_id_numeric"
    ] == 104377847614

    normalization = result[
        "normalization_authority"
    ]

    assert normalization[
        "adapter_sha256"
    ] == sha256(
        adapter
    )

    assert normalization[
        "record_schema_sha256"
    ] == sha256(
        schema_path
    )

    assert normalization[
        "runner_interface_sha256"
    ] == sha256(
        runner_path
    )

    assert normalization[
        "observed_acceptance_derivation"
    ] == DERIVATION_METHOD

    assert normalization[
        "direct_observed_acceptance_field_in_f7"
    ] is False

    assert normalization[
        "new_cryptographic_execution_performed"
    ] is False

    records = result[
        "records"
    ]

    assert len(
        records
    ) == 12

    for record in records:
        validate_record(
            record
        )

    true_count = sum(
        1
        for record in records
        if record[
            "observed_acceptance"
        ]
    )

    false_count = (
        len(records)
        - true_count
    )

    pass_count = sum(
        1
        for record in records
        if record[
            "result_state"
        ] == "pass"
    )

    reject_count = sum(
        1
        for record in records
        if record[
            "result_state"
        ] == "expected_reject"
    )

    assert true_count == 6
    assert false_count == 6
    assert pass_count == 6
    assert reject_count == 6

    assert result[
        "summary"
    ] == {
        "record_count":
        12,

        "implementation_count":
        2,

        "selected_case_count":
        6,

        "observed_acceptance_true_count":
        6,

        "observed_acceptance_false_count":
        6,

        "result_state_pass_count":
        6,

        "result_state_expected_reject_count":
        6,

        "unexpected_accept_count":
        0,

        "unexpected_reject_count":
        0,

        "error_count":
        0,

        "decision":
        "f7_normalized_result_evidence_derived_and_verified",
    }

    assert result[
        "material_boundary"
    ] == {
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
    }

    truth = result[
        "truth_boundaries"
    ]

    for key in [
        "result_implies_nist_validation",
        "result_implies_fips_204_certification",
        "result_implies_complete_fips_204_conformance",
        "result_implies_complete_sigver_coverage",
        "result_implies_universal_mldsa_correctness",
        "result_proves_security_vulnerability_absence",
        "result_proves_system_wide_quantum_safety",
        "third_party_independent_reproduction",
        "historical_run_exact_command_backfilled",
    ]:
        assert truth[
            key
        ] is False

    # Independent deterministic regeneration.
    with tempfile.TemporaryDirectory(
        prefix="qsv-ogc5-normalized-"
    ) as temp_name:

        regenerated = (
            Path(
                temp_name
            )
            / "regenerated.json"
        )

        env = os.environ.copy()

        env.pop(
            "QSV_EXECUTE_CRYPTO",
            None,
        )

        env[
            "PYTHONDONTWRITEBYTECODE"
        ] = "1"

        proc = subprocess.run(
            [
                sys.executable,
                str(
                    adapter
                ),
                "--root",
                str(
                    root
                ),
                "--output",
                str(
                    regenerated
                ),
            ],
            cwd=str(
                root
            ),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        assert proc.returncode == 0, (
            proc.stdout
        )

        assert regenerated.read_bytes() == (
            result_path.read_bytes()
        )

    raw_text = result_path.read_text(
        encoding="utf-8"
    )

    for forbidden in [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "\"raw_stdout\"",
        "\"raw_stderr\"",
        "\"private_key\"",
        "\"secret_key\"",
        "\"raw_vector_payload\"",
    ]:
        assert forbidden not in raw_text

    print(
        "QSV_MLDSA_NORMALIZED_RESULT_VERIFIER=PASS"
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
        "DETERMINISTIC_REGENERATION_BYTE_IDENTICAL=YES"
    )
    print(
        "OBSERVED_ACCEPTANCE_MARKED_DERIVED=YES"
    )
    print(
        "EXPECTED_VALID_DIRECT_COPY=NO"
    )
    print(
        "WORKFLOW_SUCCESS_AS_OBSERVED_ACCEPTANCE=NO"
    )
    print(
        "RAW_VECTOR_PAYLOAD_PRESENT=NO"
    )
    print(
        "RAW_STDOUT_PRESENT=NO"
    )
    print(
        "RAW_STDERR_PRESENT=NO"
    )
    print(
        "PRIVATE_KEY_MATERIAL_PRESENT=NO"
    )
    print(
        "THIRD_PARTY_INDEPENDENT_REPRODUCTION=false"
    )
    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )


if __name__ == "__main__":
    main()
