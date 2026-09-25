#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path


CASE_DOMAIN = b"QSV-MLDSA-SOURCE-CASE-V1\x00"
FIXTURE_DOMAIN = b"QSV-MLDSA-NEUTRAL-FIXTURE-V1\x00"

PROMPT_REL = (
    "gen-val/json-files/"
    "ML-DSA-sigVer-FIPS204/"
    "prompt.json"
)

EXPECTED_REL = (
    "gen-val/json-files/"
    "ML-DSA-sigVer-FIPS204/"
    "expectedResults.json"
)

BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-neutral-fixture-canonicalization-contract-v0.1.json"
)

SELF_REL = (
    "runtime/"
    "qsv_mldsa_acvp_to_neutral_fixture_mapper_v0_1.py"
)


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    return sha256_bytes(
        path.read_bytes()
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
        domain
        + canonical_bytes(value)
    )


def decode_hex(name, value):
    assert isinstance(
        value,
        str,
    ), name

    assert len(value) % 2 == 0, name

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise AssertionError(
            "invalid hex: " + name
        ) from exc


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def unique_by(items, key, value):
    matches = [
        item
        for item in items
        if item.get(key) == value
    ]

    assert len(matches) == 1, (
        key,
        value,
        len(matches),
    )

    return matches[0]


def artifact_reference(
    data,
    external_reference,
):
    return {
        "encoding":
            "hex",

        "value":
            None,

        "external_reference":
            external_reference,

        "sha256":
            sha256_bytes(data),

        "byte_count":
            len(data),
    }


def artifact_commitment(reference):
    if reference is None:
        return None

    return {
        "sha256":
            reference["sha256"],

        "byte_count":
            reference["byte_count"],
    }


def fixture_case_descriptor(fixture):
    artifacts = {
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
    }

    binding = fixture[
        "source_binding"
    ]

    return {
        "source_family":
            binding[
                "source_family"
            ],

        "source_repository":
            binding[
                "source_repository"
            ],

        "source_commit":
            binding[
                "source_commit"
            ],

        "source_tree":
            binding[
                "source_tree"
            ],

        "source_files":
            binding[
                "source_files"
            ],

        "case_identity":
            binding[
                "case_identity"
            ],

        "expected_outcome":
            fixture[
                "expected_outcome"
            ],

        "artifact_commitments":
            artifacts,
    }


def fixture_hash(fixture):
    target = dict(fixture)

    target.pop(
        "neutral_fixture_sha256",
        None,
    )

    return domain_hash(
        FIXTURE_DOMAIN,
        target,
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        required=True,
    )

    parser.add_argument(
        "--prompt",
        required=True,
    )

    parser.add_argument(
        "--expected",
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
        "--output",
        required=True,
    )

    args = parser.parse_args()

    assert (
        os.environ.get(
            "QSV_EXECUTE_CRYPTO"
        )
        is None
    )

    root = Path(
        args.root
    ).resolve()

    prompt_path = Path(
        args.prompt
    ).resolve()

    expected_path = Path(
        args.expected
    ).resolve()

    output_path = Path(
        args.output
    )

    binding_path = (
        root
        / BINDING_REL
    )

    profile_path = (
        root
        / PROFILE_REL
    )

    contract_path = (
        root
        / CONTRACT_REL
    )

    binding = load_json(
        binding_path
    )

    profile = load_json(
        profile_path
    )

    contract = load_json(
        contract_path
    )

    assert contract[
        "case_source_hash"
    ][
        "domain"
    ] == (
        "QSV-MLDSA-SOURCE-CASE-V1"
    )

    assert contract[
        "neutral_fixture_hash"
    ][
        "domain"
    ] == (
        "QSV-MLDSA-NEUTRAL-FIXTURE-V1"
    )

    source_inputs = {
        item[
            "path"
        ]:
        item[
            "sha256"
        ]

        for item
        in profile[
            "source_inputs"
        ]
    }

    assert set(
        source_inputs
    ) == {
        PROMPT_REL,
        EXPECTED_REL,
    }

    assert (
        sha256_file(
            prompt_path
        )
        == source_inputs[
            PROMPT_REL
        ]
    )

    assert (
        sha256_file(
            expected_path
        )
        == source_inputs[
            EXPECTED_REL
        ]
    )

    bound_files = {
        item[
            "path"
        ]:
        item[
            "sha256"
        ]

        for item
        in binding[
            "selected_vector_surface"
        ][
            "files"
        ]
    }

    assert (
        bound_files[
            PROMPT_REL
        ]
        == source_inputs[
            PROMPT_REL
        ]
    )

    assert (
        bound_files[
            EXPECTED_REL
        ]
        == source_inputs[
            EXPECTED_REL
        ]
    )

    authority = binding[
        "source_authority"
    ]

    profile_authority = profile[
        "nist_source_authority"
    ]

    assert (
        authority[
            "selected_commit"
        ]
        == profile_authority[
            "exact_commit"
        ]
    )

    assert (
        authority[
            "selected_tree"
        ]
        == profile_authority[
            "exact_tree"
        ]
    )

    prompt = load_json(
        prompt_path
    )

    expected = load_json(
        expected_path
    )

    assert prompt[
        "algorithm"
    ] == "ML-DSA"

    assert prompt[
        "mode"
    ] == "sigVer"

    assert prompt[
        "revision"
    ] == "FIPS204"

    assert expected[
        "algorithm"
    ] == "ML-DSA"

    assert expected[
        "mode"
    ] == "sigVer"

    assert expected[
        "revision"
    ] == "FIPS204"

    selected_matches = [
        item
        for item
        in profile[
            "selected_cases"
        ]
        if (
            item[
                "parameter_set"
            ]
            == args.parameter_set
            and item[
                "tg_id"
            ]
            == args.tg_id
            and item[
                "tc_id"
            ]
            == args.tc_id
        )
    ]

    assert len(
        selected_matches
    ) == 1

    selected = selected_matches[0]

    prompt_group = unique_by(
        prompt[
            "testGroups"
        ],
        "tgId",
        args.tg_id,
    )

    expected_group = unique_by(
        expected[
            "testGroups"
        ],
        "tgId",
        args.tg_id,
    )

    assert prompt_group[
        "testType"
    ] == "AFT"

    assert prompt_group[
        "parameterSet"
    ] == args.parameter_set

    assert prompt_group[
        "signatureInterface"
    ] == "external"

    assert prompt_group[
        "preHash"
    ] == "pure"

    prompt_test = unique_by(
        prompt_group[
            "tests"
        ],
        "tcId",
        args.tc_id,
    )

    expected_test = unique_by(
        expected_group[
            "tests"
        ],
        "tcId",
        args.tc_id,
    )

    assert set(
        prompt_test
    ) == {
        "tcId",
        "pk",
        "message",
        "signature",
        "context",
    }

    assert set(
        expected_test
    ) == {
        "tcId",
        "testPassed",
    }

    assert (
        expected_test[
            "testPassed"
        ]
        is selected[
            "expected_valid"
        ]
    )

    public_key = decode_hex(
        "pk",
        prompt_test[
            "pk"
        ],
    )

    message = decode_hex(
        "message",
        prompt_test[
            "message"
        ],
    )

    signature = decode_hex(
        "signature",
        prompt_test[
            "signature"
        ],
    )

    context = decode_hex(
        "context",
        prompt_test[
            "context"
        ],
    )

    prefix = (
        PROMPT_REL
        + "#tgId="
        + str(
            args.tg_id
        )
        + "/tcId="
        + str(
            args.tc_id
        )
    )

    message_ref = artifact_reference(
        message,
        (
            "nist-acvp:"
            + prefix
            + "/message"
        ),
    )

    context_ref = artifact_reference(
        context,
        (
            "nist-acvp:"
            + prefix
            + "/context"
        ),
    )

    public_ref = artifact_reference(
        public_key,
        (
            "nist-acvp:"
            + prefix
            + "/pk"
        ),
    )

    signature_ref = artifact_reference(
        signature,
        (
            "nist-acvp:"
            + prefix
            + "/signature"
        ),
    )

    outcome = (
        "accept"
        if selected[
            "expected_valid"
        ]
        else "reject"
    )

    parameter_suffix = (
        args.parameter_set
        .split("-")[-1]
    )

    fixture_id = (
        "QSV-MLDSA-ACVP-"
        + parameter_suffix
        + "-TG"
        + str(
            args.tg_id
        )
        + "-TC"
        + str(
            args.tc_id
        )
        + "-V0.3"
    )

    source_files = [
        {
            "role":
                "prompt",

            "path":
                PROMPT_REL,

            "sha256":
                source_inputs[
                    PROMPT_REL
                ],
        },
        {
            "role":
                "expected_results",

            "path":
                EXPECTED_REL,

            "sha256":
                source_inputs[
                    EXPECTED_REL
                ],
        },
    ]

    contract_sha = sha256_file(
        contract_path
    )

    fixture = {
        "schema":
            "qsv.mldsa.fixture.v0.3",

        "algorithm":
            "ML-DSA",

        "fixture_id":
            fixture_id,

        "dimension":
            "known_answer_conformance",

        "parameter_set":
            args.parameter_set,

        "operation":
            "verify",

        "producer": {
            "project":
                "NIST ACVP-Server",

            "repository":
                authority[
                    "repository"
                ],

            "commit":
                authority[
                    "selected_commit"
                ],

            "tree":
                authority[
                    "selected_tree"
                ],

            "tree_status":
                "recorded",
        },

        "consumer":
            None,

        "message":
            message_ref,

        "context":
            context_ref,

        "randomness_mode":
            "not_applicable",

        "expected_outcome":
            outcome,

        "artifacts": {
            "private_test_key":
                None,

            "public_key":
                public_ref,

            "signature":
                signature_ref,
        },

        "provenance": {
            "source_specific": {
                "source_profile":
                    PROFILE_REL,

                "source_binding":
                    BINDING_REL,

                "test_type":
                    prompt_group[
                        "testType"
                    ],

                "signature_interface":
                    prompt_group[
                        "signatureInterface"
                    ],

                "pre_hash":
                    prompt_group[
                        "preHash"
                    ],

                "tg_id":
                    args.tg_id,

                "tc_id":
                    args.tc_id,
            },

            "generation": {
                "tool":
                    SELF_REL,

                "mode":
                    "deterministic_offline_metadata_mapping",

                "new_crypto_execution":
                    False,
            },
        },

        "publication_classification":
            "public_non_secret_metadata_only",

        "source_binding": {
            "source_family":
                "nist_acvp",

            "source_repository":
                authority[
                    "repository"
                ],

            "source_commit":
                authority[
                    "selected_commit"
                ],

            "source_tree":
                authority[
                    "selected_tree"
                ],

            "source_tree_status":
                "recorded",

            "source_files":
                source_files,

            "case_identity": {
                "primary":
                    (
                        "tg"
                        + str(
                            args.tg_id
                        )
                        + "-tc"
                        + str(
                            args.tc_id
                        )
                    ),

                "coordinates": {
                    "tg_id":
                        args.tg_id,

                    "tc_id":
                        args.tc_id,
                },
            },

            "case_source_sha256":
                "0" * 64,

            "canonicalization": {
                "contract_path":
                    CONTRACT_REL,

                "contract_sha256":
                    contract_sha,

                "case_source_hash_profile":
                    "QSV-MLDSA-SOURCE-CASE-V1",

                "neutral_fixture_hash_profile":
                    "QSV-MLDSA-NEUTRAL-FIXTURE-V1",
            },
        },

        "neutral_fixture_sha256":
            "0" * 64,
    }

    descriptor = fixture_case_descriptor(
        fixture
    )

    fixture[
        "source_binding"
    ][
        "case_source_sha256"
    ] = domain_hash(
        CASE_DOMAIN,
        descriptor,
    )

    fixture[
        "neutral_fixture_sha256"
    ] = fixture_hash(
        fixture
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            fixture,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "QSV_MLDSA_ACVP_TO_NEUTRAL_FIXTURE_MAPPER=PASS"
    )

    print(
        "PARAMETER_SET="
        + args.parameter_set
    )

    print(
        "TG_ID="
        + str(
            args.tg_id
        )
    )

    print(
        "TC_ID="
        + str(
            args.tc_id
        )
    )

    print(
        "EXPECTED_OUTCOME="
        + outcome
    )

    print(
        "CASE_SOURCE_SHA256="
        + fixture[
            "source_binding"
        ][
            "case_source_sha256"
        ]
    )

    print(
        "NEUTRAL_FIXTURE_SHA256="
        + fixture[
            "neutral_fixture_sha256"
        ]
    )

    print(
        "RAW_VECTOR_PAYLOAD_PUBLISHED=NO"
    )

    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )


if __name__ == "__main__":
    main()
