#!/usr/bin/env python3

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


CASE_DOMAIN = b"QSV-MLDSA-SOURCE-CASE-V1\x00"
FIXTURE_DOMAIN = b"QSV-MLDSA-NEUTRAL-FIXTURE-V1\x00"

SCHEMA_REL = (
    "schemas/"
    "qsv-mldsa-fixture-v0.3.schema.json"
)

TEMPLATE_REL = (
    "templates/"
    "qsv-mldsa-fixture-template-v0.3.json"
)

CONTRACT_REL = (
    "contracts/"
    "qsv-mldsa-neutral-fixture-canonicalization-contract-v0.1.json"
)

MAPPER_REL = (
    "runtime/"
    "qsv_mldsa_acvp_to_neutral_fixture_mapper_v0_1.py"
)

SELF_REL = (
    "runtime/"
    "verify_qsv_mldsa_neutral_fixture_gap_closure_v0_1.py"
)

NIST_BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

NIST_PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
)

WYCHE_BINDING_REL = (
    "vectors/bindings/"
    "qsv-mldsa-wycheproof-vector-source-v0.1.json"
)

WYCHE_PROFILE_REL = (
    "profiles/"
    "qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json"
)

ACVP_POS_REL = (
    "examples/"
    "qsv-mldsa-acvp-positive-canonical-v0.3.json"
)

ACVP_NEG_REL = (
    "examples/"
    "qsv-mldsa-acvp-negative-canonical-v0.3.json"
)

WYCHE_NEG_REL = (
    "examples/"
    "qsv-mldsa-wycheproof-negative-canonical-v0.3.json"
)

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


class ValidationError(
    AssertionError
):
    pass


def fail(message):
    raise ValidationError(
        message
    )


def sha256_bytes(value):
    return hashlib.sha256(
        value
    ).hexdigest()


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
        + canonical_bytes(
            value
        )
    )


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def commitment(value):
    if value is None:
        return None

    return {
        "sha256":
            value[
                "sha256"
            ],

        "byte_count":
            value[
                "byte_count"
            ],
    }


def case_descriptor(fixture):
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

        "artifact_commitments": {
            "message":
                commitment(
                    fixture[
                        "message"
                    ]
                ),

            "context":
                commitment(
                    fixture[
                        "context"
                    ]
                ),

            "private_test_key":
                commitment(
                    fixture[
                        "artifacts"
                    ][
                        "private_test_key"
                    ]
                ),

            "public_key":
                commitment(
                    fixture[
                        "artifacts"
                    ][
                        "public_key"
                    ]
                ),

            "signature":
                commitment(
                    fixture[
                        "artifacts"
                    ][
                        "signature"
                    ]
                ),
        },
    }


def fixture_hash(fixture):
    target = copy.deepcopy(
        fixture
    )

    target.pop(
        "neutral_fixture_sha256",
        None,
    )

    return domain_hash(
        FIXTURE_DOMAIN,
        target,
    )


def resolve_ref(
    schema_root,
    ref,
):
    prefix = "#/$defs/"

    if not ref.startswith(
        prefix
    ):
        fail(
            "unsupported ref: "
            + ref
        )

    name = ref[
        len(prefix):
    ]

    try:
        return schema_root[
            "$defs"
        ][
            name
        ]
    except KeyError as exc:
        raise ValidationError(
            "unknown ref: "
            + ref
        ) from exc


def type_matches(
    instance,
    expected_type,
):
    if expected_type == "object":
        return isinstance(
            instance,
            dict,
        )

    if expected_type == "array":
        return isinstance(
            instance,
            list,
        )

    if expected_type == "string":
        return isinstance(
            instance,
            str,
        )

    if expected_type == "integer":
        return (
            isinstance(
                instance,
                int,
            )
            and not isinstance(
                instance,
                bool,
            )
        )

    if expected_type == "boolean":
        return isinstance(
            instance,
            bool,
        )

    if expected_type == "null":
        return instance is None

    fail(
        "unsupported schema type: "
        + str(
            expected_type
        )
    )


def validate_instance(
    instance,
    schema,
    schema_root,
    path="$",
):
    if "$ref" in schema:
        return validate_instance(
            instance,
            resolve_ref(
                schema_root,
                schema[
                    "$ref"
                ],
            ),
            schema_root,
            path,
        )

    if "anyOf" in schema:
        successes = 0

        for candidate in schema[
            "anyOf"
        ]:
            try:
                validate_instance(
                    instance,
                    candidate,
                    schema_root,
                    path,
                )
                successes += 1
            except ValidationError:
                pass

        if successes < 1:
            fail(
                path
                + ": anyOf failed"
            )

    if "not" in schema:
        matched = False

        try:
            validate_instance(
                instance,
                schema[
                    "not"
                ],
                schema_root,
                path,
            )
            matched = True
        except ValidationError:
            matched = False

        if matched:
            fail(
                path
                + ": not constraint matched"
            )

    if "const" in schema:
        if instance != schema[
            "const"
        ]:
            fail(
                path
                + ": const mismatch"
            )

    if "enum" in schema:
        if instance not in schema[
            "enum"
        ]:
            fail(
                path
                + ": enum mismatch"
            )

    if "type" in schema:
        expected = schema[
            "type"
        ]

        if isinstance(
            expected,
            list,
        ):
            valid = any(
                type_matches(
                    instance,
                    item,
                )
                for item in expected
            )
        else:
            valid = type_matches(
                instance,
                expected,
            )

        if not valid:
            fail(
                path
                + ": type mismatch"
            )

    if isinstance(
        instance,
        str,
    ):
        if (
            "minLength"
            in schema
            and len(
                instance
            )
            < schema[
                "minLength"
            ]
        ):
            fail(
                path
                + ": minLength"
            )

        if (
            "pattern"
            in schema
            and re.fullmatch(
                schema[
                    "pattern"
                ],
                instance,
            )
            is None
        ):
            fail(
                path
                + ": pattern mismatch"
            )

    if (
        isinstance(
            instance,
            int,
        )
        and not isinstance(
            instance,
            bool,
        )
        and "minimum"
        in schema
        and instance
        < schema[
            "minimum"
        ]
    ):
        fail(
            path
            + ": minimum"
        )

    if isinstance(
        instance,
        list,
    ):
        if (
            "minItems"
            in schema
            and len(
                instance
            )
            < schema[
                "minItems"
            ]
        ):
            fail(
                path
                + ": minItems"
            )

        if schema.get(
            "uniqueItems"
        ):
            encoded = [
                canonical_bytes(
                    item
                )
                for item in instance
            ]

            if len(
                set(
                    encoded
                )
            ) != len(
                encoded
            ):
                fail(
                    path
                    + ": uniqueItems"
                )

        if "items" in schema:
            for index, item in enumerate(
                instance
            ):
                validate_instance(
                    item,
                    schema[
                        "items"
                    ],
                    schema_root,
                    (
                        path
                        + "["
                        + str(
                            index
                        )
                        + "]"
                    ),
                )

    if isinstance(
        instance,
        dict,
    ):
        required = schema.get(
            "required",
            [],
        )

        for key in required:
            if key not in instance:
                fail(
                    path
                    + ": missing "
                    + key
                )

        properties = schema.get(
            "properties",
            {},
        )

        for key, value in instance.items():
            if key in properties:
                validate_instance(
                    value,
                    properties[
                        key
                    ],
                    schema_root,
                    path
                    + "."
                    + key,
                )
                continue

            additional = schema.get(
                "additionalProperties",
                True,
            )

            if additional is False:
                fail(
                    path
                    + ": unexpected "
                    + key
                )

            if isinstance(
                additional,
                dict,
            ):
                validate_instance(
                    value,
                    additional,
                    schema_root,
                    path
                    + "."
                    + key,
                )


def verify_sidecar(
    root,
    rel,
):
    target = root / rel
    sidecar = root / (
        rel
        + ".sha256"
    )

    tokens = sidecar.read_text(
        encoding="utf-8"
    ).strip().split()

    if len(tokens) != 2:
        fail(
            "invalid sidecar: "
            + rel
        )

    digest = sha256_file(
        target
    )

    if tokens[0] != digest:
        fail(
            "sidecar digest mismatch: "
            + rel
        )

    if tokens[1] != rel:
        fail(
            "sidecar path mismatch: "
            + rel
        )


def verify_contract(
    contract,
):
    source = contract[
        "case_source_hash"
    ]

    neutral = contract[
        "neutral_fixture_hash"
    ]

    assert source[
        "algorithm"
    ] == "SHA-256"

    assert source[
        "domain"
    ] == (
        "QSV-MLDSA-SOURCE-CASE-V1"
    )

    assert source[
        "domain_separator"
    ] == "NUL"

    assert source[
        "encoding"
    ] == "UTF-8"

    assert source[
        "serialization"
    ] == "JSON"

    assert source[
        "json_sort_keys"
    ] is True

    assert source[
        "json_separators"
    ] == [
        ",",
        ":",
    ]

    assert source[
        "ensure_ascii"
    ] is False

    assert source[
        "is_raw_source_bytes_hash"
    ] is False

    assert source[
        "descriptor_fields"
    ] == [
        "source_family",
        "source_repository",
        "source_commit",
        "source_tree",
        "source_files",
        "case_identity",
        "expected_outcome",
        "artifact_commitments",
    ]

    assert neutral[
        "algorithm"
    ] == "SHA-256"

    assert neutral[
        "domain"
    ] == (
        "QSV-MLDSA-NEUTRAL-FIXTURE-V1"
    )

    assert neutral[
        "excluded_fields"
    ] == [
        "neutral_fixture_sha256"
    ]

    assert neutral[
        "self_referential_hash_allowed"
    ] is False


def verify_public_boundary(
    fixture,
):
    refs = [
        fixture[
            "message"
        ],
        fixture[
            "context"
        ],
    ]

    for name in (
        "private_test_key",
        "public_key",
        "signature",
    ):
        value = fixture[
            "artifacts"
        ][
            name
        ]

        if value is not None:
            refs.append(
                value
            )

    for ref in refs:
        if ref[
            "value"
        ] is not None:
            fail(
                "raw artifact value published"
            )

        if not isinstance(
            ref[
                "external_reference"
            ],
            str,
        ):
            fail(
                "external reference absent"
            )

    private_ref = fixture[
        "artifacts"
    ][
        "private_test_key"
    ]

    if (
        private_ref is not None
        and private_ref[
            "value"
        ] is not None
    ):
        fail(
            "raw private test key published"
        )


def expected_source_files(
    root,
    fixture,
):
    family = fixture[
        "source_binding"
    ][
        "source_family"
    ]

    if family == "nist_acvp":

        profile = load_json(
            root
            / NIST_PROFILE_REL
        )

        binding = load_json(
            root
            / NIST_BINDING_REL
        )

        profile_files = {
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

        expected = [
            {
                "role":
                    "prompt",

                "path":
                    PROMPT_REL,

                "sha256":
                    profile_files[
                        PROMPT_REL
                    ],
            },
            {
                "role":
                    "expected_results",

                "path":
                    EXPECTED_REL,

                "sha256":
                    profile_files[
                        EXPECTED_REL
                    ],
            },
        ]

        authority = binding[
            "source_authority"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_repository"
        ] == authority[
            "repository"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_commit"
        ] == authority[
            "selected_commit"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_tree"
        ] == authority[
            "selected_tree"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_tree_status"
        ] == "recorded"

        return expected

    if family == "wycheproof":

        profile = load_json(
            root
            / WYCHE_PROFILE_REL
        )

        binding = load_json(
            root
            / WYCHE_BINDING_REL
        )

        primary = fixture[
            "source_binding"
        ][
            "case_identity"
        ][
            "primary"
        ]

        matches = [
            case
            for case
            in profile[
                "selected_cases"
            ]
            if case[
                "case_id"
            ] == primary
        ]

        assert len(
            matches
        ) == 1

        case = matches[0]

        authority = binding[
            "source_authority"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_repository"
        ] == authority[
            "repository"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_commit"
        ] == authority[
            "selected_commit"
        ]

        assert fixture[
            "source_binding"
        ][
            "source_tree"
        ] is None

        assert fixture[
            "source_binding"
        ][
            "source_tree_status"
        ] == (
            "not_recorded_historical"
        )

        return [
            {
                "role":
                    "vector",

                "path":
                    case[
                        "source_path"
                    ],

                "sha256":
                    case[
                        "source_file_sha256"
                    ],
            }
        ]

    fail(
        "unknown source family"
    )


def verify_fixture(
    root,
    fixture,
    schema,
    contract_sha,
):
    validate_instance(
        fixture,
        schema,
        schema,
    )

    binding = fixture[
        "source_binding"
    ]

    canonical = binding[
        "canonicalization"
    ]

    assert canonical[
        "contract_path"
    ] == CONTRACT_REL

    assert canonical[
        "contract_sha256"
    ] == contract_sha

    assert canonical[
        "case_source_hash_profile"
    ] == (
        "QSV-MLDSA-SOURCE-CASE-V1"
    )

    assert canonical[
        "neutral_fixture_hash_profile"
    ] == (
        "QSV-MLDSA-NEUTRAL-FIXTURE-V1"
    )

    expected_files = expected_source_files(
        root,
        fixture,
    )

    assert binding[
        "source_files"
    ] == expected_files

    recomputed_case = domain_hash(
        CASE_DOMAIN,
        case_descriptor(
            fixture
        ),
    )

    assert binding[
        "case_source_sha256"
    ] == recomputed_case

    recomputed_fixture = fixture_hash(
        fixture
    )

    assert fixture[
        "neutral_fixture_sha256"
    ] == recomputed_fixture

    upper_id = fixture[
        "fixture_id"
    ].upper()

    assert "UNASSIGNED" not in upper_id
    assert "REPLACE" not in upper_id

    assert (
        fixture[
            "neutral_fixture_sha256"
        ]
        != "0" * 64
    )

    assert (
        binding[
            "case_source_sha256"
        ]
        != "0" * 64
    )

    for item in binding[
        "source_files"
    ]:
        assert (
            item[
                "sha256"
            ]
            != "0" * 64
        )

    verify_public_boundary(
        fixture
    )


def decode_hex(
    name,
    value,
):
    assert isinstance(
        value,
        str,
    ), name

    assert len(value) % 2 == 0, name

    try:
        return bytes.fromhex(
            value
        )
    except ValueError as exc:
        raise ValidationError(
            "invalid hex "
            + name
        ) from exc


def ref(data, external):
    return {
        "encoding":
            "hex",

        "value":
            None,

        "external_reference":
            external,

        "sha256":
            sha256_bytes(
                data
            ),

        "byte_count":
            len(data),
    }


def build_wycheproof_expected(
    root,
    source_path,
    contract_sha,
):
    profile = load_json(
        root
        / WYCHE_PROFILE_REL
    )

    binding = load_json(
        root
        / WYCHE_BINDING_REL
    )

    matches = [
        case
        for case
        in profile[
            "selected_cases"
        ]
        if case[
            "case_id"
        ] == (
            "QSV-MLDSA-"
            "WYCHEPROOF-44-0052"
        )
    ]

    assert len(matches) == 1

    case = matches[0]

    assert (
        sha256_file(
            source_path
        )
        == case[
            "source_file_sha256"
        ]
    )

    source = load_json(
        source_path
    )

    assert source[
        "algorithm"
    ] == "ML-DSA-44"

    group_index = case[
        "group_index"
    ]

    group = source[
        "testGroups"
    ][
        group_index
    ]

    tests = [
        test
        for test
        in group[
            "tests"
        ]
        if test[
            "tcId"
        ] == case[
            "tc_id"
        ]
    ]

    assert len(tests) == 1

    test = tests[0]

    private_key = decode_hex(
        "privateKey",
        group[
            "privateKey"
        ],
    )

    public_key = (
        decode_hex(
            "publicKey",
            group[
                "publicKey"
            ],
        )
        if isinstance(
            group.get(
                "publicKey"
            ),
            str,
        )
        else None
    )

    message_hex = (
        test.get(
            "msg"
        )
        if isinstance(
            test.get(
                "msg"
            ),
            str,
        )
        else test.get(
            "message"
        )
    )

    assert isinstance(
        message_hex,
        str,
    )

    message = decode_hex(
        "message",
        message_hex,
    )

    context_hex = (
        test.get(
            "ctx"
        )
        if isinstance(
            test.get(
                "ctx"
            ),
            str,
        )
        else (
            test.get(
                "context"
            )
            if isinstance(
                test.get(
                    "context"
                ),
                str,
            )
            else ""
        )
    )

    context = decode_hex(
        "context",
        context_hex,
    )

    signature = (
        decode_hex(
            "sig",
            test[
                "sig"
            ],
        )
        if isinstance(
            test.get(
                "sig"
            ),
            str,
        )
        else None
    )

    rel = case[
        "source_path"
    ]

    prefix = (
        "wycheproof:"
        + rel
        + "#testGroups["
        + str(
            group_index
        )
        + "]"
    )

    private_ref = ref(
        private_key,
        prefix
        + "/privateKey",
    )

    public_ref = (
        ref(
            public_key,
            prefix
            + "/publicKey",
        )
        if public_key is not None
        else None
    )

    message_ref = ref(
        message,
        (
            prefix
            + "/tests[tcId="
            + str(
                case[
                    "tc_id"
                ]
            )
            + "]/msg"
        ),
    )

    context_ref = ref(
        context,
        (
            prefix
            + "/tests[tcId="
            + str(
                case[
                    "tc_id"
                ]
            )
            + "]/context"
        ),
    )

    signature_ref = (
        ref(
            signature,
            (
                prefix
                + "/tests[tcId="
                + str(
                    case[
                        "tc_id"
                    ]
                )
                + "]/sig"
            ),
        )
        if signature is not None
        else None
    )

    authority = binding[
        "source_authority"
    ]

    fixture = {
        "schema":
            "qsv.mldsa.fixture.v0.3",

        "algorithm":
            "ML-DSA",

        "fixture_id":
            "QSV-MLDSA-WYCHEPROOF-44-0052-V0.3",

        "dimension":
            "negative_behavior",

        "parameter_set":
            "ML-DSA-44",

        "operation":
            "sign",

        "producer": {
            "project":
                "C2SP Wycheproof",

            "repository":
                authority[
                    "repository"
                ],

            "commit":
                authority[
                    "selected_commit"
                ],

            "tree":
                None,

            "tree_status":
                "not_recorded_historical",
        },

        "consumer":
            None,

        "message":
            message_ref,

        "context":
            context_ref,

        "randomness_mode":
            "deterministic",

        "expected_outcome":
            "reject",

        "artifacts": {
            "private_test_key":
                private_ref,

            "public_key":
                public_ref,

            "signature":
                signature_ref,
        },

        "provenance": {
            "source_specific": {
                "source_profile":
                    WYCHE_PROFILE_REL,

                "source_binding":
                    WYCHE_BINDING_REL,

                "source_operation":
                    case[
                        "source_operation"
                    ],

                "group_index":
                    group_index,

                "tc_id":
                    case[
                        "tc_id"
                    ],

                "flag":
                    case[
                        "flag"
                    ],

                "comment":
                    case[
                        "comment"
                    ],

                "lane":
                    case[
                        "lane"
                    ],
            },

            "generation": {
                "tool":
                    SELF_REL,

                "mode":
                    "deterministic_wycheproof_metadata_derivation",

                "new_crypto_execution":
                    False,
            },
        },

        "publication_classification":
            "public_non_secret_metadata_only",

        "source_binding": {
            "source_family":
                "wycheproof",

            "source_repository":
                authority[
                    "repository"
                ],

            "source_commit":
                authority[
                    "selected_commit"
                ],

            "source_tree":
                None,

            "source_tree_status":
                "not_recorded_historical",

            "source_files": [
                {
                    "role":
                        "vector",

                    "path":
                        rel,

                    "sha256":
                        case[
                            "source_file_sha256"
                        ],
                }
            ],

            "case_identity": {
                "primary":
                    case[
                        "case_id"
                    ],

                "coordinates": {
                    "group_index":
                        group_index,

                    "tc_id":
                        case[
                            "tc_id"
                        ],
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

    fixture[
        "source_binding"
    ][
        "case_source_sha256"
    ] = domain_hash(
        CASE_DOMAIN,
        case_descriptor(
            fixture
        ),
    )

    fixture[
        "neutral_fixture_sha256"
    ] = fixture_hash(
        fixture
    )

    return fixture


def expect_reject(
    name,
    operation,
):
    try:
        operation()
    except (
        AssertionError,
        ValidationError,
        KeyError,
        TypeError,
        ValueError,
    ):
        print(
            "NEGATIVE_MUTATION"
            f"|name={name}"
            "|status=REJECTED"
        )
        return

    fail(
        "negative mutation accepted: "
        + name
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--root",
        default=".",
    )

    parser.add_argument(
        "--nist-prompt",
    )

    parser.add_argument(
        "--nist-expected",
    )

    parser.add_argument(
        "--wycheproof-source",
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

    schema_path = (
        root
        / SCHEMA_REL
    )

    template_path = (
        root
        / TEMPLATE_REL
    )

    contract_path = (
        root
        / CONTRACT_REL
    )

    schema = load_json(
        schema_path
    )

    template = load_json(
        template_path
    )

    contract = load_json(
        contract_path
    )

    verify_contract(
        contract
    )

    contract_sha = sha256_file(
        contract_path
    )

    assert schema[
        "$id"
    ] == (
        "urn:qsv:mldsa:fixture:0.3"
    )

    assert schema[
        "properties"
    ][
        "schema"
    ][
        "const"
    ] == (
        "qsv.mldsa.fixture.v0.3"
    )

    assert schema[
        "additionalProperties"
    ] is False

    required = schema[
        "required"
    ]

    assert len(
        required
    ) == 17

    assert set(
        template.keys()
    ) == set(
        required
    )

    sidecar_targets = [
        CONTRACT_REL,
        MAPPER_REL,
        SELF_REL,
        ACVP_POS_REL,
        ACVP_NEG_REL,
        WYCHE_NEG_REL,
    ]

    for rel in sidecar_targets:
        verify_sidecar(
            root,
            rel,
        )

    examples = {
        "acvp_positive":
            load_json(
                root
                / ACVP_POS_REL
            ),

        "acvp_negative":
            load_json(
                root
                / ACVP_NEG_REL
            ),

        "wycheproof_negative":
            load_json(
                root
                / WYCHE_NEG_REL
            ),
    }

    for name, fixture in examples.items():
        verify_fixture(
            root,
            fixture,
            schema,
            contract_sha,
        )

        print(
            "FIXTURE_VALIDATION"
            f"|name={name}"
            "|schema=PASS"
            "|case_source_hash=PASS"
            "|neutral_fixture_hash=PASS"
            "|publication_boundary=PASS"
        )

    assert examples[
        "acvp_positive"
    ][
        "expected_outcome"
    ] == "accept"

    assert examples[
        "acvp_negative"
    ][
        "expected_outcome"
    ] == "reject"

    assert examples[
        "wycheproof_negative"
    ][
        "expected_outcome"
    ] == "reject"

    assert examples[
        "acvp_positive"
    ][
        "source_binding"
    ][
        "source_family"
    ] == "nist_acvp"

    assert examples[
        "acvp_negative"
    ][
        "source_binding"
    ][
        "source_family"
    ] == "nist_acvp"

    assert examples[
        "wycheproof_negative"
    ][
        "source_binding"
    ][
        "source_family"
    ] == "wycheproof"

    # Fail-closed mutation tests against the published examples.

    unknown = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    unknown[
        "unexpected_field"
    ] = True

    expect_reject(
        "unknown_top_level_field",
        lambda:
            validate_instance(
                unknown,
                schema,
                schema,
            ),
    )

    missing = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    del missing[
        "source_binding"
    ]

    expect_reject(
        "missing_required_field",
        lambda:
            validate_instance(
                missing,
                schema,
                schema,
            ),
    )

    source_hash_tamper = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    source_hash_tamper[
        "source_binding"
    ][
        "source_files"
    ][0][
        "sha256"
    ] = "1" * 64

    expect_reject(
        "source_file_hash_tamper",
        lambda:
            verify_fixture(
                root,
                source_hash_tamper,
                schema,
                contract_sha,
            ),
    )

    case_hash_tamper = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    case_hash_tamper[
        "source_binding"
    ][
        "case_source_sha256"
    ] = "2" * 64

    expect_reject(
        "case_source_hash_tamper",
        lambda:
            verify_fixture(
                root,
                case_hash_tamper,
                schema,
                contract_sha,
            ),
    )

    fixture_hash_tamper = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    fixture_hash_tamper[
        "neutral_fixture_sha256"
    ] = "3" * 64

    expect_reject(
        "neutral_fixture_hash_tamper",
        lambda:
            verify_fixture(
                root,
                fixture_hash_tamper,
                schema,
                contract_sha,
            ),
    )

    identity_tamper = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    identity_tamper[
        "source_binding"
    ][
        "case_identity"
    ][
        "coordinates"
    ][
        "tc_id"
    ] = 999999

    expect_reject(
        "case_identity_tamper",
        lambda:
            verify_fixture(
                root,
                identity_tamper,
                schema,
                contract_sha,
            ),
    )

    outcome_tamper = copy.deepcopy(
        examples[
            "acvp_positive"
        ]
    )

    outcome_tamper[
        "expected_outcome"
    ] = "reject"

    expect_reject(
        "expected_outcome_tamper",
        lambda:
            verify_fixture(
                root,
                outcome_tamper,
                schema,
                contract_sha,
            ),
    )

    private_tamper = copy.deepcopy(
        examples[
            "wycheproof_negative"
        ]
    )

    private_tamper[
        "artifacts"
    ][
        "private_test_key"
    ][
        "value"
    ] = "00"

    expect_reject(
        "raw_private_material_publication",
        lambda:
            verify_fixture(
                root,
                private_tamper,
                schema,
                contract_sha,
            ),
    )

    source_args = [
        args.nist_prompt,
        args.nist_expected,
        args.wycheproof_source,
    ]

    supplied_count = sum(
        value is not None
        for value in source_args
    )

    assert supplied_count in (
        0,
        3,
    )

    if supplied_count == 3:

        prompt_path = Path(
            args.nist_prompt
        ).resolve()

        expected_path = Path(
            args.nist_expected
        ).resolve()

        wyche_path = Path(
            args.wycheproof_source
        ).resolve()

        nist_profile = load_json(
            root
            / NIST_PROFILE_REL
        )

        source_inputs = {
            item[
                "path"
            ]:
            item[
                "sha256"
            ]

            for item
            in nist_profile[
                "source_inputs"
            ]
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

        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(
                temp
            )

            mapper = (
                root
                / MAPPER_REL
            )

            env = dict(
                os.environ
            )

            env.pop(
                "QSV_EXECUTE_CRYPTO",
                None,
            )

            cases = [
                (
                    "acvp_positive",
                    "ML-DSA-44",
                    1,
                    3,
                    root
                    / ACVP_POS_REL,
                ),
                (
                    "acvp_negative",
                    "ML-DSA-44",
                    1,
                    1,
                    root
                    / ACVP_NEG_REL,
                ),
            ]

            for (
                name,
                parameter_set,
                tg_id,
                tc_id,
                published,
            ) in cases:

                run1 = (
                    temp_root
                    / (
                        name
                        + "-1.json"
                    )
                )

                run2 = (
                    temp_root
                    / (
                        name
                        + "-2.json"
                    )
                )

                base = [
                    sys.executable,
                    str(
                        mapper
                    ),
                    "--root",
                    str(
                        root
                    ),
                    "--prompt",
                    str(
                        prompt_path
                    ),
                    "--expected",
                    str(
                        expected_path
                    ),
                    "--parameter-set",
                    parameter_set,
                    "--tg-id",
                    str(
                        tg_id
                    ),
                    "--tc-id",
                    str(
                        tc_id
                    ),
                ]

                subprocess.run(
                    base
                    + [
                        "--output",
                        str(
                            run1
                        ),
                    ],
                    check=True,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                subprocess.run(
                    base
                    + [
                        "--output",
                        str(
                            run2
                        ),
                    ],
                    check=True,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                assert (
                    run1.read_bytes()
                    == run2.read_bytes()
                )

                assert (
                    run1.read_bytes()
                    == published.read_bytes()
                )

                print(
                    "ACVP_REGENERATION"
                    f"|name={name}"
                    "|run1_run2_byte_identical=YES"
                    "|published_byte_identical=YES"
                )

        expected_wyche = (
            build_wycheproof_expected(
                root,
                wyche_path,
                contract_sha,
            )
        )

        published_wyche = examples[
            "wycheproof_negative"
        ]

        assert (
            canonical_bytes(
                expected_wyche
            )
            == canonical_bytes(
                published_wyche
            )
        )

        print(
            "WYCHEPROOF_REGENERATION"
            "|published_semantically_identical=YES"
        )

        print(
            "SOURCE_REGENERATION_PERFORMED=YES"
        )

    else:
        print(
            "SOURCE_REGENERATION_PERFORMED=NO"
        )

    print(
        "QSV_MLDSA_NEUTRAL_FIXTURE_GAP_CLOSURE_VERIFIER=PASS"
    )

    print(
        "FIXTURE_SCHEMA_VERSION=v0.3"
    )

    print(
        "CANONICAL_EXAMPLE_COUNT=3"
    )

    print(
        "ACVP_POSITIVE_CANONICAL_EXAMPLE=PASS"
    )

    print(
        "ACVP_NEGATIVE_CANONICAL_EXAMPLE=PASS"
    )

    print(
        "WYCHEPROOF_NEGATIVE_CANONICAL_EXAMPLE=PASS"
    )

    print(
        "CASE_SOURCE_HASH_RECOMPUTATION=PASS"
    )

    print(
        "NEUTRAL_FIXTURE_HASH_RECOMPUTATION=PASS"
    )

    print(
        "UNKNOWN_FIELD_REJECTION=PASS"
    )

    print(
        "MISSING_FIELD_REJECTION=PASS"
    )

    print(
        "SOURCE_HASH_TAMPER_REJECTION=PASS"
    )

    print(
        "CASE_HASH_TAMPER_REJECTION=PASS"
    )

    print(
        "FIXTURE_HASH_TAMPER_REJECTION=PASS"
    )

    print(
        "CASE_IDENTITY_TAMPER_REJECTION=PASS"
    )

    print(
        "EXPECTED_OUTCOME_TAMPER_REJECTION=PASS"
    )

    print(
        "RAW_PRIVATE_MATERIAL_REJECTION=PASS"
    )

    print(
        "RAW_VECTOR_PAYLOAD_PUBLISHED=NO"
    )

    print(
        "NEW_CRYPTO_EXECUTION_PERFORMED=NO"
    )


if __name__ == "__main__":
    main()
