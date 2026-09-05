#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path


EXPECTED_SIZES = {
    "ML-DSA-44": {
        "pk": 1312,
        "signature": 2420,
    },
    "ML-DSA-65": {
        "pk": 1952,
        "signature": 3309,
    },
    "ML-DSA-87": {
        "pk": 2592,
        "signature": 4627,
    },
}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def decode_hex(name, value):
    assert isinstance(value, str)
    assert len(value) % 2 == 0

    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise AssertionError(
            f"invalid hex field: {name}"
        ) from exc


parser = argparse.ArgumentParser()

parser.add_argument("--profile", required=True)
parser.add_argument("--prompt", required=True)
parser.add_argument("--expected", required=True)
parser.add_argument("--manifest", required=True)
parser.add_argument("--runtime-dir")

args = parser.parse_args()


with open(args.profile, encoding="utf-8") as f:
    profile = json.load(f)

with open(args.prompt, encoding="utf-8") as f:
    prompt = json.load(f)

with open(args.expected, encoding="utf-8") as f:
    expected = json.load(f)


surface = profile["execution_surface"]

assert surface["algorithm"] == "ML-DSA"
assert surface["mode"] == "sigVer"
assert surface["revision"] == "FIPS204"
assert surface["signature_interface"] == "external"
assert surface["pre_hash"] == "pure"
assert surface["selected_case_count"] == 6

assert prompt["algorithm"] == "ML-DSA"
assert prompt["mode"] == "sigVer"
assert prompt["revision"] == "FIPS204"

assert expected["algorithm"] == "ML-DSA"
assert expected["mode"] == "sigVer"
assert expected["revision"] == "FIPS204"


prompt_groups = {
    group["tgId"]: group
    for group in prompt["testGroups"]
}

expected_groups = {
    group["tgId"]: group
    for group in expected["testGroups"]
}


runtime_enabled = args.runtime_dir is not None

if runtime_enabled:
    if os.environ.get("QSV_EXECUTE_CRYPTO") != "YES":
        raise SystemExit(
            "STOP: QSV_EXECUTE_CRYPTO=YES required "
            "before runtime payload emission"
        )

    runtime_root = Path(args.runtime_dir)

    runtime_root.mkdir(
        parents=True,
        exist_ok=False,
    )

else:
    runtime_root = None


manifest_cases = []


for selected in profile["selected_cases"]:

    parameter_set = selected["parameter_set"]
    tg_id = selected["tg_id"]
    tc_id = selected["tc_id"]
    expected_valid = selected["expected_valid"]

    assert parameter_set in EXPECTED_SIZES
    assert tg_id in prompt_groups
    assert tg_id in expected_groups

    prompt_group = prompt_groups[tg_id]
    expected_group = expected_groups[tg_id]

    assert prompt_group["testType"] == "AFT"
    assert prompt_group["parameterSet"] == parameter_set
    assert prompt_group["signatureInterface"] == "external"
    assert prompt_group["preHash"] == "pure"

    prompt_tests = {
        test["tcId"]: test
        for test in prompt_group["tests"]
    }

    expected_tests = {
        test["tcId"]: test
        for test in expected_group["tests"]
    }

    assert tc_id in prompt_tests
    assert tc_id in expected_tests

    test = prompt_tests[tc_id]
    result = expected_tests[tc_id]

    assert set(test.keys()) == {
        "tcId",
        "pk",
        "message",
        "signature",
        "context",
    }

    assert result["testPassed"] is expected_valid

    pk = decode_hex("pk", test["pk"])
    message = decode_hex("message", test["message"])
    signature = decode_hex("signature", test["signature"])
    context = decode_hex("context", test["context"])

    assert len(pk) == EXPECTED_SIZES[
        parameter_set
    ]["pk"]

    assert len(signature) == EXPECTED_SIZES[
        parameter_set
    ]["signature"]

    assert len(context) <= 255

    manifest_cases.append(
        {
            "parameter_set":
                parameter_set,

            "tg_id":
                tg_id,

            "tc_id":
                tc_id,

            "expected_valid":
                expected_valid,

            "pk_size_bytes":
                len(pk),

            "message_size_bytes":
                len(message),

            "context_size_bytes":
                len(context),

            "signature_size_bytes":
                len(signature),

            "pk_sha256":
                digest(pk),

            "message_sha256":
                digest(message),

            "context_sha256":
                digest(context),

            "signature_sha256":
                digest(signature),
        }
    )

    if runtime_enabled:

        case_dir = (
            runtime_root
            / (
                parameter_set
                + "-tg"
                + str(tg_id)
                + "-tc"
                + str(tc_id)
            )
        )

        case_dir.mkdir()

        (case_dir / "pk.bin").write_bytes(pk)
        (case_dir / "message.bin").write_bytes(message)
        (case_dir / "context.bin").write_bytes(context)
        (case_dir / "signature.bin").write_bytes(signature)

        (
            case_dir
            / "case.json"
        ).write_text(
            json.dumps(
                {
                    "parameter_set":
                        parameter_set,

                    "tg_id":
                        tg_id,

                    "tc_id":
                        tc_id,

                    "expected_valid":
                        expected_valid,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


assert len(manifest_cases) == 6


manifest = {
    "schema":
        "qsv.mldsa.runtime-sixcase-metadata.v0.1",

    "payload_embedded":
        False,

    "runtime_payload_emitted":
        runtime_enabled,

    "case_count":
        6,

    "cases":
        manifest_cases,
}


Path(args.manifest).write_text(
    json.dumps(
        manifest,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)


print("QSV_MLDSA_SIXCASE_METADATA_EXTRACTION=PASS")
print("SELECTED_CASE_COUNT=6")

print(
    "RAW_PAYLOAD_WRITTEN="
    + (
        "YES"
        if runtime_enabled
        else "NO"
    )
)
