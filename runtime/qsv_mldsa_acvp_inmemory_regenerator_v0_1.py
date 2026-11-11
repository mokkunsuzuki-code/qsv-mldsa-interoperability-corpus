"""FRESH_G01: selected-six, byte-pinned ACVP->legacy fixture mapping.

No I/O, imports of target runner, crypto sigVer, or import-time verification.
Historical v0.3 fixture serializer is deliberately NOT RFC 8785 JCS.
The mapping is independently reauthored from an indexed reference and the
approved profile; exact historical output agreement is NOT runtime verified.
"""
import hashlib
import json
import re

SOURCE_REPOSITORY = "https://github.com/usnistgov/ACVP-Server.git"
SOURCE_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCE_TREE = "a6b81add7faf8a8b647afcdc54268615decde9b5"
PROMPT_REL = "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json"
EXPECTED_REL = "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json"
PROFILE_REL = "profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json"
BINDING_REL = "vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json"
CONTRACT_REL = "contracts/qsv-mldsa-neutral-fixture-canonicalization-contract-v0.1.json"
LEGACY_MAPPER_REL = "runtime/qsv_mldsa_acvp_to_neutral_fixture_mapper_v0_1.py"
PINNED = {
    "prompt": "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
    "expected_results": "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
}
SELECTED = {
    ("ML-DSA-44", 1, 1): False, ("ML-DSA-44", 1, 3): True,
    ("ML-DSA-65", 3, 31): False, ("ML-DSA-65", 3, 33): True,
    ("ML-DSA-87", 5, 61): False, ("ML-DSA-87", 5, 63): True,
}
CASE_DOMAIN = b"QSV-MLDSA-SOURCE-CASE-V1\x00"
FIXTURE_DOMAIN = b"QSV-MLDSA-NEUTRAL-FIXTURE-V1\x00"

class RegenerationBlocked(ValueError):
    pass

def check(condition, reason):
    if not condition:
        raise RegenerationBlocked(reason)

def sha(raw):
    check(type(raw) is bytes, "SOURCE_INPUT_NOT_IMMUTABLE_BYTES")
    return hashlib.sha256(raw).hexdigest()

def _pairs(pairs):
    out = {}
    for key, val in pairs:
        check(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = val
    return out

def _no_constant(_):
    raise RegenerationBlocked("NON_FINITE_JSON")

def decode(raw):
    check(type(raw) is bytes, "JSON_INPUT_NOT_BYTES")
    try:
        obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                         parse_constant=_no_constant)
    except (UnicodeError, ValueError) as exc:
        raise RegenerationBlocked("JSON_DECODE_FAILED") from exc
    check(type(obj) is dict, "JSON_OBJECT_REQUIRED")
    return obj

def _unique(seq, key, needle):
    check(type(seq) is list, "GROUP_OR_TEST_LIST_REQUIRED")
    matches = [x for x in seq if type(x) is dict and type(x.get(key)) is int
               and x[key] == needle]
    check(len(matches) == 1, "ACVP_SELECTOR_NOT_UNIQUE")
    return matches[0]

def _hex(name, value):
    check(type(value) is str and re.fullmatch(r"(?:[A-Fa-f0-9]{2})*", value) is not None,
          "INVALID_ACVP_HEX_" + name)
    return bytes.fromhex(value)

def _ref(value, target):
    return {"encoding": "hex", "value": None, "external_reference": target,
            "sha256": sha(value), "byte_count": len(value)}

def _legacy_bytes(obj, pretty=False):
    if pretty:
        return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True,
                           allow_nan=False) + "\n").encode("utf-8")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def _domain(prefix, obj):
    return sha(prefix + _legacy_bytes(obj))

def _commitment(node):
    return None if node is None else {"sha256": node["sha256"], "byte_count": node["byte_count"]}

def regenerate_from_verified_bytes(prompt_bytes, expected_results_bytes, case_identity, authority):
    """Return (fixture, exact serialized bytes) using supplied, pinned bytes only.

    Caller binds output to independently pinned published fixture and evidence.
    No path is read after checking SHA-256 (TOCTOU-resistant immutable bytes).
    """
    check(type(authority) is dict and type(case_identity) is dict, "AUTHORITY_OR_CASE_INVALID")
    check(set(case_identity) == {"case_id", "parameter_set", "tg_id", "tc_id", "expected_valid"},
          "CASE_FIELDS_INVALID")
    p, tg, tc, valid = (case_identity[k] for k in
                        ("parameter_set", "tg_id", "tc_id", "expected_valid"))
    check(type(p) is str and type(tg) is int and type(tc) is int and type(valid) is bool and
          (p, tg, tc) in SELECTED and SELECTED[(p, tg, tc)] is valid and
          case_identity["case_id"] == f"{p}-tg{tg}-tc{tc}", "CASE_NOT_SELECTED")
    check(sha(prompt_bytes) == PINNED["prompt"] and
          sha(expected_results_bytes) == PINNED["expected_results"],
          "PINNED_SOURCE_DIGEST_MISMATCH")
    check(authority.get("source_repository") == SOURCE_REPOSITORY and
          authority.get("source_commit") == SOURCE_COMMIT and
          authority.get("source_tree") == SOURCE_TREE, "SOURCE_AUTHORITY_MISMATCH")
    contract_digest = authority.get("neutral_contract_sha256")
    check(type(contract_digest) is str and re.fullmatch(r"[0-9a-f]{64}", contract_digest),
          "NEUTRAL_CONTRACT_REFERENCE_REQUIRED")
    prompt, expected = decode(prompt_bytes), decode(expected_results_bytes)
    for name, source in (("prompt", prompt), ("expected", expected)):
        check(source.get("algorithm") == "ML-DSA" and source.get("mode") == "sigVer" and
              source.get("revision") == "FIPS204", "ACVP_HEADER_MISMATCH_" + name)
    group = _unique(prompt.get("testGroups"), "tgId", tg)
    exp_group = _unique(expected.get("testGroups"), "tgId", tg)
    check(group.get("testType") == "AFT" and group.get("parameterSet") == p and
          group.get("signatureInterface") == "external" and group.get("preHash") == "pure",
          "ACVP_GROUP_METADATA_MISMATCH")
    test = _unique(group.get("tests"), "tcId", tc)
    exp_test = _unique(exp_group.get("tests"), "tcId", tc)
    check(set(test) == {"tcId", "pk", "message", "signature", "context"} and
          set(exp_test) == {"tcId", "testPassed"} and
          exp_test["testPassed"] is valid, "ACVP_SELECTED_CASE_MISMATCH")
    prefix = PROMPT_REL + f"#tgId={tg}/tcId={tc}"
    message = _ref(_hex("message", test["message"]), "nist-acvp:" + prefix + "/message")
    context = _ref(_hex("context", test["context"]), "nist-acvp:" + prefix + "/context")
    pub = _ref(_hex("pk", test["pk"]), "nist-acvp:" + prefix + "/pk")
    signature = _ref(_hex("signature", test["signature"]), "nist-acvp:" + prefix + "/signature")
    fixture = {
        "schema": "qsv.mldsa.fixture.v0.3", "algorithm": "ML-DSA",
        "fixture_id": f"QSV-MLDSA-ACVP-{p.split('-')[-1]}-TG{tg}-TC{tc}-V0.3",
        "dimension": "known_answer_conformance", "parameter_set": p,
        "operation": "verify",
        "producer": {"project": "NIST ACVP-Server", "repository": SOURCE_REPOSITORY,
                     "commit": SOURCE_COMMIT, "tree": SOURCE_TREE, "tree_status": "recorded"},
        "consumer": None, "message": message, "context": context,
        "randomness_mode": "not_applicable", "expected_outcome": "accept" if valid else "reject",
        "artifacts": {"private_test_key": None, "public_key": pub, "signature": signature},
        "provenance": {
            "source_specific": {"source_profile": PROFILE_REL, "source_binding": BINDING_REL,
                "test_type": group["testType"], "signature_interface": group["signatureInterface"],
                "pre_hash": group["preHash"], "tg_id": tg, "tc_id": tc},
            "generation": {"tool": LEGACY_MAPPER_REL,
                           "mode": "deterministic_offline_metadata_mapping", "new_crypto_execution": False}},
        "publication_classification": "public_non_secret_metadata_only",
        "source_binding": {
            "source_family": "nist_acvp", "source_repository": SOURCE_REPOSITORY,
            "source_commit": SOURCE_COMMIT, "source_tree": SOURCE_TREE,
            "source_tree_status": "recorded",
            "source_files": [
                {"role": "prompt", "path": PROMPT_REL, "sha256": PINNED["prompt"]},
                {"role": "expected_results", "path": EXPECTED_REL,
                 "sha256": PINNED["expected_results"]}],
            "case_identity": {"primary": f"tg{tg}-tc{tc}",
                              "coordinates": {"tg_id": tg, "tc_id": tc}},
            "case_source_sha256": "0" * 64,
            "canonicalization": {
                "contract_path": CONTRACT_REL, "contract_sha256": contract_digest,
                "case_source_hash_profile": "QSV-MLDSA-SOURCE-CASE-V1",
                "neutral_fixture_hash_profile": "QSV-MLDSA-NEUTRAL-FIXTURE-V1"}},
        "neutral_fixture_sha256": "0" * 64
    }
    descriptor = {
        "source_family": "nist_acvp", "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT, "source_tree": SOURCE_TREE,
        "source_files": fixture["source_binding"]["source_files"],
        "case_identity": fixture["source_binding"]["case_identity"],
        "expected_outcome": fixture["expected_outcome"],
        "artifact_commitments": {
            "message": _commitment(message), "context": _commitment(context),
            "private_test_key": None, "public_key": _commitment(pub),
            "signature": _commitment(signature)},
    }
    fixture["source_binding"]["case_source_sha256"] = _domain(CASE_DOMAIN, descriptor)
    no_self_digest = dict(fixture)
    no_self_digest.pop("neutral_fixture_sha256")
    fixture["neutral_fixture_sha256"] = _domain(FIXTURE_DOMAIN, no_self_digest)
    return fixture, _legacy_bytes(fixture, pretty=True)
