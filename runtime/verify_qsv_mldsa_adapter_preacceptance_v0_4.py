"""FRESH_G01 selected-six Source-Bound PRE-acceptance (not official).

No filesystem, network, import-time checks or ML-DSA execution. All actual
pinned bytes must arrive unchanged in memory. Caller must separately establish
trustworthy custody for evidence SHA pins. This module cannot certify its own
origin, launch authority, or third-party reproducibility.
"""
import hashlib
import json
import math
import re
from qsv_mldsa_acvp_inmemory_regenerator_v0_1 import (
    PINNED, PROMPT_REL, EXPECTED_REL, SELECTED, SOURCE_REPOSITORY,
    SOURCE_COMMIT, SOURCE_TREE, RegenerationBlocked,
    regenerate_from_verified_bytes,
)

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT40 = re.compile(r"[0-9a-f]{40}\Z")

class PreacceptanceBlocked(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise PreacceptanceBlocked(reason)

def sha(raw):
    require(type(raw) is bytes, "REFERENCE_NOT_IMMUTABLE_BYTES")
    return hashlib.sha256(raw).hexdigest()

def _unique_pairs(pairs):
    out = {}
    for key, value in pairs:
        require(key not in out, "EVIDENCE_DUPLICATE_JSON_KEY")
        out[key] = value
    return out

def _no_constant(_):
    raise PreacceptanceBlocked("EVIDENCE_NON_FINITE_JSON")

def _finite_json_float(token):
    """Use the historical Python float domain; reject exponent overflow to infinity."""
    try:
        value = float(token)
    except (ValueError, OverflowError) as exc:
        raise PreacceptanceBlocked("EVIDENCE_NON_FINITE_JSON") from exc
    require(math.isfinite(value), "EVIDENCE_NON_FINITE_JSON")
    return value

def decode(raw):
    try:
        obj = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=_unique_pairs, parse_constant=_no_constant,
                         parse_float=_finite_json_float)
    except (UnicodeError, ValueError, OverflowError, RecursionError) as exc:
        raise PreacceptanceBlocked("EVIDENCE_JSON_INVALID") from exc
    require(type(obj) is dict, "EVIDENCE_OBJECT_REQUIRED")
    return obj

def _hex64(value):
    return type(value) is str and HEX64.fullmatch(value) is not None

def _pin_raw(authority, name, raw):
    """Raw-byte identity vs explicit EXPECTED authority pin, never self-hash pin."""
    expected = authority.get(name + "_sha256")
    require(_hex64(expected), "REFERENCE_PIN_NOT_ESTABLISHED_" + name.upper())
    require(sha(raw) == expected, "REFERENCE_DIGEST_MISMATCH_" + name.upper())
    return decode(raw)

def _case_identity(case):
    require(type(case) is dict and set(case) ==
            {"case_id", "parameter_set", "tg_id", "tc_id", "expected_valid"},
            "CASE_IDENTITY_FIELDS_INVALID")
    p, tg, tc, ev = (case[k] for k in
                     ("parameter_set", "tg_id", "tc_id", "expected_valid"))
    require(type(p) is str and type(tg) is int and type(tc) is int and
            type(ev) is bool and (p, tg, tc) in SELECTED and SELECTED[(p, tg, tc)] is ev and
            case["case_id"] == f"{p}-tg{tg}-tc{tc}", "CASE_NOT_SELECTED")
    return case

def _historical_case(record, case, fixture_digest):
    require(record.get("schema") == "qsv.mldsa.source-bound-acceptance.v0.2" and
            record.get("record_kind") == "case_acceptance" and
            record.get("source_bound_verification_requested") is True and
            record.get("source_bound_verification_state") == "PASS" and
            record.get("reason_code") == "PASS", "HISTORICAL_SOURCE_BOUND_RECORD_INVALID")
    identity = record.get("case_identity", {})
    require(identity.get("parameter_set") == case["parameter_set"] and
            identity.get("coordinates") == {"tg_id": case["tg_id"], "tc_id": case["tc_id"]} and
            identity.get("expected_valid") is case["expected_valid"],
            "HISTORICAL_CASE_SELECTOR_MISMATCH")
    pin = record.get("source_authority", {})
    require(pin.get("repository") == SOURCE_REPOSITORY and
            pin.get("commit") == SOURCE_COMMIT and pin.get("tree") == SOURCE_TREE,
            "HISTORICAL_SOURCE_AUTHORITY_MISMATCH")
    rows = record.get("source_files", [])
    require(type(rows) is list and len(rows) == 2, "HISTORICAL_SOURCE_ROLE_COUNT")
    required = {"prompt": PROMPT_REL, "expected_results": EXPECTED_REL}
    seen = set()
    for row in rows:
        require(type(row) is dict, "HISTORICAL_SOURCE_ENTRY_INVALID")
        role = row.get("role")
        require(role in required and role not in seen and row.get("path") == required[role] and
                row.get("expected_sha256") == PINNED[role] and
                row.get("observed_sha256") == PINNED[role] and
                row.get("verification_status") == "MATCH", "HISTORICAL_SOURCE_BINDING_MISMATCH")
        seen.add(role)
    require(seen == set(required), "HISTORICAL_SOURCE_DUPLICATE_OR_MISSING")
    regeneration = record.get("regeneration", {})
    require(regeneration.get("performed") is True and
            regeneration.get("run1_equals_run2") is True and
            regeneration.get("regenerated_fixture_match") is True and
            regeneration.get("comparison_mode") == "byte_identical_serialized_file_bytes",
            "HISTORICAL_REGENERATION_INCOMPLETE")
    require(record.get("published_fixture", {}).get("sha256") == fixture_digest,
            "HISTORICAL_FIXTURE_DIGEST_MISMATCH")

# Versioned aggregate-aware compatibility candidate; not approved for execution.
# All historical path/hash pins are separately fixed by the public QSV Git tree;
# this candidate's SHA256 is only identity, never self-authenticating trust.
QSV_PUBLIC_REPOSITORY = "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus"
QSV_PUBLIC_COMMIT = "fa388dee16d829b1a59d7fb62482bbff67f49740"
QSV_PUBLIC_TREE = "2e4bf28cf8cd5b24124cb9d5f1ca15fcc92e98a1"
CANDIDATE_GENERATION = "FRESH_G01_R1_A03_AGGREGATE_V0_4"
AGGREGATE_PATH = "results/qsv_mldsa_f7_normalized_result_evidence_v0_1/qsv_mldsa_f7_normalized_result_evidence_v0_1.json"
AGGREGATE_SHA256 = "fa549e10ec79e0de4f79c516a7eacc5ed937de0a6defde7769efea3dd57e2335"
BINDING_PATH = "manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json"
BINDING_SHA256 = "32620fc0d957c93f78913fd60eb2441ca1201e15121bf0bda5ceda72e88451cd"
CONTRACT_PATH = "contracts/qsv-mldsa-normalized-result-source-binding-contract-v0.1.json"
CONTRACT_SHA256 = "21a6d62111e5dad9d1d7f88f57f3d438f06abfed260ec9aea33aa78ec066d441"
SUCCESSOR_PATH = "manifest/qsv-mldsa-f7-consumer-source-to-runtime-provenance-v0.1-manifest.json"
SUCCESSOR_SHA256 = "5f9fcd753abe51c73c78aa851b8b4e14a6717355fcd8fa5fb412d794fb22c299"
LINEAGE_PATH = "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json"
LINEAGE_SHA256 = "bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289"
ADAPTER_PATH = "runtime/qsv_mldsa_normalized_result_adapter_v0_1.py"
ADAPTER_SHA256 = "5a9adeeb92eef28abd5f3d5a6be516f886c7f8b8b656dfbddfb83e66ed9655e8"
# S02: Historical runtime capture is a second pinned artifact, not a synthesized pin.
RUNTIME_EVIDENCE_PATH = "results/qsv_mldsa_f7_runtime_invocation_evidence_v0_1/qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json"
RUNTIME_EVIDENCE_SHA256 = "0a5f8da64736deab407e76a35db40a5badff9018f1c1e8f5c49f1cfeba5d42b0"
FIXTURE_DERIVATION_AUTHORITY = r"qsv-f7- + first24(sha256('qsv-f7-fixture-v0.2\n' + runtime_manifest_sha256 + '\n' + case_id + '\n')))"
CONSUMER_SHARED_FIELDS = frozenset((
    "adapter_identity", "lineage", "repository", "runtime_identity",
    "source_identity", "source_to_runtime_binding",
))
CONSUMER_MANIFEST_ONLY_FIELDS = frozenset(("identity_basis", "implementation_id"))
MAX_HISTORICAL_JSON_BYTES = 1_000_000
MAX_JSON_DEPTH = 64
IMPLEMENTATIONS = ("openssl", "cloudflare-circl")
CONSUMER_PATHS = {
    "openssl": "manifest/qsv-mldsa-f7-consumer-identity-openssl-v0.1.json",
    "cloudflare-circl": "manifest/qsv-mldsa-f7-consumer-identity-cloudflare-circl-v0.1.json",
}
REPOSITORIES = {
    "openssl": "https://github.com/openssl/openssl.git",
    "cloudflare-circl": "https://github.com/cloudflare/circl.git",
}

def _bounded_json(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_HISTORICAL_JSON_BYTES,
            "HISTORICAL_JSON_BYTES_INVALID")
    obj = decode(raw)  # strict UTF-8, duplicate-key and nonfinite rejection
    def inspect(value, depth):
        require(depth <= MAX_JSON_DEPTH, "HISTORICAL_JSON_DEPTH_EXCEEDED")
        if type(value) is dict:
            for k, v in value.items():
                require(type(k) is str, "HISTORICAL_JSON_KEY_INVALID")
                inspect(v, depth + 1)
        elif type(value) is list:
            require(len(value) <= 512, "HISTORICAL_JSON_ARRAY_TOO_LARGE")
            for v in value:
                inspect(v, depth + 1)
        else:
            require(type(value) in (str, int, float, bool, type(None)),
                    "HISTORICAL_JSON_TYPE_INVALID")
            if type(value) is float:
                require(math.isfinite(value), "EVIDENCE_NON_FINITE_JSON")
    inspect(obj, 0)
    return obj

def _fixed_raw(authority, path, fixed_sha):
    objects = authority.get("historical_raw_by_path")
    require(type(objects) is dict and path in objects and
            type(path) is str and not path.startswith("/") and
            ".." not in path.split("/"), "FIXED_AUTHORITY_PATH_MISSING")
    raw = objects[path]
    require(type(raw) is bytes and len(raw) <= MAX_HISTORICAL_JSON_BYTES,
            "FIXED_AUTHORITY_RAW_BYTES_MISSING")
    require(sha(raw) == fixed_sha, "FIXED_HISTORICAL_RAW_DIGEST_MISMATCH")
    return raw

def _selector(implementation, case):
    require(implementation in IMPLEMENTATIONS and type(case) is dict,
            "NORMALIZED_SELECTOR_INVALID")
    require(set(case) >= {"case_id", "parameter_set", "tg_id", "tc_id", "expected_valid"},
            "NORMALIZED_SELECTOR_FIELDS_MISSING")
    require(type(case["case_id"]) is str and type(case["parameter_set"]) is str and
            type(case["tg_id"]) is int and type(case["tc_id"]) is int and
            type(case["expected_valid"]) is bool, "NORMALIZED_SELECTOR_TYPES_INVALID")
    return (implementation, case["case_id"], case["parameter_set"],
            case["tg_id"], case["tc_id"], case["expected_valid"])

def _historical_selector_and_digest(record, bound):
    require(type(record) is dict and type(bound) is dict,
            "HISTORICAL_RECORD_OR_BINDING_INVALID")
    rec_case = record.get("inputs", {}).get("case", {})
    require(type(rec_case) is dict and type(rec_case.get("source_expected_valid")) is bool,
            "HISTORICAL_CASE_INPUT_MISSING")
    selector_case = {
        "case_id": rec_case.get("case_id"),
        "parameter_set": rec_case.get("parameter_set"),
        "tg_id": rec_case.get("tg_id"), "tc_id": rec_case.get("tc_id"),
        "expected_valid": rec_case["source_expected_valid"],
    }
    key = _selector(record.get("implementation"), selector_case)
    bind_case = bound.get("case_identity", {})
    bind_key = _selector(bound.get("implementation_id"), bind_case)
    require(key == bind_key and bound.get("normalized_record", {}).get("selector") ==
            dict(implementation_id=key[0], case_id=key[1], parameter_set=key[2],
                 tg_id=key[3], tc_id=key[4], expected_valid=key[5]),
            "HISTORICAL_NORMALIZED_SELECTOR_MISMATCH")
    require((key[2], key[3], key[4]) in SELECTED and
            SELECTED[(key[2], key[3], key[4])] is key[5],
            "HISTORICAL_SELECTOR_NOT_SELECTED")
    normalized = bound["normalized_record"]
    require(type(record.get("observed_acceptance")) is bool and
            record["observed_acceptance"] is key[5] and
            record["observed_acceptance"] is normalized.get("observed_acceptance") and
            record.get("result_state") == normalized.get("result_state") and
            type(record.get("fixture_id")) is str and bool(record["fixture_id"]),
            "HISTORICAL_RESULT_IDENTITY_MISMATCH")
    executable = record.get("artifact_hashes", {}).get("resolved_executable_sha256")
    require(_hex64(executable) and executable == normalized.get("resolved_executable_sha256"),
            "HISTORICAL_EXECUTABLE_DIGEST_MISMATCH")
    try:
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise PreacceptanceBlocked("HISTORICAL_CANONICALIZATION_FAILED") from exc
    digest = sha(canonical)
    require(digest == normalized.get("canonical_sha256") and _hex64(digest),
            "HISTORICAL_CANONICAL_DIGEST_MISMATCH")
    return key, digest

def _historical_fixture_binding(record, invocation, runtime_manifest_sha256):
    """S02: tie F7 fixture_id to the pinned historical formula and runtime capture.

    This is distinct from any NIST-neutral published-fixture regeneration identity.
    The manifest digest is the pinned Historical Aggregate's declared digest;
    it does NOT prove independent reconstruction of that runtime manifest.
    """
    require(type(invocation) is dict, "HISTORICAL_INVOCATION_SELECTOR_MISSING")
    inputs = record.get("inputs", {}).get("case", {})
    hashes = record.get("artifact_hashes", {})
    case_id = inputs.get("case_id")
    require(type(case_id) is str and _hex64(runtime_manifest_sha256) and
            hashes.get("runtime_manifest_sha256") == runtime_manifest_sha256,
            "HISTORICAL_RUNTIME_MANIFEST_REFERENCE_MISMATCH")
    expected_fixture_id = "qsv-f7-" + hashlib.sha256(
        b"qsv-f7-fixture-v0.2\n" + runtime_manifest_sha256.encode("ascii") +
        b"\n" + case_id.encode("utf-8") + b"\n"
    ).hexdigest()[:24]
    require(record.get("fixture_id") == expected_fixture_id,
            "HISTORICAL_FIXTURE_ID_DERIVATION_MISMATCH")
    scope = invocation.get("execution_scope", {})
    require(type(scope) is dict and scope.get("case_id") == case_id and
            scope.get("parameter_set") == inputs.get("parameter_set") and
            type(scope.get("tg_id")) is int and scope.get("tg_id") == inputs.get("tg_id") and
            type(scope.get("tc_id")) is int and scope.get("tc_id") == inputs.get("tc_id") and
            type(scope.get("expected_valid")) is bool and
            scope.get("expected_valid") is inputs.get("source_expected_valid") and
            invocation.get("implementation") == record.get("implementation") and
            invocation.get("resolved_executable_sha256") == hashes.get("resolved_executable_sha256") and
            invocation.get("exact_command") == record.get("exact_command") and
            invocation.get("stdout_sha256") == record.get("output", {}).get("stdout_sha256") and
            invocation.get("stderr_sha256") == record.get("output", {}).get("stderr_sha256") and
            type(invocation.get("exit_code")) is int and
            invocation.get("exit_code") == record.get("exit_status", {}).get("code"),
            "HISTORICAL_FIXTURE_RUNTIME_INVOCATION_MISMATCH")

def _normalized_and_consumer(authority, case, raw_normalized, raw_binding,
                             raw_provenance, implementation):
    # Trust pins are *fixed* QSV public-commit raw identities, not supplied by the
    # same caller as newly serialized, derived, or projected JSON bytes.
    require(authority.get("historical_repository") == QSV_PUBLIC_REPOSITORY and
            authority.get("historical_commit") == QSV_PUBLIC_COMMIT and
            authority.get("historical_tree") == QSV_PUBLIC_TREE,
            "QSV_PINNED_PUBLIC_TREE_NOT_ESTABLISHED")
    require(type(raw_normalized) is bytes and sha(raw_normalized) == AGGREGATE_SHA256 and
            type(raw_binding) is bytes and sha(raw_binding) == BINDING_SHA256 and
            type(raw_provenance) is bytes and sha(raw_provenance) == SUCCESSOR_SHA256,
            "HISTORICAL_PRIMARY_RAW_PIN_MISMATCH")
    # E02: caller path must match the same pinned QSV Historical Aggregate.
    # Raw digest does not by itself authenticate the caller's path string.
    require(authority.get("normalized_result_path") == AGGREGATE_PATH,
            "HISTORICAL_AGGREGATE_PATH_NOT_PINNED")
    require(raw_normalized == _fixed_raw(authority, AGGREGATE_PATH, AGGREGATE_SHA256) and
            raw_binding == _fixed_raw(authority, BINDING_PATH, BINDING_SHA256) and
            raw_provenance == _fixed_raw(authority, SUCCESSOR_PATH, SUCCESSOR_SHA256),
            "HISTORICAL_RAW_VIEW_MISMATCH")
    aggregate, binding, successor = (_bounded_json(raw_normalized),
                                     _bounded_json(raw_binding),
                                     _bounded_json(raw_provenance))
    contract = _bounded_json(_fixed_raw(authority, CONTRACT_PATH, CONTRACT_SHA256))
    require(contract.get("join", {}).get("record_canonicalization") ==
            "utf8-json-sort-keys-true-separators-comma-colon-ensure-ascii-false" and
            contract.get("scope", {}).get("normalized_result_path") == AGGREGATE_PATH and
            contract["scope"].get("normalized_result_sha256") == AGGREGATE_SHA256 and
            binding.get("contract_binding") == {"path": CONTRACT_PATH,
                "sha256": CONTRACT_SHA256} and
            binding.get("historical_normalized_result", {}).get("sha256") == AGGREGATE_SHA256,
            "HISTORICAL_CANONICAL_CONTRACT_NOT_FIXED")
    records, bindings = aggregate.get("records"), binding.get("bindings")
    require(type(records) is list and type(bindings) is list and
            len(records) == len(bindings) == 12,
            "HISTORICAL_TWELVE_RECORD_SET_REQUIRED")
    expected = {(impl, f"{p}-tg{tg}-tc{tc}", p, tg, tc, ev)
                for impl in IMPLEMENTATIONS for (p, tg, tc), ev in SELECTED.items()}
    # S02: a separately pinned Historical Runtime Evidence artifact corroborates
    # the record's case, implementation, command, executable, and output.
    source_authority = aggregate.get("source_authority", {})
    normalize_authority = aggregate.get("normalization_authority", {})
    require(type(source_authority) is dict and type(normalize_authority) is dict and
            normalize_authority.get("fixture_id_derivation") == FIXTURE_DERIVATION_AUTHORITY and
            source_authority.get("bound_runtime_evidence_path") == RUNTIME_EVIDENCE_PATH and
            source_authority.get("bound_runtime_evidence_sha256") == RUNTIME_EVIDENCE_SHA256 and
            binding.get("historical_runtime_evidence") ==
            {"path": RUNTIME_EVIDENCE_PATH, "sha256": RUNTIME_EVIDENCE_SHA256} and
            _hex64(source_authority.get("runtime_manifest_sha256")),
            "HISTORICAL_FIXTURE_AUTHORITY_NOT_ESTABLISHED")
    runtime_capture = _bounded_json(_fixed_raw(
        authority, RUNTIME_EVIDENCE_PATH, RUNTIME_EVIDENCE_SHA256))
    invocation_rows = runtime_capture.get("invocations")
    require(type(invocation_rows) is list and len(invocation_rows) == 12,
            "HISTORICAL_RUNTIME_INVOCATIONS_INVALID")
    runtime_by_key = {}
    for invocation in invocation_rows:
        require(type(invocation) is dict and
                type(invocation.get("execution_scope")) is dict,
                "HISTORICAL_RUNTIME_INVOCATION_INVALID")
        invocation_case = invocation["execution_scope"]
        key = (invocation.get("implementation"), invocation_case.get("case_id"))
        require(key not in runtime_by_key and key[0] in IMPLEMENTATIONS and
                type(key[1]) is str,
                "HISTORICAL_RUNTIME_SELECTOR_DUPLICATE_OR_UNKNOWN")
        runtime_by_key[key] = invocation
    require(set(runtime_by_key) == {(key[0], key[1]) for key in expected},
            "HISTORICAL_RUNTIME_SELECTOR_SET_MISMATCH")
    records_by_key = {}
    bindings_by_key = {}
    for row in bindings:
        require(type(row) is dict, "HISTORICAL_BINDING_OBJECT_REQUIRED")
        key = _selector(row.get("implementation_id"), row.get("case_identity", {}))
        require(key not in bindings_by_key, "HISTORICAL_DUPLICATE_BINDING_SELECTOR")
        bindings_by_key[key] = row
    for record in records:
        require(type(record) is dict, "HISTORICAL_RECORD_OBJECT_REQUIRED")
        c = record.get("inputs", {}).get("case", {})
        require(type(c) is dict and type(c.get("source_expected_valid")) is bool,
                "HISTORICAL_RECORD_CASE_INVALID")
        key = _selector(record.get("implementation"), dict(
            case_id=c.get("case_id"), parameter_set=c.get("parameter_set"),
            tg_id=c.get("tg_id"), tc_id=c.get("tc_id"),
            expected_valid=c["source_expected_valid"]))
        require(key not in records_by_key and key in bindings_by_key,
                "HISTORICAL_DUPLICATE_OR_UNBOUND_RECORD")
        _historical_selector_and_digest(record, bindings_by_key[key])
        _historical_fixture_binding(record, runtime_by_key[(key[0], key[1])],
                                    source_authority["runtime_manifest_sha256"])
        records_by_key[key] = record
    require(set(records_by_key) == set(bindings_by_key) == expected,
            "HISTORICAL_SELECTOR_SET_MISMATCH")
    target_key = _selector(implementation, case)
    require(target_key in records_by_key, "HISTORICAL_SELECTION_NOT_UNIQUE")
    record, bound = records_by_key[target_key], bindings_by_key[target_key]
    _, canonical_digest = _historical_selector_and_digest(record, bound)
    source_case = bound.get("source_bound_case", {})
    require(source_case.get("state") == "PASS" and
            source_case.get("path") == authority.get("historical_case_record_path") and
            source_case.get("sha256") == sha(authority.get("historical_case_record_bytes")),
            "HISTORICAL_SOURCE_BOUND_CASE_RAW_MISMATCH")
    snapshot = bound.get("consumer_snapshot", {})
    require(type(snapshot) is dict and
            snapshot.get("source_to_runtime_binding", {}).get("status") == "incomplete",
            "HISTORICAL_SOURCE_TO_RUNTIME_PROMOTION_FORBIDDEN")
    consumer_ref = bound.get("consumer_authority", {})
    require(consumer_ref.get("path") == CONSUMER_PATHS[implementation] and
            _hex64(consumer_ref.get("sha256")), "HISTORICAL_CONSUMER_REFERENCE_INVALID")
    consumer_raw = _fixed_raw(authority, consumer_ref["path"], consumer_ref["sha256"])
    consumer = _bounded_json(consumer_raw).get("consumer")
    # S01: Historical manifest has six shared fields plus two authenticated
    # manifest-only fields. Never equate the 8-field manifest with a 6-field view.
    require(type(consumer) is dict and set(consumer) ==
            CONSUMER_SHARED_FIELDS | CONSUMER_MANIFEST_ONLY_FIELDS and
            set(snapshot) == CONSUMER_SHARED_FIELDS,
            "HISTORICAL_CONSUMER_FIELD_PROFILE_MISMATCH")
    require(all(consumer[field] == snapshot[field]
                for field in CONSUMER_SHARED_FIELDS),
            "HISTORICAL_CONSUMER_SHARED_FIELDS_MISMATCH")
    require(type(consumer.get("identity_basis")) is str and
            consumer["identity_basis"] == "runtime_version_and_source_commit" and
            type(consumer.get("implementation_id")) is str and
            consumer["implementation_id"] == implementation,
            "HISTORICAL_CONSUMER_MANIFEST_ONLY_IDENTITY_MISMATCH")
    lineage_ref = snapshot.get("lineage", {})
    require(lineage_ref.get("binding_path") == LINEAGE_PATH and
            lineage_ref.get("binding_sha256") == LINEAGE_SHA256,
            "HISTORICAL_LINEAGE_REFERENCE_INVALID")
    lineage = _bounded_json(_fixed_raw(authority, LINEAGE_PATH, LINEAGE_SHA256))
    require(type(lineage.get("implementations")) is dict and
            implementation.replace("-", "_") in lineage["implementations"],
            "HISTORICAL_LINEAGE_IMPLEMENTATION_MISSING")
    adapter = snapshot.get("adapter_identity", {})
    require(adapter.get("path") == ADAPTER_PATH and
            adapter.get("sha256") == ADAPTER_SHA256,
            "HISTORICAL_ADAPTER_REFERENCE_MISMATCH")
    _fixed_raw(authority, ADAPTER_PATH, ADAPTER_SHA256)
    source = snapshot.get("source_identity", {})
    runtime = snapshot.get("runtime_identity", {})
    require(snapshot.get("repository") == REPOSITORIES[implementation] and
            type(source.get("commit")) is str and
            COMMIT40.fullmatch(source["commit"]) is not None and
            type(source.get("tree")) is str and
            COMMIT40.fullmatch(source["tree"]) is not None and
            runtime.get("executable_sha256") == record["artifact_hashes"]["resolved_executable_sha256"],
            "HISTORICAL_SOURCE_OR_RUNTIME_IDENTITY_MISMATCH")
    lineage_impl = lineage["implementations"][implementation.replace("-", "_")]
    if implementation == "openssl":
        upstream = lineage_impl.get("upstream_release", {})
        require(upstream.get("source_commit") == source["commit"] and
                upstream.get("source_tree") == source["tree"],
                "HISTORICAL_OPENSSL_LINEAGE_MISMATCH")
    else:
        require(lineage_impl.get("source_commit") == source["commit"] and
                lineage_impl.get("source_tree") == source["tree"],
                "HISTORICAL_CIRCL_LINEAGE_MISMATCH")
    require(successor.get("authority_role") ==
            "APPEND_ONLY_HISTORICAL_BUILD_EVENT_PROVENANCE_AUTHORITY" and
            successor.get("claim_boundary", {}).get("independent_reproducible_build_proven") is False,
            "HISTORICAL_PROVENANCE_CLAIM_BOUNDARY_MISMATCH")
    successor_rows = successor.get("consumers")
    require(type(successor_rows) is list and len(successor_rows) == 2,
            "HISTORICAL_PROVENANCE_CONSUMERS_INVALID")
    successor_matches = [r for r in successor_rows if type(r) is dict and
                         r.get("implementation_id") == implementation]
    require(len(successor_matches) == 1,
            "HISTORICAL_PROVENANCE_SELECTOR_INVALID")
    successor_consumer = successor_matches[0]
    require(successor_consumer.get("consumer_authority") == consumer_ref and
            successor_consumer.get("source_identity", {}).get("commit") == source["commit"] and
            successor_consumer.get("source_identity", {}).get("tree") == source["tree"] and
            successor_consumer.get("runtime_identity", {}).get("executable_sha256") ==
                runtime["executable_sha256"] and
            successor_consumer.get("source_to_runtime_provenance", {}).get("independent_rebuild_proven") is False,
            "HISTORICAL_SUCCESSOR_CONSUMER_MISMATCH")
    bound_snapshot = bound["consumer_snapshot"]
    require(bound_snapshot.get("runtime_identity", {}).get("executable_sha256") ==
            bound["normalized_record"].get("resolved_executable_sha256"),
            "HISTORICAL_EXECUTABLE_BINDING_MISMATCH")
    trace = {
        "aggregate_path": AGGREGATE_PATH, "aggregate_raw_sha256": AGGREGATE_SHA256,
        "canonical_record_sha256": canonical_digest,
        "contract_path": CONTRACT_PATH, "contract_raw_sha256": CONTRACT_SHA256,
        "case_id": case["case_id"], "implementation_id": implementation,
        "source_bound_case_sha256": source_case["sha256"],
    }
    result = {"implementation_id": implementation,
              "repository": snapshot["repository"], "source_commit": source["commit"],
              "runtime_sha256": runtime["executable_sha256"],
              "lineage_sha256": lineage_ref["binding_sha256"],
              "adapter_sha256": adapter["sha256"],
              "historical_source_to_runtime_status": "incomplete",
              "successor_provenance_manifest": {"path": SUCCESSOR_PATH,
                                                 "sha256": SUCCESSOR_SHA256}}
    return result, trace

def verify_preacceptance(request, verified_sources, authority):
    """Require exact bytes, regeneration and independent authority joins.

    request: dict with case_identity, implementation_id, acceptance_mode,
      source_bound_requested and unique case_bindings if aggregate is supplied.
    verified_sources: exactly {prompt: bytes, expected_results: bytes}.
    authority: externally supplied raw evidence plus separately fixed digest pins.
    No caller dictionary is a verified trust root without external custody.
    """
    require(type(request) is dict and type(verified_sources) is dict and
            type(authority) is dict, "INPUT_OBJECTS_REQUIRED")
    require(request.get("acceptance_mode") == "source_bound" and
            request.get("source_bound_requested") is True, "METADATA_ONLY_NOT_ACCEPTED")
    require(set(verified_sources) == {"prompt", "expected_results"},
            "EXACT_TWO_SOURCE_ROLES_REQUIRED")
    case = _case_identity(request.get("case_identity"))
    implementation = request.get("implementation_id")
    require(type(implementation) is str, "CONSUMER_IMPLEMENTATION_MISSING")
    aggregate = request.get("case_bindings")
    if aggregate is not None:
        require(type(aggregate) is list and len(aggregate) == len(set(aggregate)) and
                case["case_id"] in aggregate, "DUPLICATE_CASE_MAPPING")
    require(authority.get("source_repository") == SOURCE_REPOSITORY and
            authority.get("source_commit") == SOURCE_COMMIT and
            authority.get("source_tree") == SOURCE_TREE and
            authority.get("source_paths") == {"prompt": PROMPT_REL,
                                             "expected_results": EXPECTED_REL},
            "PINNED_SOURCE_AUTHORITY_MISMATCH")
    source_rows = []
    for role, path in (("prompt", PROMPT_REL), ("expected_results", EXPECTED_REL)):
        observed = sha(verified_sources[role])
        require(observed == PINNED[role], "PINNED_SOURCE_DIGEST_MISMATCH")
        source_rows.append({"role": role, "path": path, "expected_sha256": PINNED[role],
                            "observed_sha256": observed, "consumed_sha256": observed,
                            "digest_match": True})
    published = authority.get("published_fixture_bytes")
    fixture_pin = authority.get("published_fixture_sha256")
    require(_hex64(fixture_pin) and sha(published) == fixture_pin,
            "PUBLISHED_FIXTURE_REFERENCE_MISMATCH")
    try:
        _, first = regenerate_from_verified_bytes(
            verified_sources["prompt"], verified_sources["expected_results"], case, authority)
        _, second = regenerate_from_verified_bytes(
            verified_sources["prompt"], verified_sources["expected_results"], case, authority)
    except RegenerationBlocked as exc:
        raise PreacceptanceBlocked("SOURCE_REGENERATION_BLOCKED:" + str(exc)) from exc
    require(first == second, "DOUBLE_REGENERATION_MISMATCH")
    require(first == published, "PUBLISHED_FIXTURE_BYTE_MISMATCH")
    case_record_bytes = authority.get("historical_case_record_bytes")
    case_record = _pin_raw(authority, "historical_case_record", case_record_bytes)
    _historical_case(case_record, case, sha(published))
    normalized_record = authority.get("normalized_result_bytes")
    binding_bytes = authority.get("normalized_binding_manifest_bytes")
    provenance_bytes = authority.get("successor_provenance_manifest_bytes")
    consumer, historical_trace = _normalized_and_consumer(authority, case, normalized_record,
                                         binding_bytes, provenance_bytes, implementation)
    envelope = {
        "schema": "qsv.mldsa.adapter.preacceptance.envelope.v0.4",
        "generation": CANDIDATE_GENERATION, "decision": "PREACCEPTANCE_PASS",
        "acceptance_mode": "source_bound", "case_identity": dict(case),
        "source_authority": {"repository": SOURCE_REPOSITORY,
                             "commit": SOURCE_COMMIT, "tree": SOURCE_TREE},
        "source_files": source_rows,
        "source_regeneration": {"requested": True, "performed": True,
                                  "status": "PASS", "reason": "PASS", "first_run_digest": sha(first),
                                 "second_run_digest": sha(second),
                                 "runs_byte_identical": True,
                                 "published_fixture_byte_match": True,
                                 "same_verified_bytes_consumed": True},
        "published_fixture": {"path": authority.get("published_fixture_path", ""),
                              "sha256": sha(published)},
        "historical_case_binding": {"path": authority.get("historical_case_record_path", ""),
                                    "sha256": sha(case_record_bytes)},
        "normalized_binding": {
            "manifest": {"path": "manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json",
                         "sha256": sha(binding_bytes)},
            "normalized_record": {"path": AGGREGATE_PATH,
                                  "sha256": sha(normalized_record)},
            "case_id": case["case_id"], "implementation_id": implementation,
            "historical_record_canonical_sha256": historical_trace["canonical_record_sha256"]},
        "normalized_result_source_binding": {
            "normalized_raw_sha256": sha(normalized_record),
            "historical_canonical_sha256": historical_trace["canonical_record_sha256"],
            "historical_contract_raw_sha256": CONTRACT_SHA256,
            "case_id": case["case_id"], "implementation_id": implementation,
            "source_regeneration_performed": True,
            "same_verified_bytes_consumed": True,
            "pinned_source_digests": {role: sha(verified_sources[role])
                                      for role in ("prompt", "expected_results")},
        },
        "consumer_binding": consumer,
        "historical_normalized_authority": historical_trace,
        "verification_event": {"status": "PREACCEPTANCE_PASS", "official_acceptance": False,
                               "source_bound_requested": True,
                               "raw_evidence_digest": sha(case_record_bytes)}
    }
    require(all(envelope[key]["path"] for key in
                ("published_fixture", "historical_case_binding")) and
            bool(envelope["normalized_binding"]["normalized_record"]["path"]),
            "EVIDENCE_PATH_AUTHORITY_MISSING")
    return envelope
