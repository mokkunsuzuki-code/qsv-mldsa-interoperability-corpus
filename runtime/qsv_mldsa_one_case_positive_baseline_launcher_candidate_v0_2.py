"""QSP/QSV L01 v0.2 SOURCE-ONLY candidate (not runtime-authorized).

No import-time work; fixed public authority pins are compiled into this candidate,
not learned from caller-provided digests. Source verification is NOT an approval.
This tool performs no cryptographic ML-DSA, no networking and no writes.
Run functions only in a separately explicitly authorized, isolated runtime.
"""
import hashlib
import json
import math

CANDIDATE_ID = "QSV_L01_V0_2_EXACT_RAW_HANDOFF"
IMPLEMENTATION = "openssl"
CASE = {"case_id":"ML-DSA-44-tg1-tc1", "parameter_set":"ML-DSA-44",
        "tg_id":1,"tc_id":1,"expected_valid":False}
HISTORICAL_RESULT_STATE = "expected_reject"  # Not preacceptance rejection.
F7_FIXTURE_ID = "qsv-f7-9c8f81446b91d2602a4b0e31"
SOURCE_REPO = "https://github.com/usnistgov/ACVP-Server.git"
SOURCE_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
SOURCE_TREE = "a6b81add7faf8a8b647afcdc54268615decde9b5"
HISTORICAL_REPO = "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus"
HISTORICAL_COMMIT = "fa388dee16d829b1a59d7fb62482bbff67f49740"
HISTORICAL_TREE = "2e4bf28cf8cd5b24124cb9d5f1ca15fcc92e98a1"
NEUTRAL_CONTRACT = "contracts/qsv-mldsa-neutral-fixture-canonicalization-contract-v0.1.json"
COVERAGE = "manifest/qsv-mldsa-f7-sixcase-neutral-fixture-coverage-v0.1-manifest.json"
FIXTURE = "examples/qsv-mldsa-acvp-negative-canonical-v0.3.json"
CASE_RECORD = "results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa44_tg1_tc1_v0_1.json"
AGGREGATE = "results/qsv_mldsa_f7_normalized_result_evidence_v0_1/qsv_mldsa_f7_normalized_result_evidence_v0_1.json"
BINDING = "manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json"
CONTRACT = "contracts/qsv-mldsa-normalized-result-source-binding-contract-v0.1.json"
CONSUMER = "manifest/qsv-mldsa-f7-consumer-identity-openssl-v0.1.json"
SUCCESSOR = "manifest/qsv-mldsa-f7-consumer-source-to-runtime-provenance-v0.1-manifest.json"
LINEAGE = "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json"
ADAPTER = "runtime/qsv_mldsa_normalized_result_adapter_v0_1.py"
RUNTIME_INVOCATION = "results/qsv_mldsa_f7_runtime_invocation_evidence_v0_1/qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json"
PROMPT = "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json"
EXPECTED = "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json"
V04_A03 = "runtime/verify_qsv_mldsa_adapter_preacceptance_v0_4.py"
V04_A01 = "contracts/qsv-mldsa-adapter-preacceptance-contract-v0.4.json"
V04_A02 = "schemas/qsv-mldsa-adapter-preacceptance-envelope-v0.4.schema.json"
A04 = "runtime/qsv_mldsa_acvp_inmemory_regenerator_v0_1.py"

# Expected digests fixed separately by pinned public source and audited candidate identities.
# Never populate or overwrite this table from candidate input or A03 outputs.
PINNED = {
 "source/"+V04_A03: "8800ddc0779f2f31c15ec167c4e3fbc37afc6502bf2d8687665aa31872ecc0c5",
 "source/"+V04_A01: "0d871b2101046fe791abce15269a4d0de405c8cdf0312822fcc24fdb952c5ed0",
 "source/"+V04_A02: "cb706c192c7ad6dd688b90d4a8fa9c9113b6fb580596775dd5b002e8e2f490bb",
 "source/"+A04: "665425e8237c6d76a8e3028a9c6d9d581e2c42552435c49bd20be476a1d7c10c",
 "nist/"+PROMPT: "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
 "nist/"+EXPECTED: "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
 "qsv/"+NEUTRAL_CONTRACT: "74be71c4332f389c03c6032251f6b2df94a1b4b6aff8a7216dd6d5651f0b9e4e",
 "qsv/"+COVERAGE: "1d88dbc902e5ed568b06fd9e8e001fc61afb3c8b514e70e540db289a47b9b23a",
 "qsv/"+FIXTURE: "11c9d28a211d1545bd0ba9b83da4ce101fb6be0bcf815063d7af905962825602",
 "qsv/"+CASE_RECORD: "b0f8d9025b5db0f167398a120e66f719c2a4e67cdb5785a8f23961f4e39dc967",
 "qsv/"+AGGREGATE: "fa549e10ec79e0de4f79c516a7eacc5ed937de0a6defde7769efea3dd57e2335",
 "qsv/"+BINDING: "32620fc0d957c93f78913fd60eb2441ca1201e15121bf0bda5ceda72e88451cd",
 "qsv/"+CONTRACT: "21a6d62111e5dad9d1d7f88f57f3d438f06abfed260ec9aea33aa78ec066d441",
 "qsv/"+CONSUMER: "20a5adb3b789051fafcb65423ec7219a25ae6462574bd29245de598d9b39889d",
 "qsv/"+SUCCESSOR: "5f9fcd753abe51c73c78aa851b8b4e14a6717355fcd8fa5fb412d794fb22c299",
 "qsv/"+LINEAGE: "bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289",
 "qsv/"+ADAPTER: "5a9adeeb92eef28abd5f3d5a6be516f886c7f8b8b656dfbddfb83e66ed9655e8",
 "qsv/"+RUNTIME_INVOCATION: "0a5f8da64736deab407e76a35db40a5badff9018f1c1e8f5c49f1cfeba5d42b0",
}
SELECTED_CANONICAL = "920c71cbcf752c1b954536d2a1e2b1a331e41a97c5d00f42146dfb4ae528ac30"
SELECTED_EXECUTABLE = "07978755211bffcfe57f28ce6354292245a3a0af08d247c617c3f36378aa6b93"

class CandidateBlocked(ValueError):
    """Fail-closed preparation or observation failure; not an official acceptance."""

def demand(ok, reason):
    if not ok:
        raise CandidateBlocked(reason)

def h(raw):
    demand(type(raw) is bytes, "RAW_BYTES_REQUIRED")
    return hashlib.sha256(raw).hexdigest()

def no_duplicates(pairs):
    d = {}
    for k, v in pairs:
        demand(k not in d, "DUPLICATE_JSON_KEY")
        d[k] = v
    return d

def reject_constant(_):
    raise CandidateBlocked("NONSTANDARD_JSON_CONSTANT")

def finite_float(text):
    x = float(text)
    demand(math.isfinite(x), "NONFINITE_JSON_NUMBER")
    return x

def parse_json(raw):
    demand(type(raw) is bytes and len(raw) <= 4_000_000, "JSON_RAW_TOO_LARGE_OR_INVALID")
    try:
        obj = json.loads(raw.decode("utf-8", "strict"),
                         object_pairs_hook=no_duplicates, parse_constant=reject_constant,
                         parse_float=finite_float)
    except (UnicodeError, ValueError, TypeError, OverflowError) as exc:
        raise CandidateBlocked("STRICT_JSON_DECODE_FAILED") from exc
    demand(type(obj) is dict, "JSON_OBJECT_REQUIRED")
    return obj

def validate_raw_snapshot(raw_by_path):
    """Exact 18-key immutable snapshot; no filesystem reads/writes or self-pinning."""
    demand(type(raw_by_path) is dict and set(raw_by_path) == set(PINNED),
           "SOURCE_AND_HISTORICAL_PATH_SET_MISMATCH")
    for path, expected in PINNED.items():
        raw = raw_by_path[path]
        demand(type(raw) is bytes and len(raw) <= 4_000_000,
               "RAW_TYPE_OR_SIZE_INVALID:" + path)
        demand(h(raw) == expected, "PINNED_RAW_DIGEST_MISMATCH:" + path)
    return True

def selected_record_and_binding(raw_by_path):
    aggregate = parse_json(raw_by_path["qsv/"+AGGREGATE])
    bound = parse_json(raw_by_path["qsv/"+BINDING])
    contract = parse_json(raw_by_path["qsv/"+CONTRACT])
    demand(contract.get("join",{}).get("record_canonicalization") ==
           "utf8-json-sort-keys-true-separators-comma-colon-ensure-ascii-false",
           "HISTORICAL_CANONICAL_PROFILE_MISMATCH")
    rows, links = aggregate.get("records"), bound.get("bindings")
    demand(type(rows) is list and type(links) is list and len(rows)==len(links)==12,
           "HISTORICAL_RECORD_COUNT_NOT_TWELVE")
    rmatch = [r for r in rows if type(r) is dict and r.get("implementation") == IMPLEMENTATION
              and r.get("inputs",{}).get("case",{}).get("case_id") == CASE["case_id"]]
    bmatch = [b for b in links if type(b) is dict and b.get("implementation_id") == IMPLEMENTATION
              and b.get("case_identity",{}).get("case_id") == CASE["case_id"]]
    demand(len(rmatch) == len(bmatch) == 1, "NON_UNIQUE_HISTORICAL_SELECTOR")
    r, b = rmatch[0], bmatch[0]
    rc=r["inputs"]["case"]
    demand((rc.get("parameter_set"),rc.get("tg_id"),rc.get("tc_id"),
            rc.get("source_expected_valid")) ==
           (CASE["parameter_set"],CASE["tg_id"],CASE["tc_id"],CASE["expected_valid"]),
           "HISTORICAL_CASE_COORDINATES_MISMATCH")
    demand(b.get("case_identity") == CASE and
           b.get("normalized_record",{}).get("selector") ==
           dict(implementation_id=IMPLEMENTATION,**CASE), "BINDING_SELECTOR_MISMATCH")
    canon=json.dumps(r,sort_keys=True,separators=(",",":"),ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    demand(h(canon)==SELECTED_CANONICAL==b["normalized_record"]["canonical_sha256"],
           "HISTORICAL_CANONICAL_DIGEST_MISMATCH")
    demand(r.get("result_state") == HISTORICAL_RESULT_STATE and
           r.get("observed_acceptance") is False and
           r.get("fixture_id") == F7_FIXTURE_ID and
           r.get("artifact_hashes",{}).get("resolved_executable_sha256") == SELECTED_EXECUTABLE,
           "HISTORICAL_RESULT_OR_EXECUTABLE_MISMATCH")
    demand(b.get("source_bound_case") ==
           {"path":CASE_RECORD,"sha256":PINNED["qsv/"+CASE_RECORD],"state":"PASS"},
           "HISTORICAL_CASE_RECORD_BINDING_MISMATCH")
    demand(b.get("consumer_authority") ==
           {"path":CONSUMER,"sha256":PINNED["qsv/"+CONSUMER]},
           "HISTORICAL_CONSUMER_AUTHORITY_MISMATCH")
    return r,b

def prepare_one_case_inputs(raw_by_path):
    """Prepare only the immutable selected OpenSSL tg1/tc1 case; never execute A03.

    Caller must supply exact ORIGINAL bytes from externally verified custody.
    Caller dictionaries or this source's self-reported success are not trust anchors.
    """
    validate_raw_snapshot(raw_by_path)
    coverage = parse_json(raw_by_path["qsv/"+COVERAGE])
    cases=coverage.get("cases")
    demand(type(cases) is list and len(cases)==6,"SIX_FIXTURE_COVERAGE_REQUIRED")
    selection=[c for c in cases if type(c) is dict and
               c.get("parameter_set")==CASE["parameter_set"] and
               c.get("case_identity",{}).get("coordinates")==
               {"tg_id":CASE["tg_id"],"tc_id":CASE["tc_id"]}]
    demand(len(selection)==1 and selection[0].get("expected_valid") is False and
           selection[0].get("fixture_path")==FIXTURE and
           selection[0].get("fixture_sha256")==PINNED["qsv/"+FIXTURE],
           "PUBLISHED_FIXTURE_COVERAGE_NOT_PINNED")
    historical_case=parse_json(raw_by_path["qsv/"+CASE_RECORD])
    demand(historical_case.get("published_fixture") ==
           {"path":FIXTURE,"sha256":PINNED["qsv/"+FIXTURE]},
           "HISTORICAL_FIXTURE_PATH_OR_DIGEST_MISMATCH")
    record,binding=selected_record_and_binding(raw_by_path)
    consumer=parse_json(raw_by_path["qsv/"+CONSUMER]).get("consumer")
    demand(type(consumer) is dict and consumer.get("implementation_id")==IMPLEMENTATION and
           consumer.get("source_to_runtime_binding",{}).get("status")=="incomplete" and
           consumer.get("runtime_identity",{}).get("executable_sha256")==SELECTED_EXECUTABLE and
           all(consumer.get(k)==binding["consumer_snapshot"].get(k)
               for k in ("adapter_identity","lineage","repository","runtime_identity",
                         "source_identity","source_to_runtime_binding")),
           "CONSUMER_SNAPSHOT_OR_LINEAGE_INCONSISTENCY")
    # Prove pinned canonicalization contract RAW identity (A04 itself checks only SHA shape).
    neutral_contract=parse_json(raw_by_path["qsv/"+NEUTRAL_CONTRACT])
    demand(bool(neutral_contract),"NEUTRAL_CONTRACT_EMPTY")
    # Required historical raw objects consumed by A03 _fixed_raw(); strict exact set.
    historical=(AGGREGATE,BINDING,CONTRACT,CONSUMER,SUCCESSOR,LINEAGE,ADAPTER,
                RUNTIME_INVOCATION)
    historical_raw={path:raw_by_path["qsv/"+path] for path in historical}
    authority={
       "source_repository":SOURCE_REPO,"source_commit":SOURCE_COMMIT,"source_tree":SOURCE_TREE,
       "source_paths":{"prompt":PROMPT,"expected_results":EXPECTED},
       "neutral_contract_sha256":PINNED["qsv/"+NEUTRAL_CONTRACT],
       "published_fixture_bytes":raw_by_path["qsv/"+FIXTURE],
       "published_fixture_sha256":PINNED["qsv/"+FIXTURE],
       "published_fixture_path":FIXTURE,
       "historical_case_record_bytes":raw_by_path["qsv/"+CASE_RECORD],
       "historical_case_record_sha256":PINNED["qsv/"+CASE_RECORD],
       "historical_case_record_path":CASE_RECORD,
       "normalized_result_bytes":raw_by_path["qsv/"+AGGREGATE],
       "normalized_result_path":AGGREGATE,
       "normalized_binding_manifest_bytes":raw_by_path["qsv/"+BINDING],
       "successor_provenance_manifest_bytes":raw_by_path["qsv/"+SUCCESSOR],
       "historical_repository":HISTORICAL_REPO,
       "historical_commit":HISTORICAL_COMMIT,"historical_tree":HISTORICAL_TREE,
       "historical_raw_by_path":historical_raw,
    }
    request={"implementation_id":IMPLEMENTATION,"case_identity":dict(CASE),
             "acceptance_mode":"source_bound","source_bound_requested":True,
             "case_bindings":[CASE["case_id"]]}
    verified_sources={"prompt":raw_by_path["nist/"+PROMPT],
                      "expected_results":raw_by_path["nist/"+EXPECTED]}
    return {"request":request,"verified_sources":verified_sources,"authority":authority,
            "prepared_observation_raw_snapshot":dict(raw_by_path),
            "claim_limit":"NOT_EXECUTED_NOT_INDEPENDENT_RUNTIME_OBSERVATION"}


def copy_and_verify_exact_raw_snapshot(raw_by_path):
    """Own an exact 18-path byte snapshot, then check its *fixed* authority pins.

    Only exact built-in bytes values are accepted. A new bytes object is obtained
    per entry before validation. The caller's dictionary is never read again
    after this copy completes. This is NOT an OS/runtime isolation guarantee.
    """
    demand(type(raw_by_path) is dict and set(raw_by_path) == set(PINNED),
           "SOURCE_AND_HISTORICAL_PATH_SET_MISMATCH")
    snapshot = {}
    for path in PINNED:
        try:
            supplied = raw_by_path[path]
        except KeyError as exc:
            raise CandidateBlocked("SOURCE_AND_HISTORICAL_PATH_SET_MISMATCH") from exc
        demand(type(supplied) is bytes and len(supplied) <= 4_000_000,
               "RAW_TYPE_OR_SIZE_INVALID:" + path)
        # Always create privately owned bytes; never retain caller containers.
        snapshot[path] = memoryview(supplied).tobytes()
    validate_raw_snapshot(snapshot)
    return snapshot


def invoke_only_after_separate_explicit_runtime_approval(raw_by_path):
    """SOURCE-ONLY candidate; invocation still needs separate runner approval.

    Accept only 18 raw byte inputs, NOT a caller-crafted 'prepared' dictionary.
    Re-verify the owned copy against fixed authority immediately before building
    request/verified_sources/authority. Never trust caller-issued digest overrides.
    This function MUST NOT be called by this source-construction/static-audit turn.
    Runtime module import identity, isolation and approval are NOT established.
    """
    stable_snapshot = copy_and_verify_exact_raw_snapshot(raw_by_path)
    prepared = prepare_one_case_inputs(stable_snapshot)
    # The nested dispatch objects are constructed locally from the verified
    # snapshot; they are not supplied by the caller or stored in a shared cache.
    # An approved external runner must independently pin A03 AND A04 module
    # resolution and prohibit source swaps before allowing this import.
    from verify_qsv_mldsa_adapter_preacceptance_v0_4 import verify_preacceptance
    return verify_preacceptance(prepared["request"], prepared["verified_sources"],
                                prepared["authority"])
