#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import subprocess
import sys

BASE = 'b0fbf40d3a20a68e1242d3674f3a794c625484d4'
BASE_TREE = '4e6fa5221d7481d6f1d39fa155524bb46da4a58d'
SCHEMA = 'schemas/qsv-mldsa-normalized-result-source-binding-v0.1.schema.json'
SCHEMA_SHA = '400035a8c7543318390d231abb7baf217ca03af4713ad7151321fc1ebf1381e7'
CONTRACT = 'contracts/qsv-mldsa-normalized-result-source-binding-contract-v0.1.json'
CONTRACT_SHA = '21a6d62111e5dad9d1d7f88f57f3d438f06abfed260ec9aea33aa78ec066d441'
MANIFEST = 'manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json'
VERIFIER = 'runtime/verify_qsv_mldsa_normalized_result_source_binding_v0_1.py'

NORM = 'results/qsv_mldsa_f7_normalized_result_evidence_v0_1/qsv_mldsa_f7_normalized_result_evidence_v0_1.json'
NORM_SHA = 'fa549e10ec79e0de4f79c516a7eacc5ed937de0a6defde7769efea3dd57e2335'
RUNTIME = 'results/qsv_mldsa_f7_runtime_invocation_evidence_v0_1/qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json'
RUNTIME_SHA = '0a5f8da64736deab407e76a35db40a5badff9018f1c1e8f5c49f1cfeba5d42b0'
OPENSSL = 'manifest/qsv-mldsa-f7-consumer-identity-openssl-v0.1.json'
OPENSSL_SHA = '20a5adb3b789051fafcb65423ec7219a25ae6462574bd29245de598d9b39889d'
CIRCL = 'manifest/qsv-mldsa-f7-consumer-identity-cloudflare-circl-v0.1.json'
CIRCL_SHA = '45e418dc68a065eac6381639efc7764ce99ff86ebd1e4f4b6f2795526c76295d'
ADAPTER = 'runtime/qsv_mldsa_normalized_result_adapter_v0_1.py'
ADAPTER_SHA = '5a9adeeb92eef28abd5f3d5a6be516f886c7f8b8b656dfbddfb83e66ed9655e8'
LINEAGE = 'lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json'
LINEAGE_SHA = 'bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289'
AGG = 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_aggregate_summary_v0_1.json'
AGG_SHA = '5aff3ed86320e9ec4080c691b1018211e6a9f721008838925f0268e04782e1fe'
SEVEN_DIGEST = '6a196b09790f18f1a7a4e2bdc5964baaf9dad88e1d8802c771a2bfa72a37811e'
CASES = (('ML-DSA-44-tg1-tc1', 'ML-DSA-44', 1, 1, False, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa44_tg1_tc1_v0_1.json', 'b0f8d9025b5db0f167398a120e66f719c2a4e67cdb5785a8f23961f4e39dc967'), ('ML-DSA-44-tg1-tc3', 'ML-DSA-44', 1, 3, True, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa44_tg1_tc3_v0_1.json', 'a6e9f8537b07e126f1046a99670ff025e30f65364f23a21ad5f4ad083abd1ed9'), ('ML-DSA-65-tg3-tc31', 'ML-DSA-65', 3, 31, False, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa65_tg3_tc31_v0_1.json', 'dd528a48ccb29a1fc384fd2c192b687ee3398aeda29f9e5c93f9a4755977586e'), ('ML-DSA-65-tg3-tc33', 'ML-DSA-65', 3, 33, True, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa65_tg3_tc33_v0_1.json', '630fdc79bbb4b6998f1334a06e958220e7834c785450cc6ed3cc84af9972d66a'), ('ML-DSA-87-tg5-tc61', 'ML-DSA-87', 5, 61, False, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa87_tg5_tc61_v0_1.json', '14eea9161ddb939281a90617e9dc78c90d973db29114441a51763ade82ebe7d8'), ('ML-DSA-87-tg5-tc63', 'ML-DSA-87', 5, 63, True, 'results/qsv_mldsa_f7_source_bound_acceptance_evidence_v0_1/qsv_mldsa_f7_source_bound_acceptance_case_mldsa87_tg5_tc63_v0_1.json', '8fa64e78b48933dfbdf4eb3e6447d96f997f3910563d5e0adf4f6b28a051c55b'))

KNOWN_PRESTAGING_UNTRACKED = tuple(sorted((
    'schemas/qsv-mldsa-normalized-result-source-binding-v0.1.schema.json',
    'contracts/qsv-mldsa-normalized-result-source-binding-contract-v0.1.json',
    'contracts/qsv-mldsa-normalized-result-source-binding-contract-v0.1.json.sha256',
    'runtime/verify_qsv_mldsa_normalized_result_source_binding_v0_1.py',
    'runtime/verify_qsv_mldsa_normalized_result_source_binding_v0_1.py.sha256',
    'manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json',
    'manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json.sha256',
)))

HISTORICAL = {
    NORM: NORM_SHA,
    RUNTIME: RUNTIME_SHA,
    OPENSSL: OPENSSL_SHA,
    CIRCL: CIRCL_SHA,
    ADAPTER: ADAPTER_SHA,
    LINEAGE: LINEAGE_SHA,
    AGG: AGG_SHA,
}
for _cid,_ps,_tg,_tc,_ev,_path,_sha in CASES:
    HISTORICAL[_path] = _sha


class ControlledBlock(Exception):
    pass


def stop(code):
    print("BINDING_VERIFIER_RESULT=BLOCKED")
    print("BLOCKER=" + code)
    raise ControlledBlock(code)


def h(data):
    return hashlib.sha256(data).hexdigest()


def canonical_record_sha256(obj):
    raw = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return h(raw)


def gp(root, *args, allowed=(0,)):
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    p = subprocess.run(
        ["/usr/bin/git", "-C", str(root), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if p.returncode not in allowed:
        stop("AUTHORITY_MISMATCH=git_read:" + repr(args))
    return p


def gt(root, *args):
    return gp(root, *args).stdout.decode("utf-8", "surrogateescape").strip()


def gb(root, *args):
    return gp(root, *args).stdout


def gpaths(root, *args):
    return tuple(
        sorted(
            x.decode("utf-8", "surrogateescape")
            for x in gb(root, *args).split(b"\0")
            if x
        )
    )


def load_json_bytes(data, label):
    try:
        obj = json.loads(data.decode("utf-8"))
    except Exception:
        stop("MALFORMED_DOCUMENT=" + label)
    if not isinstance(obj, dict):
        stop("MALFORMED_DOCUMENT=" + label + ":object_required")
    return obj


def require_exact_keys(obj, expected, context):
    if not isinstance(obj, dict):
        stop("MALFORMED_DOCUMENT=" + context + ":object_required")
    actual = set(obj)
    expected = set(expected)
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        stop(
            "REQUIRED_FIELD_MISSING="
            + context
            + ":"
            + ",".join(missing)
        )
    if unknown:
        stop(
            "UNKNOWN_FIELD="
            + context
            + ":"
            + ",".join(unknown)
        )


def validate_repo_relative_path(root, rel, expected, context):
    if not isinstance(rel, str) or not rel:
        stop("INVALID_PATH=" + context)
    if "\x00" in rel or "\\" in rel or rel.startswith("/") or "//" in rel:
        stop("INVALID_PATH=" + context)
    pure = pathlib.PurePosixPath(rel)
    if pure.is_absolute() or any(
        part in ("", ".", "..") for part in pure.parts
    ):
        stop("PATH_ESCAPE=" + context)
    if rel != expected:
        stop("AUTHORITY_MISMATCH=" + context + ":unexpected_path")
    cur = root
    for part in pure.parts:
        cur = cur / part
        if cur.is_symlink():
            stop("INVALID_PATH=" + context + ":symlink")
    if not cur.is_file():
        stop("INVALID_PATH=" + context + ":regular_file_required")
    resolved = cur.resolve()
    try:
        common = os.path.commonpath([str(root), str(resolved)])
    except Exception:
        stop("PATH_ESCAPE=" + context)
    if common != str(root):
        stop("PATH_ESCAPE=" + context)
    return cur


def verify_sidecar(root, rel):
    target = validate_repo_relative_path(root, rel, rel, "target:" + rel)
    side = validate_repo_relative_path(
        root,
        rel + ".sha256",
        rel + ".sha256",
        "sidecar:" + rel,
    )
    digest = h(target.read_bytes())
    expected = digest + "  " + rel + "\n"
    try:
        observed = side.read_text(encoding="utf-8")
    except Exception:
        stop("MALFORMED_DOCUMENT=sidecar:" + rel)
    if observed != expected:
        stop("HASH_MISMATCH=sidecar:" + rel)
    return digest


def verify_git_state(root):
    actual_root = pathlib.Path(
        gt(root, "rev-parse", "--show-toplevel")
    ).resolve()
    if actual_root != root:
        stop("AUTHORITY_MISMATCH=repository_root")

    if gt(root, "rev-parse", BASE + "^{tree}") != BASE_TREE:
        stop("AUTHORITY_MISMATCH=base_tree")

    anc = gp(
        root,
        "merge-base",
        "--is-ancestor",
        BASE,
        "HEAD",
        allowed=(0, 1),
    )
    if anc.returncode != 0:
        stop("AUTHORITY_MISMATCH=base_not_ancestor")

    if gp(
        root,
        "diff",
        "--cached",
        "--quiet",
        allowed=(0, 1),
    ).returncode != 0:
        stop("FILESYSTEM_GIT_MISMATCH=index_dirty")

    if gp(
        root,
        "diff",
        "--quiet",
        allowed=(0, 1),
    ).returncode != 0:
        stop("FILESYSTEM_GIT_MISMATCH=tracked_worktree_dirty")

    untracked = gpaths(
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )
    if untracked not in ((), KNOWN_PRESTAGING_UNTRACKED):
        stop("FILESYSTEM_GIT_MISMATCH=unexpected_untracked_set")


def git_blob(root, rev, rel):
    return gb(root, "show", rev + ":" + rel)


def verify_base_head_preservation(root, rel, expected_sha):
    base_bytes = git_blob(root, BASE, rel)
    head_bytes = git_blob(root, "HEAD", rel)

    if h(base_bytes) != expected_sha:
        stop("HISTORICAL_PRESERVATION_FAILURE=" + rel + ":base_sha")
    if h(head_bytes) != expected_sha:
        stop("HISTORICAL_PRESERVATION_FAILURE=" + rel + ":head_sha")
    if base_bytes != head_bytes:
        stop("HISTORICAL_PRESERVATION_FAILURE=" + rel + ":bytes")
    if gt(root, "rev-parse", BASE + ":" + rel) != gt(
        root, "rev-parse", "HEAD:" + rel
    ):
        stop("HISTORICAL_PRESERVATION_FAILURE=" + rel + ":blob_oid")
    return head_bytes


def verify_head_filesystem_equivalence(root, rel, expected_sha):
    head_bytes = verify_base_head_preservation(
        root,
        rel,
        expected_sha,
    )
    path = validate_repo_relative_path(
        root,
        rel,
        rel,
        "historical:" + rel,
    )
    fs_bytes = path.read_bytes()
    if h(fs_bytes) != expected_sha or fs_bytes != head_bytes:
        stop("FILESYSTEM_GIT_MISMATCH=" + rel)
    return fs_bytes


def verify_hash_bound_reference(
    root,
    ref,
    expected_path,
    expected_sha,
    context,
):
    require_exact_keys(ref, ("path", "sha256"), context)
    path = validate_repo_relative_path(
        root,
        ref["path"],
        expected_path,
        context,
    )
    if ref["sha256"] != expected_sha:
        stop("HASH_MISMATCH=" + context + ":declared_sha")
    if h(path.read_bytes()) != expected_sha:
        stop("HASH_MISMATCH=" + context + ":filesystem_sha")


def main():
    if "QSV_EXECUTE_CRYPTO" in os.environ:
        stop("AUTHORITY_MISMATCH=QSV_EXECUTE_CRYPTO_present")

    root = (
        pathlib.Path(sys.argv[1]).resolve()
        if len(sys.argv) == 2
        else pathlib.Path(__file__).resolve().parent.parent
    )

    verify_git_state(root)

    self_sha = verify_sidecar(root, VERIFIER)
    contract_sha = verify_sidecar(root, CONTRACT)
    manifest_sha = verify_sidecar(root, MANIFEST)

    if contract_sha != CONTRACT_SHA:
        stop("HASH_MISMATCH=contract")
    if h((root / SCHEMA).read_bytes()) != SCHEMA_SHA:
        stop("HASH_MISMATCH=schema")

    schema = load_json_bytes((root / SCHEMA).read_bytes(), SCHEMA)
    contract = load_json_bytes((root / CONTRACT).read_bytes(), CONTRACT)
    manifest = load_json_bytes((root / MANIFEST).read_bytes(), MANIFEST)

    require_exact_keys(
        manifest,
        (
            "schema",
            "authority_version",
            "authority_model",
            "schema_binding",
            "contract_binding",
            "historical_normalized_result",
            "historical_runtime_evidence",
            "public_source_bound_evidence",
            "consumer_authorities",
            "bindings",
            "summary",
            "claim_boundary",
        ),
        "manifest",
    )

    if schema.get("$id") != (
        "urn:qsv:mldsa:normalized-result-source-binding:0.1"
    ):
        stop("AUTHORITY_MISMATCH=schema_id")
    if schema.get("additionalProperties") is not False:
        stop("AUTHORITY_MISMATCH=schema_not_closed")

    if contract.get("schema_binding") != {
        "path": SCHEMA,
        "sha256": SCHEMA_SHA,
    }:
        stop("AUTHORITY_MISMATCH=contract_schema_binding")

    if contract.get("schema_enforcement", {}).get(
        "model"
    ) != "MODEL_S2_STDLIB_EXPLICIT_EXACT_VALIDATION":
        stop("AUTHORITY_MISMATCH=contract_schema_enforcement")

    if contract.get("repository_trust_model", {}).get(
        "model"
    ) != "BASE_HEAD_FILESYSTEM_THREE_LAYER":
        stop("AUTHORITY_MISMATCH=contract_trust_model")

    if manifest["schema"] != (
        "qsv.mldsa.normalized-result-source-binding.v0.1"
    ):
        stop("AUTHORITY_MISMATCH=manifest_schema")
    if manifest["authority_version"] != "0.1":
        stop("AUTHORITY_MISMATCH=manifest_version")
    if manifest["authority_model"] != (
        "MODEL_C_EXTERNAL_HASH_BOUND_BINDING_AUTHORITY"
    ):
        stop("AUTHORITY_MISMATCH=manifest_model")

    verify_hash_bound_reference(
        root,
        manifest["schema_binding"],
        SCHEMA,
        SCHEMA_SHA,
        "manifest.schema_binding",
    )
    verify_hash_bound_reference(
        root,
        manifest["contract_binding"],
        CONTRACT,
        CONTRACT_SHA,
        "manifest.contract_binding",
    )

    expected_norm_ref = {
        "path": NORM,
        "sha256": NORM_SHA,
        "schema": "qsv.mldsa.f7-normalized-result-evidence.v0.1",
        "record_count": 12,
    }
    if manifest["historical_normalized_result"] != expected_norm_ref:
        stop("AUTHORITY_MISMATCH=historical_normalized_result_ref")

    expected_runtime_ref = {
        "path": RUNTIME,
        "sha256": RUNTIME_SHA,
    }
    if manifest["historical_runtime_evidence"] != expected_runtime_ref:
        stop("AUTHORITY_MISMATCH=historical_runtime_evidence_ref")

    expected_public = {
        "commit": BASE,
        "tree": BASE_TREE,
        "aggregate_path": AGG,
        "aggregate_sha256": AGG_SHA,
        "seven_record_digest_manifest_sha256": SEVEN_DIGEST,
        "selected_case_count": 6,
    }
    if manifest["public_source_bound_evidence"] != expected_public:
        stop("AUTHORITY_MISMATCH=public_source_bound_evidence")

    for rel, expected_sha in sorted(HISTORICAL.items()):
        verify_head_filesystem_equivalence(
            root,
            rel,
            expected_sha,
        )

    norm = load_json_bytes(
        git_blob(root, BASE, NORM),
        NORM,
    )
    runtime = load_json_bytes(
        git_blob(root, BASE, RUNTIME),
        RUNTIME,
    )
    aggregate = load_json_bytes(
        git_blob(root, BASE, AGG),
        AGG,
    )

    if not (
        aggregate.get("aggregate_state") == "PASS"
        and aggregate.get("expected_case_count") == 6
        and aggregate.get("source_bound_acceptance_complete") is True
        and aggregate.get("global_f7_source_bound_acceptance") is True
    ):
        stop("SOURCE_BOUND_REFERENCE_MISMATCH=aggregate_semantics")

    digest_rows = {AGG: AGG_SHA}
    source_specs = {}
    for cid, ps, tg, tc, ev, path, sha in CASES:
        obj = load_json_bytes(
            git_blob(root, BASE, path),
            path,
        )
        ident = obj.get("case_identity", {})
        coords = ident.get("coordinates", {})
        key = (ps, tg, tc, ev)
        if (
            obj.get("source_bound_verification_state") != "PASS"
            or ident.get("parameter_set") != ps
            or coords.get("tg_id") != tg
            or coords.get("tc_id") != tc
            or ident.get("expected_valid") is not ev
        ):
            stop("SOURCE_BOUND_REFERENCE_MISMATCH=" + cid)
        source_specs[key] = (cid, path, sha)
        digest_rows[path] = sha

    digest_manifest = h(
        "\n".join(
            rel + "\t" + digest_rows[rel]
            for rel in sorted(digest_rows)
        ).encode("utf-8")
    )
    if digest_manifest != SEVEN_DIGEST:
        stop("HASH_MISMATCH=seven_record_digest")

    consumers = {}
    for impl, rel, sha in (
        ("openssl", OPENSSL, OPENSSL_SHA),
        ("cloudflare-circl", CIRCL, CIRCL_SHA),
    ):
        obj = load_json_bytes(
            git_blob(root, BASE, rel),
            rel,
        )
        consumer = obj.get("consumer")
        if not isinstance(consumer, dict):
            stop("MALFORMED_DOCUMENT=consumer:" + impl)
        if consumer.get("implementation_id") != impl:
            stop("CONSUMER_AUTHORITY_MISMATCH=" + impl + ":id")
        if consumer.get("source_to_runtime_binding", {}).get(
            "status"
        ) != "incomplete":
            stop(
                "CONSUMER_AUTHORITY_MISMATCH="
                + impl
                + ":source_to_runtime_status"
            )
        consumers[impl] = consumer

    auths = manifest["consumer_authorities"]
    if not isinstance(auths, list) or len(auths) != 2:
        stop("AUTHORITY_MISMATCH=consumer_authority_count")

    auth_by_impl = {}
    for entry in auths:
        require_exact_keys(
            entry,
            (
                "implementation_id",
                "path",
                "sha256",
                "source_to_runtime_status",
            ),
            "consumer_authority_entry",
        )
        impl = entry["implementation_id"]
        if impl in auth_by_impl:
            stop("AUTHORITY_MISMATCH=duplicate_consumer_authority")
        if impl not in ("openssl", "cloudflare-circl"):
            stop("AUTHORITY_MISMATCH=unknown_consumer_authority")
        expected_path, expected_sha = (
            (OPENSSL, OPENSSL_SHA)
            if impl == "openssl"
            else (CIRCL, CIRCL_SHA)
        )
        expected_entry = {
            "implementation_id": impl,
            "path": expected_path,
            "sha256": expected_sha,
            "source_to_runtime_status": "incomplete",
        }
        if entry != expected_entry:
            stop("CONSUMER_AUTHORITY_MISMATCH=" + impl + ":entry")
        verify_hash_bound_reference(
            root,
            {
                "path": entry["path"],
                "sha256": entry["sha256"],
            },
            expected_path,
            expected_sha,
            "consumer_authority_entry." + impl,
        )
        auth_by_impl[impl] = entry

    if set(auth_by_impl) != {"openssl", "cloudflare-circl"}:
        stop("AUTHORITY_MISMATCH=consumer_authority_set")

    records = norm.get("records")
    if not isinstance(records, list) or len(records) != 12:
        stop("AUTHORITY_MISMATCH=normalized_record_count")

    normalized = {}
    for record in records:
        impl = record.get("implementation")
        if impl not in consumers:
            stop("AUTHORITY_MISMATCH=normalized_implementation")
        case = record.get("inputs", {}).get("case", {})
        key = (
            impl,
            case.get("parameter_set"),
            case.get("tg_id"),
            case.get("tc_id"),
            case.get("source_expected_valid"),
        )
        if key in normalized:
            stop("AUTHORITY_MISMATCH=duplicate_normalized_mapping")
        normalized[key] = record

    bindings = manifest["bindings"]
    if not isinstance(bindings, list) or len(bindings) != 12:
        stop("AUTHORITY_MISMATCH=binding_count")

    seen = set()
    for binding in bindings:
        require_exact_keys(
            binding,
            (
                "implementation_id",
                "case_identity",
                "normalized_record",
                "consumer_authority",
                "consumer_snapshot",
                "source_bound_case",
            ),
            "binding",
        )
        require_exact_keys(
            binding["case_identity"],
            (
                "case_id",
                "parameter_set",
                "tg_id",
                "tc_id",
                "expected_valid",
            ),
            "binding.case_identity",
        )
        require_exact_keys(
            binding["normalized_record"],
            (
                "selector",
                "canonical_sha256",
                "result_state",
                "observed_acceptance",
                "resolved_executable_sha256",
            ),
            "binding.normalized_record",
        )
        require_exact_keys(
            binding["normalized_record"]["selector"],
            (
                "implementation_id",
                "case_id",
                "parameter_set",
                "tg_id",
                "tc_id",
                "expected_valid",
            ),
            "binding.normalized_record.selector",
        )
        require_exact_keys(
            binding["consumer_authority"],
            ("path", "sha256"),
            "binding.consumer_authority",
        )
        require_exact_keys(
            binding["consumer_snapshot"],
            (
                "repository",
                "source_identity",
                "runtime_identity",
                "source_to_runtime_binding",
                "lineage",
                "adapter_identity",
            ),
            "binding.consumer_snapshot",
        )
        require_exact_keys(
            binding["source_bound_case"],
            ("path", "sha256", "state"),
            "binding.source_bound_case",
        )

        impl = binding["implementation_id"]
        if impl not in consumers:
            stop("CONSUMER_AUTHORITY_MISMATCH=unknown_binding_impl")

        ci = binding["case_identity"]
        key = (
            impl,
            ci["parameter_set"],
            ci["tg_id"],
            ci["tc_id"],
            ci["expected_valid"],
        )
        if key in seen:
            stop("AUTHORITY_MISMATCH=duplicate_binding_mapping")
        if key not in normalized:
            stop("AUTHORITY_MISMATCH=binding_without_normalized_record")
        seen.add(key)

        record = normalized[key]
        case = record["inputs"]["case"]
        expected_ci = {
            "case_id": case["case_id"],
            "parameter_set": case["parameter_set"],
            "tg_id": case["tg_id"],
            "tc_id": case["tc_id"],
            "expected_valid": case["source_expected_valid"],
        }
        if ci != expected_ci:
            stop("AUTHORITY_MISMATCH=binding_case_identity")

        selector = binding["normalized_record"]["selector"]
        expected_selector = {
            "implementation_id": impl,
            "case_id": case["case_id"],
            "parameter_set": case["parameter_set"],
            "tg_id": case["tg_id"],
            "tc_id": case["tc_id"],
            "expected_valid": case["source_expected_valid"],
        }
        if selector != expected_selector:
            stop("AUTHORITY_MISMATCH=normalized_selector")

        if binding["normalized_record"]["canonical_sha256"] != (
            canonical_record_sha256(record)
        ):
            stop("HASH_MISMATCH=normalized_record_canonical_sha")

        if binding["normalized_record"]["result_state"] != record.get(
            "result_state"
        ):
            stop("AUTHORITY_MISMATCH=normalized_result_state")

        if binding["normalized_record"]["observed_acceptance"] is not (
            record.get("observed_acceptance")
        ):
            stop("AUTHORITY_MISMATCH=normalized_observed_acceptance")

        runtime_hash = record["artifact_hashes"][
            "resolved_executable_sha256"
        ]
        if binding["normalized_record"][
            "resolved_executable_sha256"
        ] != runtime_hash:
            stop("CONSUMER_AUTHORITY_MISMATCH=normalized_runtime_hash")

        expected_consumer_path, expected_consumer_sha = (
            (OPENSSL, OPENSSL_SHA)
            if impl == "openssl"
            else (CIRCL, CIRCL_SHA)
        )
        verify_hash_bound_reference(
            root,
            binding["consumer_authority"],
            expected_consumer_path,
            expected_consumer_sha,
            "binding.consumer_authority." + impl,
        )

        consumer = consumers[impl]
        expected_snapshot = {
            "repository": consumer["repository"],
            "source_identity": consumer["source_identity"],
            "runtime_identity": consumer["runtime_identity"],
            "source_to_runtime_binding": consumer[
                "source_to_runtime_binding"
            ],
            "lineage": consumer["lineage"],
            "adapter_identity": consumer["adapter_identity"],
        }
        if binding["consumer_snapshot"] != expected_snapshot:
            stop("CONSUMER_AUTHORITY_MISMATCH=consumer_snapshot." + impl)

        if binding["consumer_snapshot"][
            "source_to_runtime_binding"
        ].get("status") != "incomplete":
            stop("CONSUMER_AUTHORITY_MISMATCH=false_provenance_promotion")

        if binding["consumer_snapshot"]["runtime_identity"].get(
            "executable_sha256"
        ) != runtime_hash:
            stop("CONSUMER_AUTHORITY_MISMATCH=result_runtime_join")

        skey = (
            ci["parameter_set"],
            ci["tg_id"],
            ci["tc_id"],
            ci["expected_valid"],
        )
        if skey not in source_specs:
            stop("SOURCE_BOUND_REFERENCE_MISMATCH=selected_case_mapping")
        _cid, source_path, source_sha = source_specs[skey]
        expected_source_ref = {
            "path": source_path,
            "sha256": source_sha,
            "state": "PASS",
        }
        if binding["source_bound_case"] != expected_source_ref:
            stop("SOURCE_BOUND_REFERENCE_MISMATCH=source_bound_case_ref")

    if set(normalized) != seen:
        stop("AUTHORITY_MISMATCH=binding_set_not_exact")

    expected_summary = {
        "normalized_record_count": 12,
        "implementation_count": 2,
        "selected_case_count": 6,
        "binding_count": 12,
        "source_bound_case_count": 6,
        "source_to_runtime_proven_consumer_count": 0,
        "source_to_runtime_incomplete_consumer_count": 2,
        "requirement_e_status": "PARTIAL",
        "construction_semantics": "append_only_external_hash_binding",
    }
    if manifest["summary"] != expected_summary:
        stop("AUTHORITY_MISMATCH=summary")

    expected_claim_boundary = {
        "selected_six_case_source_bound_acceptance_complete": True,
        "public_seven_record_evidence_verified": True,
        "full_f7_source_bound_coverage": False,
        "complete_acvp_coverage": False,
        "source_to_runtime_provenance_complete": False,
        "nist_validation": False,
        "fips_204_certification": False,
        "universal_mldsa_correctness": False,
        "third_party_independent_crypto_reproduction": False,
        "historical_normalized_result_rewritten": False,
        "adapter_wiring_implemented": False,
        "new_crypto_execution_performed": False,
    }
    if manifest["claim_boundary"] != expected_claim_boundary:
        stop("AUTHORITY_MISMATCH=claim_boundary")

    invocations = runtime.get("invocations")
    if not isinstance(invocations, list) or len(invocations) != 12:
        stop("AUTHORITY_MISMATCH=runtime_invocation_count")

    for inv in invocations:
        impl = inv.get("implementation")
        if impl not in consumers:
            stop("AUTHORITY_MISMATCH=runtime_implementation")
        source = inv.get("implementation_source_authority", {})
        consumer = consumers[impl]
        csource = consumer.get("source_identity", {})
        if not (
            source.get("repository") == consumer.get("repository")
            and source.get("commit") == csource.get("commit")
            and source.get("tree") == csource.get("tree")
        ):
            stop("CONSUMER_AUTHORITY_MISMATCH=runtime_source_identity")

    print("QSV_MLDSA_NORMALIZED_RESULT_SOURCE_BINDING_VERIFIER=PASS")
    print("VERIFIER_SELF_SHA256=" + self_sha)
    print("CONTRACT_SHA256=" + contract_sha)
    print("MANIFEST_SHA256=" + manifest_sha)
    print("NORMALIZED_RECORD_COUNT=12")
    print("BINDING_COUNT=12")
    print("SELECTED_CASE_COUNT=6")
    print("OPENSSL_SOURCE_TO_RUNTIME_STATUS=incomplete")
    print("CIRCL_SOURCE_TO_RUNTIME_STATUS=incomplete")
    print("SOURCE_TO_RUNTIME_PROVENANCE_COMPLETE=NO")
    print("SELECTED_SIX_CASE_SOURCE_BOUND_ACCEPTANCE_COMPLETE=YES")
    print("FULL_F7_SOURCE_BOUND_COVERAGE=NO")
    print("NIST_VALIDATION=NO")
    print("FIPS_204_CERTIFICATION=NO")
    print("THIRD_PARTY_INDEPENDENT_CRYPTO_REPRODUCTION=NO")
    print("NEW_CRYPTO_EXECUTION_PERFORMED=NO")
    print("BINDING_VERIFIER_RESULT=PASS")


if __name__ == "__main__":
    try:
        main()
    except ControlledBlock:
        raise SystemExit(1)
    except SystemExit:
        raise
    except Exception as exc:
        print("BINDING_VERIFIER_RESULT=BLOCKED")
        print("BLOCKER=INTERNAL_VERIFIER_ERROR:" + type(exc).__name__)
        raise SystemExit(1)
