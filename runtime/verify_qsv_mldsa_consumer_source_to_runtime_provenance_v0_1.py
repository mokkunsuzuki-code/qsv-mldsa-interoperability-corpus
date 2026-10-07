#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

PREDECESSOR_COMMIT = "7fbf5c84a01a3f51da38bb680b4133922ae4ff4b"
PREDECESSOR_TREE = "15a46eddfee496e29e7cf8ffc91bcf7c203441c1"
PREDECESSOR_PARENT = "b0fbf40d3a20a68e1242d3674f3a794c625484d4"
PREDECESSOR_SUBJECT = "Add SB-2R normalized-result source-binding authority v0.1"

SCHEMA_REL = "schemas/qsv-mldsa-consumer-source-to-runtime-provenance-v0.1.schema.json"
CONTRACT_REL = "contracts/qsv-mldsa-consumer-source-to-runtime-provenance-contract-v0.1.json"
MANIFEST_REL = "manifest/qsv-mldsa-f7-consumer-source-to-runtime-provenance-v0.1-manifest.json"
SELF_REL = "runtime/verify_qsv_mldsa_consumer_source_to_runtime_provenance_v0_1.py"

EXPECTED_EVIDENCE = {
    "workflow": (
        ".github/workflows/qsv-mldsa-f7-instrumented-sixcase-reproduction-v0_1.yml",
        "89841e7b818ac0e37ec322ae1972463270372275db40c49b0175830fd20e39fb",
    ),
    "runtime_invocation_evidence": (
        "results/qsv_mldsa_f7_runtime_invocation_evidence_v0_1/qsv_mldsa_f7_runtime_invocation_evidence_v0_1.job-bound.json",
        "0a5f8da64736deab407e76a35db40a5badff9018f1c1e8f5c49f1cfeba5d42b0",
    ),
    "openssl_consumer": (
        "manifest/qsv-mldsa-f7-consumer-identity-openssl-v0.1.json",
        "20a5adb3b789051fafcb65423ec7219a25ae6462574bd29245de598d9b39889d",
    ),
    "circl_consumer": (
        "manifest/qsv-mldsa-f7-consumer-identity-cloudflare-circl-v0.1.json",
        "45e418dc68a065eac6381639efc7764ce99ff86ebd1e4f4b6f2795526c76295d",
    ),
    "lineage": (
        "lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json",
        "bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289",
    ),
    "adapter": (
        "runtime/qsv_mldsa_normalized_result_adapter_v0_1.py",
        "5a9adeeb92eef28abd5f3d5a6be516f886c7f8b8b656dfbddfb83e66ed9655e8",
    ),
    "normalized_result_evidence": (
        "results/qsv_mldsa_f7_normalized_result_evidence_v0_1/qsv_mldsa_f7_normalized_result_evidence_v0_1.json",
        "fa549e10ec79e0de4f79c516a7eacc5ed937de0a6defde7769efea3dd57e2335",
    ),
    "normalized_result_source_binding": (
        "manifest/qsv-mldsa-f7-normalized-result-source-binding-v0.1-manifest.json",
        "32620fc0d957c93f78913fd60eb2441ca1201e15121bf0bda5ceda72e88451cd",
    ),
}

OPENSSL_SOURCE = {
    "repository": "https://github.com/openssl/openssl.git",
    "commit": "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",
    "tree": "a8a306c000bc2426afd3264b2c41bc7223728475",
    "version": "3.6.3",
}
CIRCL_SOURCE = {
    "repository": "https://github.com/cloudflare/circl.git",
    "commit": "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
    "tree": "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",
    "version": None,
}
OPENSSL_RUNTIME_SHA = "07978755211bffcfe57f28ce6354292245a3a0af08d247c617c3f36378aa6b93"
CIRCL_RUNTIME_SHA = "b53ca61dd665f628770a2d2326e3b335ea35bc2a18f5dbfd2a23374064c230c0"

CASE_SHA = {
    "ML-DSA-44-tg1-tc1": "b0f8d9025b5db0f167398a120e66f719c2a4e67cdb5785a8f23961f4e39dc967",
    "ML-DSA-44-tg1-tc3": "a6e9f8537b07e126f1046a99670ff025e30f65364f23a21ad5f4ad083abd1ed9",
    "ML-DSA-65-tg3-tc31": "dd528a48ccb29a1fc384fd2c192b687ee3398aeda29f9e5c93f9a4755977586e",
    "ML-DSA-65-tg3-tc33": "630fdc79bbb4b6998f1334a06e958220e7834c785450cc6ed3cc84af9972d66a",
    "ML-DSA-87-tg5-tc61": "14eea9161ddb939281a90617e9dc78c90d973db29114441a51763ade82ebe7d8",
    "ML-DSA-87-tg5-tc63": "8fa64e78b48933dfbdf4eb3e6447d96f997f3910563d5e0adf4f6b28a051c55b",
}
CANONICAL = {
    "cloudflare-circl": {
        "ML-DSA-44-tg1-tc1": "7ba8ab255e82531b34bbc7da2c4835a8acfa2bee72db40178c4e64beee2560bc",
        "ML-DSA-44-tg1-tc3": "e96b9961e523626a5eaef8f84a8fcecb9cc7e16e1c3f6c7e9deb37d2a78b161b",
        "ML-DSA-65-tg3-tc31": "2bc8a8ea8d83c464d42ef5395878b7a1cb1c9b277e82ac02b4b756c3a2c87439",
        "ML-DSA-65-tg3-tc33": "5f3e4cdf8cd4b7cc83f7074d6fcd0f2367ca38bbe5a723bded927046f102c518",
        "ML-DSA-87-tg5-tc61": "744eb206378f175e6db557c2e858c5402a29e126bd754728229b5f4918c4b1cc",
        "ML-DSA-87-tg5-tc63": "c3b185e19d9d594a610111bdae7487dfb81db2af3aab0a051a1da024171cdf31",
    },
    "openssl": {
        "ML-DSA-44-tg1-tc1": "920c71cbcf752c1b954536d2a1e2b1a331e41a97c5d00f42146dfb4ae528ac30",
        "ML-DSA-44-tg1-tc3": "ad02caf24df1fca8705e7c0778576c513d798112f120b14d0efa4ab7e3cf5328",
        "ML-DSA-65-tg3-tc31": "fb0eb7f91d05046834d4a198fbeb1203526f1cbd693d8eb541740888538b3dec",
        "ML-DSA-65-tg3-tc33": "b3f376ef0714e675563353e583f79e345baf37d856fed72a18b39ce1fbe1ef6b",
        "ML-DSA-87-tg5-tc61": "ef8ee9baf79cd01f559d2699cb4f557709cb8148d41f738fb0ad1cd0f28475ba",
        "ML-DSA-87-tg5-tc63": "5c52ebbaf4da1bb2e6b7a5712d005a41188c26706e95113fdb71b5a1013f0448",
    },
}

class Reject(Exception):
    pass

def need(condition, code):
    if not condition:
        raise Reject(code)

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def sha256_path(path):
    return sha256_bytes(path.read_bytes())

def safe_rel(rel):
    need(isinstance(rel, str) and rel, "PATH_EMPTY")
    p = pathlib.PurePosixPath(rel)
    need(not p.is_absolute(), "ABSOLUTE_PATH:" + rel)
    need(".." not in p.parts, "PARENT_TRAVERSAL:" + rel)
    return p

def regular_file(rel):
    p = ROOT / safe_rel(rel)
    need(p.exists(), "MISSING_FILE:" + rel)
    need(not p.is_symlink(), "SYMLINK_REJECTED:" + rel)
    need(p.is_file(), "NOT_REGULAR_FILE:" + rel)
    return p

def read_json(rel):
    p = regular_file(rel)
    try:
        value = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        raise Reject("JSON_PARSE_ERROR:" + rel + ":" + str(exc))
    need(isinstance(value, dict), "JSON_TOP_LEVEL_NOT_OBJECT:" + rel)
    return value

def git_bytes(*args):
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    p = subprocess.run(
        ["/usr/bin/git", "-C", str(ROOT), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    need(p.returncode == 0, "GIT_COMMAND_FAILED:" + " ".join(args))
    return p.stdout

def git_text(*args):
    return git_bytes(*args).decode("utf-8", "surrogateescape").strip()

def check_sidecar(rel):
    target = regular_file(rel)
    side = regular_file(rel + ".sha256")
    parts = side.read_text(encoding="utf-8").split()
    need(len(parts) == 2, "SIDECAR_SHAPE:" + rel)
    need(parts[0] == sha256_path(target), "SIDECAR_DIGEST:" + rel)
    need(parts[1] == rel, "SIDECAR_PATH:" + rel)

def check_predecessor_dag():
    need(git_text("show", "-s", "--format=%T", PREDECESSOR_COMMIT) == PREDECESSOR_TREE, "PREDECESSOR_TREE")
    need(git_text("show", "-s", "--format=%P", PREDECESSOR_COMMIT) == PREDECESSOR_PARENT, "PREDECESSOR_PARENT")
    need(git_text("show", "-s", "--format=%s", PREDECESSOR_COMMIT) == PREDECESSOR_SUBJECT, "PREDECESSOR_SUBJECT")
    env = dict(os.environ)
    env["GIT_OPTIONAL_LOCKS"] = "0"
    rc = subprocess.run(
        ["/usr/bin/git", "-C", str(ROOT), "merge-base", "--is-ancestor", PREDECESSOR_COMMIT, "HEAD"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=env, check=False,
    ).returncode
    need(rc == 0, "PREDECESSOR_NOT_ANCESTOR_OF_HEAD")

def predecessor_file_three_layer(rel, expected_sha):
    fs = regular_file(rel).read_bytes()
    need(sha256_bytes(fs) == expected_sha, "FILESYSTEM_SHA:" + rel)
    base = git_bytes("show", PREDECESSOR_COMMIT + ":" + rel)
    head = git_bytes("show", "HEAD:" + rel)
    need(sha256_bytes(base) == expected_sha, "BASE_SHA:" + rel)
    need(sha256_bytes(head) == expected_sha, "HEAD_SHA:" + rel)
    need(base == head == fs, "THREE_LAYER_BYTE_MISMATCH:" + rel)


def schema_type_matches(value, expected_type):
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    raise Reject("SCHEMA_UNSUPPORTED_TYPE:" + str(expected_type))

def resolve_local_ref(root_schema, ref):
    prefix = "#/$defs/"
    need(isinstance(ref, str) and ref.startswith(prefix), "SCHEMA_UNSUPPORTED_REF")
    name = ref[len(prefix):]
    need(name and "/" not in name, "SCHEMA_UNSUPPORTED_REF")
    defs = root_schema.get("$defs")
    need(isinstance(defs, dict) and name in defs, "SCHEMA_MISSING_DEF:" + name)
    return defs[name]

def validate_schema(instance, spec, root_schema, path="$"):
    need(isinstance(spec, dict), "SCHEMA_SPEC_NOT_OBJECT:" + path)

    if "$ref" in spec:
        target = resolve_local_ref(root_schema, spec["$ref"])
        validate_schema(instance, target, root_schema, path)
        return

    if "type" in spec:
        expected = spec["type"]
        if isinstance(expected, list):
            need(
                any(schema_type_matches(instance, item) for item in expected),
                "SCHEMA_TYPE:" + path,
            )
        else:
            need(
                schema_type_matches(instance, expected),
                "SCHEMA_TYPE:" + path,
            )

    if "const" in spec:
        need(instance == spec["const"], "SCHEMA_CONST:" + path)

    if "enum" in spec:
        need(instance in spec["enum"], "SCHEMA_ENUM:" + path)

    if isinstance(instance, str):
        if "minLength" in spec:
            need(len(instance) >= spec["minLength"], "SCHEMA_MIN_LENGTH:" + path)
        if "pattern" in spec:
            need(
                re.fullmatch(spec["pattern"], instance) is not None,
                "SCHEMA_PATTERN:" + path,
            )

    if isinstance(instance, list):
        if "minItems" in spec:
            need(len(instance) >= spec["minItems"], "SCHEMA_MIN_ITEMS:" + path)
        if "maxItems" in spec:
            need(len(instance) <= spec["maxItems"], "SCHEMA_MAX_ITEMS:" + path)
        if "items" in spec:
            for index, item in enumerate(instance):
                validate_schema(
                    item,
                    spec["items"],
                    root_schema,
                    path + "[" + str(index) + "]",
                )

    if isinstance(instance, dict):
        required = spec.get("required", [])
        need(isinstance(required, list), "SCHEMA_REQUIRED_SHAPE:" + path)
        for key in required:
            need(key in instance, "SCHEMA_REQUIRED:" + path + "." + str(key))

        properties = spec.get("properties", {})
        need(isinstance(properties, dict), "SCHEMA_PROPERTIES_SHAPE:" + path)

        additional = spec.get("additionalProperties", True)

        for key, value in instance.items():
            child_path = path + "." + str(key)
            if key in properties:
                validate_schema(value, properties[key], root_schema, child_path)
            elif additional is False:
                raise Reject("SCHEMA_UNKNOWN_FIELD:" + child_path)
            elif isinstance(additional, dict):
                validate_schema(value, additional, root_schema, child_path)


def check_contract(contract, schema_sha):
    need(contract["schema"] == "qsv.mldsa.consumer-source-to-runtime-provenance-contract.v0.1", "CONTRACT_SCHEMA")
    need(contract["version"] == "0.1", "CONTRACT_VERSION")
    need(contract["schema_enforcement"]["model"] == "MODEL_S2_STDLIB_EXPLICIT_EXACT_VALIDATION", "SCHEMA_MODEL")
    need(contract["schema_enforcement"]["schema_sha256"] == schema_sha, "SCHEMA_BINDING")
    need(contract["repository_trust_model"]["model"] == "BASE_HEAD_FILESYSTEM_THREE_LAYER", "TRUST_MODEL")
    need(contract["repository_trust_model"]["historical_artifact_rewrite_allowed"] is False, "HISTORICAL_REWRITE")
    need(len(contract["positive_test_matrix"]) == 8, "POSITIVE_TEST_COUNT")
    need(len(contract["negative_test_matrix"]) == 50, "NEGATIVE_TEST_COUNT")
    need(contract["test_targets"]["unexpected_accept_target"] == 0, "UNEXPECTED_ACCEPT_TARGET")
    hist = contract["historical_execution_authority"]
    need(hist["github_run_id"] == 34968252038, "RUN_ID")
    need(hist["github_job_id"] == 104377847614, "JOB_ID")
    need(hist["github_run_attempt"] == 1, "RUN_ATTEMPT")
    need(hist["process_invocation_count"] == 12, "PROCESS_INVOCATION_COUNT")
    for key, (path, digest) in EXPECTED_EVIDENCE.items():
        need(contract["required_evidence_bindings"][key] == {"path": path, "sha256": digest}, "CONTRACT_EVIDENCE:" + key)

def consumer_map(manifest):
    consumers = manifest["consumers"]
    need(isinstance(consumers, list) and len(consumers) == 2, "CONSUMER_COUNT")
    out = {}
    for c in consumers:
        impl = c.get("implementation_id")
        need(impl in {"openssl", "cloudflare-circl"}, "IMPLEMENTATION_ID")
        need(impl not in out, "DUPLICATE_IMPLEMENTATION")
        out[impl] = c
    need(set(out) == {"openssl", "cloudflare-circl"}, "IMPLEMENTATION_SET")
    return out

def check_manifest(manifest, schema_sha, contract_sha):
    need(manifest["schema"] == "qsv.mldsa.consumer-source-to-runtime-provenance.v0.1", "MANIFEST_SCHEMA")
    need(manifest["version"] == "0.1", "MANIFEST_VERSION")
    need(manifest["authority_role"] == "APPEND_ONLY_HISTORICAL_BUILD_EVENT_PROVENANCE_AUTHORITY", "MANIFEST_ROLE")
    pred = manifest["predecessor_public_authority"]
    need(pred["commit"] == PREDECESSOR_COMMIT and pred["tree"] == PREDECESSOR_TREE, "MANIFEST_PREDECESSOR")
    need(manifest["schema_binding"] == {"path": SCHEMA_REL, "sha256": schema_sha}, "MANIFEST_SCHEMA_BINDING")
    need(manifest["contract_binding"] == {"path": CONTRACT_REL, "sha256": contract_sha}, "MANIFEST_CONTRACT_BINDING")
    need(manifest["scope"]["selected_case_count"] == 6, "SELECTED_CASE_COUNT")
    need(manifest["scope"]["implementation_count"] == 2, "IMPLEMENTATION_COUNT")
    need(manifest["scope"]["full_f7_source_bound_coverage"] is False, "FULL_F7_BOUNDARY")
    need(manifest["provenance_model"]["minimum_for_adapter_wiring"] == "LEVEL_3_BUILD_EVENT_EVIDENCED", "MINIMUM_LEVEL")
    need(manifest["provenance_model"]["retroactive_provenance_upgrade_allowed"] is False, "RETROACTIVE_BOUNDARY")
    for key, (path, digest) in EXPECTED_EVIDENCE.items():
        need(manifest["evidence_bindings"][key] == {"path": path, "sha256": digest}, "MANIFEST_EVIDENCE:" + key)
    summary = manifest["summary"]
    need(summary["consumer_count"] == 2, "SUMMARY_CONSUMER_COUNT")
    need(summary["level_3_consumer_count"] == 2, "SUMMARY_LEVEL3_COUNT")
    need(summary["normalized_binding_count"] == 12, "SUMMARY_NORMALIZED_COUNT")
    need(summary["requirement_e_status"] == "COMPLETE_AT_LEVEL_3_DEFINED_SIX_CASE_SCOPE", "REQUIREMENT_E_STATUS")
    need(summary["adapter_wiring_prerequisite_satisfied_if_authority_verifies"] is True, "ADAPTER_PREREQUISITE")
    for key, value in manifest["claim_boundary"].items():
        need(value is False, "CLAIM_BOUNDARY:" + key)

def check_predecessor_consumer(path, impl, expected_source, expected_runtime_sha):
    obj = read_json(path)["consumer"]
    need(obj["implementation_id"] == impl, "PREDECESSOR_IMPLEMENTATION:" + impl)
    need(obj["repository"] == expected_source["repository"], "PREDECESSOR_REPOSITORY:" + impl)
    expected_source_identity = {
        "commit": expected_source["commit"],
        "tree": expected_source["tree"],
        "version": expected_source["version"],
    }
    need(
        obj["source_identity"] == expected_source_identity,
        "PREDECESSOR_SOURCE_IDENTITY:" + impl,
    )
    need(obj["runtime_identity"]["executable_sha256"] == expected_runtime_sha, "PREDECESSOR_RUNTIME:" + impl)
    need(obj["source_to_runtime_binding"]["status"] == "incomplete", "PREDECESSOR_STATUS:" + impl)
    need(obj["adapter_identity"]["sha256"] == EXPECTED_EVIDENCE["adapter"][1], "PREDECESSOR_ADAPTER:" + impl)
    need(obj["lineage"]["binding_sha256"] == EXPECTED_EVIDENCE["lineage"][1], "PREDECESSOR_LINEAGE:" + impl)

def check_lineage():
    obj = read_json(EXPECTED_EVIDENCE["lineage"][0])
    openssl = obj["implementations"]["openssl"]
    circl = obj["implementations"]["cloudflare_circl"]
    need(openssl["upstream_release"]["source_commit"] == OPENSSL_SOURCE["commit"], "LINEAGE_OPENSSL_COMMIT")
    need(openssl["upstream_release"]["source_tree"] == OPENSSL_SOURCE["tree"], "LINEAGE_OPENSSL_TREE")
    need(openssl["build_provenance"]["complete"] is False, "LINEAGE_OPENSSL_COMPLETE")
    need(openssl["build_provenance"]["status"] == "incomplete", "LINEAGE_OPENSSL_STATUS")
    need(circl["source_commit"] == CIRCL_SOURCE["commit"], "LINEAGE_CIRCL_COMMIT")
    need(circl["source_tree"] == CIRCL_SOURCE["tree"], "LINEAGE_CIRCL_TREE")
    need(obj["truth_boundaries"]["hash_alone_implies_build_provenance"] is False, "LINEAGE_HASH_BOUNDARY")
    need(obj["truth_boundaries"]["version_string_implies_build_provenance"] is False, "LINEAGE_VERSION_BOUNDARY")

def check_workflow(contract):
    text = regular_file(EXPECTED_EVIDENCE["workflow"][0]).read_text(encoding="utf-8")
    for impl in ("openssl", "cloudflare-circl"):
        for token in contract["workflow_recipe_requirements"][impl]["required_tokens"]:
            need(token in text, "WORKFLOW_TOKEN:" + impl + ":" + token[:60])

def check_runtime_evidence():
    runtime = read_json(EXPECTED_EVIDENCE["runtime_invocation_evidence"][0])
    github = runtime["github"]
    need(github["github_run_id"] == "34968252038", "RUNTIME_RUN_ID")
    need(github["github_job_id_numeric"] == 104377847614, "RUNTIME_JOB_ID")
    need(github["github_run_attempt"] == "1", "RUNTIME_RUN_ATTEMPT")
    need(runtime["invocation_count"] == 12, "RUNTIME_INVOCATION_COUNT")
    need(runtime["summary"]["openssl_invocation_count"] == 6, "RUNTIME_OPENSSL_COUNT")
    need(runtime["summary"]["circl_invocation_count"] == 6, "RUNTIME_CIRCL_COUNT")
    need(runtime["evidence_semantics"]["captured_at_execution"] is True, "CAPTURED_AT_EXECUTION")
    need(runtime["evidence_semantics"]["reconstructed_after_execution"] is False, "NOT_RECONSTRUCTED")
    build = runtime["build_observations"]
    need(build["openssl_built_binary_sha256"] == "15e2531a6cc982ba7c6d08f1cea086d4f8a132566519a5efefa1e256ea4aad6d", "OPENSSL_BUILT_BINARY")
    need(build["openssl_built_libcrypto_sha256"] == "e1694ccaacbd51548a0f1a135d27d67acb642338b4b175d3276a1d1e8f7495a6", "OPENSSL_LIBCRYPTO")
    need(build["openssl_harness_binary_sha256"] == OPENSSL_RUNTIME_SHA, "OPENSSL_BUILD_RUNTIME_EDGE")
    need(build["circl_harness_binary_sha256"] == CIRCL_RUNTIME_SHA, "CIRCL_BUILD_RUNTIME_EDGE")
    seen = {"openssl": set(), "cloudflare-circl": set()}
    for inv in runtime["invocations"]:
        impl = inv["implementation"]
        need(impl in seen, "RUNTIME_IMPLEMENTATION")
        seen[impl].add(inv["invocation_id"])
        source = OPENSSL_SOURCE if impl == "openssl" else CIRCL_SOURCE
        runtime_sha = OPENSSL_RUNTIME_SHA if impl == "openssl" else CIRCL_RUNTIME_SHA
        need(inv["implementation_source_authority"] == {
            "repository": source["repository"], "commit": source["commit"], "tree": source["tree"]
        }, "RUNTIME_SOURCE_AUTHORITY:" + impl)
        need(inv["resolved_executable_sha256"] == runtime_sha, "RUNTIME_EXECUTABLE_SHA:" + impl)
        need(inv["workflow_identity"]["sha256"] == EXPECTED_EVIDENCE["workflow"][1], "RUNTIME_WORKFLOW_SHA:" + impl)
        need(inv["process_started"] is True, "RUNTIME_PROCESS_STARTED:" + impl)
        need(inv["result_state"] == "process_exit_success", "RUNTIME_RESULT_STATE:" + impl)
    expected_ids = {
        "openssl": {"openssl-" + cid for cid in CASE_SHA},
        "cloudflare-circl": {"cloudflare-circl-" + cid for cid in CASE_SHA},
    }
    need(seen == expected_ids, "RUNTIME_INVOCATION_IDS")

def check_successor_consumer(c, impl):
    source = OPENSSL_SOURCE if impl == "openssl" else CIRCL_SOURCE
    runtime_sha = OPENSSL_RUNTIME_SHA if impl == "openssl" else CIRCL_RUNTIME_SHA
    consumer_evidence = EXPECTED_EVIDENCE["openssl_consumer"] if impl == "openssl" else EXPECTED_EVIDENCE["circl_consumer"]
    need(c["consumer_authority"] == {"path":consumer_evidence[0],"sha256":consumer_evidence[1]}, "SUCCESSOR_CONSUMER_AUTHORITY:" + impl)
    need(c["source_identity"] == source, "SUCCESSOR_SOURCE:" + impl)
    need(c["runtime_identity"]["executable_sha256"] == runtime_sha, "SUCCESSOR_RUNTIME:" + impl)
    need(c["runtime_identity"]["historical_invocation_count"] == 6, "SUCCESSOR_INVOCATION_COUNT:" + impl)
    build = c["historical_build_event"]
    need(build["github_run_id"] == 34968252038, "SUCCESSOR_RUN_ID:" + impl)
    need(build["github_job_id"] == 104377847614, "SUCCESSOR_JOB_ID:" + impl)
    need(build["github_run_attempt"] == 1, "SUCCESSOR_RUN_ATTEMPT:" + impl)
    need(build["workflow"] == {"path":EXPECTED_EVIDENCE["workflow"][0],"sha256":EXPECTED_EVIDENCE["workflow"][1]}, "SUCCESSOR_WORKFLOW:" + impl)
    need(build["source_checkout_exact"] is True, "SUCCESSOR_SOURCE_CHECKOUT:" + impl)
    expected_recipe = (
        "OPENSSL_CONFIGURE_LINUX_X86_64_NO_SHARED_MAKE_J2_INSTALL_SW_CC_STATIC_LIBCRYPTO"
        if impl == "openssl"
        else "CIRCL_EXACT_SOURCE_GO_BUILD_MOD_READONLY_TRIMPATH_GOTOOLCHAIN_LOCAL"
    )
    need(build["build_recipe_identity"] == expected_recipe, "SUCCESSOR_BUILD_RECIPE:" + impl)
    need(build["produced_artifacts"]["runtime_executable_sha256"] == runtime_sha, "SUCCESSOR_BUILD_RUNTIME_EDGE:" + impl)
    prov = c["source_to_runtime_provenance"]
    need(prov["level"] == "LEVEL_3_BUILD_EVENT_EVIDENCED", "SUCCESSOR_LEVEL:" + impl)
    need(prov["status"] == "HISTORICAL_BUILD_EVENT_EVIDENCED", "SUCCESSOR_STATUS:" + impl)
    need(prov["predecessor_consumer_status"] == "incomplete", "SUCCESSOR_PREDECESSOR_STATUS:" + impl)
    need(prov["historical_and_prospective_runtime_identity_separate"] is True, "SUCCESSOR_HISTORY_SEPARATION:" + impl)
    need(prov["reproducible_build_proven"] is False, "SUCCESSOR_REPRODUCIBLE_BOUNDARY:" + impl)
    need(prov["independent_rebuild_proven"] is False, "SUCCESSOR_INDEPENDENT_BOUNDARY:" + impl)
    need(prov["complete_environment_provenance"] is False, "SUCCESSOR_ENVIRONMENT_BOUNDARY:" + impl)
    if impl == "openssl":
        need(build["produced_artifacts"]["openssl_built_binary_sha256"] == "15e2531a6cc982ba7c6d08f1cea086d4f8a132566519a5efefa1e256ea4aad6d", "SUCCESSOR_OPENSSL_BINARY")
        need(build["produced_artifacts"]["openssl_built_libcrypto_sha256"] == "e1694ccaacbd51548a0f1a135d27d67acb642338b4b175d3276a1d1e8f7495a6", "SUCCESSOR_OPENSSL_LIBCRYPTO")
        need(build["toolchain_evidence"]["status"] == "PARTIAL", "SUCCESSOR_OPENSSL_TOOLCHAIN_STATUS")
    else:
        tool = build["toolchain_evidence"]
        need(tool["status"] == "PINNED_GO_ARCHIVE_PARTIAL_ENVIRONMENT", "SUCCESSOR_CIRCL_TOOLCHAIN_STATUS")
        need(tool["go_version"] == "go1.26.5", "SUCCESSOR_CIRCL_GO_VERSION")
        need(tool["go_archive_sha256"] == "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053", "SUCCESSOR_CIRCL_GO_ARCHIVE")
        need(tool["go_mod_sha256"] == "79b9daccc7f033377bcbc70524418d999a1677849924d7b5e488e646c4cf00d7", "SUCCESSOR_CIRCL_GO_MOD")
        need(tool["go_sum_sha256"] == "3d75d69d3b553e9aa69e1278de681b8dc55c28c6e4233bb398c5b7373c3abd0a", "SUCCESSOR_CIRCL_GO_SUM")
        need(tool["go_mod_sum_unchanged_after_build"] is True, "SUCCESSOR_CIRCL_GO_MOD_SUM")

def check_normalized_source_binding(consumers):
    old = read_json(EXPECTED_EVIDENCE["normalized_result_source_binding"][0])
    need(old["summary"]["binding_count"] == 12, "OLD_BINDING_COUNT")
    need(old["summary"]["source_to_runtime_proven_consumer_count"] == 0, "OLD_PROVEN_COUNT")
    need(old["summary"]["source_to_runtime_incomplete_consumer_count"] == 2, "OLD_INCOMPLETE_COUNT")
    need(old["claim_boundary"]["source_to_runtime_provenance_complete"] is False, "OLD_PROVENANCE_BOUNDARY")
    observed = {"openssl": {}, "cloudflare-circl": {}}
    for b in old["bindings"]:
        impl = b["implementation_id"]
        case_id = b["normalized_record"]["selector"]["case_id"]
        need(b["consumer_snapshot"]["source_to_runtime_binding"]["status"] == "incomplete", "OLD_BINDING_STATUS")
        observed[impl][case_id] = {
            "canonical_sha256": b["normalized_record"]["canonical_sha256"],
            "runtime_sha256": b["normalized_record"]["resolved_executable_sha256"],
            "source_bound_case_sha256": b["source_bound_case"]["sha256"],
        }
    for impl, c in consumers.items():
        need(set(observed[impl]) == set(CASE_SHA), "OLD_CASE_SET:" + impl)
        runtime_sha = OPENSSL_RUNTIME_SHA if impl == "openssl" else CIRCL_RUNTIME_SHA
        for item in c["normalized_result_bindings"]:
            cid = item["case_id"]
            need(item["canonical_sha256"] == CANONICAL[impl][cid], "CANONICAL_DECLARED:" + impl + ":" + cid)
            need(item["source_bound_case_sha256"] == CASE_SHA[cid], "SOURCE_BOUND_DECLARED:" + impl + ":" + cid)
            need(observed[impl][cid]["canonical_sha256"] == item["canonical_sha256"], "CANONICAL_CROSS_BIND:" + impl + ":" + cid)
            need(observed[impl][cid]["source_bound_case_sha256"] == item["source_bound_case_sha256"], "SOURCE_BOUND_CROSS_BIND:" + impl + ":" + cid)
            need(observed[impl][cid]["runtime_sha256"] == runtime_sha, "RUNTIME_CROSS_BIND:" + impl + ":" + cid)

def main():
    print("===== QSV ML-DSA CONSUMER SOURCE-TO-RUNTIME PROVENANCE VERIFIER V0.1 =====")
    print("VERIFICATION_MODE=READ_ONLY")
    print("NETWORK_REQUIRED=NO")
    print("BUILD_EXECUTION_PERFORMED=NO")
    print("CRYPTO_EXECUTION_PERFORMED=NO")

    check_predecessor_dag()
    for _, (rel, digest) in EXPECTED_EVIDENCE.items():
        predecessor_file_three_layer(rel, digest)

    check_sidecar(CONTRACT_REL)
    check_sidecar(MANIFEST_REL)
    check_sidecar(SELF_REL)

    schema = read_json(SCHEMA_REL)
    contract = read_json(CONTRACT_REL)
    manifest = read_json(MANIFEST_REL)
    schema_sha = sha256_path(regular_file(SCHEMA_REL))
    contract_sha = sha256_path(regular_file(CONTRACT_REL))

    need(schema["$schema"] == "https://json-schema.org/draft/2020-12/schema", "SCHEMA_DRAFT")
    need(schema["additionalProperties"] is False, "SCHEMA_TOP_ADDITIONAL_PROPERTIES")
    validate_schema(manifest, schema, schema, "$")
    check_contract(contract, schema_sha)
    check_manifest(manifest, schema_sha, contract_sha)

    check_predecessor_consumer(EXPECTED_EVIDENCE["openssl_consumer"][0], "openssl", OPENSSL_SOURCE, OPENSSL_RUNTIME_SHA)
    check_predecessor_consumer(EXPECTED_EVIDENCE["circl_consumer"][0], "cloudflare-circl", CIRCL_SOURCE, CIRCL_RUNTIME_SHA)
    check_lineage()
    check_workflow(contract)
    check_runtime_evidence()

    consumers = consumer_map(manifest)
    check_successor_consumer(consumers["openssl"], "openssl")
    check_successor_consumer(consumers["cloudflare-circl"], "cloudflare-circl")
    check_normalized_source_binding(consumers)

    print("PREDECESSOR_THREE_LAYER_TRUST=PASS")
    print("OPENSSL_SOURCE_IDENTITY=PASS")
    print("OPENSSL_HISTORICAL_BUILD_EVENT=PASS")
    print("OPENSSL_BUILD_TO_RUNTIME_HASH_EDGE=PASS")
    print("OPENSSL_SOURCE_TO_RUNTIME_PROVENANCE_LEVEL=LEVEL_3_BUILD_EVENT_EVIDENCED")
    print("CIRCL_SOURCE_IDENTITY=PASS")
    print("CIRCL_HISTORICAL_BUILD_EVENT=PASS")
    print("CIRCL_BUILD_TO_RUNTIME_HASH_EDGE=PASS")
    print("CIRCL_SOURCE_TO_RUNTIME_PROVENANCE_LEVEL=LEVEL_3_BUILD_EVENT_EVIDENCED")
    print("NORMALIZED_RESULT_BINDING_COUNT=12")
    print("REQUIREMENT_E_STATUS=COMPLETE_AT_LEVEL_3_DEFINED_SIX_CASE_SCOPE")
    print("REPRODUCIBLE_BUILD_PROVEN=NO")
    print("INDEPENDENT_REPRODUCIBLE_BUILD_PROVEN=NO")
    print("COMPLETE_ENVIRONMENT_PROVENANCE=NO")
    print("ADAPTER_WIRING_IMPLEMENTED=NO")
    print("FULL_F7_SOURCE_BOUND_COVERAGE=NO")
    print("NIST_VALIDATION=NO")
    print("FIPS_204_CERTIFICATION=NO")
    print("THIRD_PARTY_INDEPENDENT_CRYPTO_REPRODUCTION=NO")
    print("CONSUMER_SOURCE_TO_RUNTIME_PROVENANCE_VERIFICATION=PASS")

if __name__ == "__main__":
    try:
        main()
    except Reject as exc:
        print("CONSUMER_SOURCE_TO_RUNTIME_PROVENANCE_VERIFICATION=FAIL")
        print("CONTROLLED_REJECT=" + str(exc))
        raise SystemExit(1)
