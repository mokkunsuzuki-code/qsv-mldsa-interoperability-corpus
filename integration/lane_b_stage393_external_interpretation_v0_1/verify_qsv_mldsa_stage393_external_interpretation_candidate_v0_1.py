#!/usr/bin/env python3

import hashlib
import json
import os
import subprocess
from pathlib import Path


CANDIDATE = Path(__file__).resolve().parent

LIVE_ROOT = (
    Path.home()
    / "Desktop/test/qsv-mldsa-interoperability-corpus-development"
)

EVIDENCE_NAME = (
    "qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json"
)

MANIFEST_NAME = (
    "qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json"
)

SELF_NAME = (
    "verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py"
)

EXPECTED_EVIDENCE_SHA256 = (
    "8fbd24c8253fca511f1fe12b94b85c92e8f23d9aeb7b46ff21e8b8fed9437d55"
)

EXPECTED_MANIFEST_SHA256 = (
    "e9b79df51996114dde54676464af4ae5906e77e8c351fb3ea240be0e27b16700"
)

EXPECTED_QSV_HEAD = (
    "9147de5e27a2764a95d7ef296b24b8c5bf235286"
)

EXPECTED_QSV_TREE = (
    "ee64d8091cbe9b0b811b5310b1f58788142da70d"
)

EXPECTED_FREEZE_SHA256 = (
    "dd89fd8ee3c124d7fcc314ca1db61ad9bccd6f1c32fa3201f521a6ac50412015"
)

EXPECTED_RATIONALE_FILE_SHA256 = (
    "fc1d7fd3ccb955be09d7a0545a300675f2cbd8673c7f90919b8add60f73bd1ac"
)

EXPECTED_RATIONALE_GIT_BLOB = (
    "0fcf450ef30cfc167775f1c938a20f2f027cf9ca"
)

EXPECTED_STAGE393_EXECUTION_CIRCL_COMMIT = (
    "cfa7c70defd831ffb0792ab2af560bfef43d60ca"
)

EXPECTED_RATIONALE_CIRCL_COMMIT = (
    "352600b0a4b2380815cef55fc690c65049c7e56b"
)

EXPECTED_WYCHEPROOF_COMMIT = (
    "dac1dd4729fd1f8dd9e1e9f3dce51d783da6c166"
)

EXPECTED_STATEMENT = (
    "These are deliberate choices of each implementation."
)

EXPECTED_REFERENCE_BODY = (
    "[here](https://github.com/cloudflare/circl/blob/main/"
    "sign/schemes/wycheproof_test.go#L135-L137)"
)

EXPECTED_COMMENT_LINES = [
    "TODO The standards don't require rejecting private keys",
    "with out of range s1/s2. Pending discussion on whether",
    "we should reject them, we're skipping these testcases.",
]

EXPECTED_SIX_CASES = {
    (
        "QSV-MLDSA-WYCHEPROOF-44-0052",
        "ML-DSA-44",
        52,
        "testvectors_v1/mldsa_44_sign_noseed_test.json",
        "ee55e18b1944db496b2539d3884dfacc04a96db21bcec239063df5e4cd1ee6cb",
    ),
    (
        "QSV-MLDSA-WYCHEPROOF-44-0053",
        "ML-DSA-44",
        53,
        "testvectors_v1/mldsa_44_sign_noseed_test.json",
        "ee55e18b1944db496b2539d3884dfacc04a96db21bcec239063df5e4cd1ee6cb",
    ),
    (
        "QSV-MLDSA-WYCHEPROOF-65-0056",
        "ML-DSA-65",
        56,
        "testvectors_v1/mldsa_65_sign_noseed_test.json",
        "8587a53e7e3ca20b006b661316b89c762acdecf3fa902746b01cbc09fe14130d",
    ),
    (
        "QSV-MLDSA-WYCHEPROOF-65-0057",
        "ML-DSA-65",
        57,
        "testvectors_v1/mldsa_65_sign_noseed_test.json",
        "8587a53e7e3ca20b006b661316b89c762acdecf3fa902746b01cbc09fe14130d",
    ),
    (
        "QSV-MLDSA-WYCHEPROOF-87-0047",
        "ML-DSA-87",
        47,
        "testvectors_v1/mldsa_87_sign_noseed_test.json",
        "bd4c997f1fb90d985dbcca9a5ab52cef1f5c22d2cc0ba332d8dbe68703a5b40d",
    ),
    (
        "QSV-MLDSA-WYCHEPROOF-87-0048",
        "ML-DSA-87",
        48,
        "testvectors_v1/mldsa_87_sign_noseed_test.json",
        "bd4c997f1fb90d985dbcca9a5ab52cef1f5c22d2cc0ba332d8dbe68703a5b40d",
    ),
}

checks = 0
failures = []


def check(name, condition):
    global checks

    checks += 1

    if not condition:
        failures.append(name)


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def git(*args):
    return subprocess.check_output(
        ["git", "-C", str(LIVE_ROOT), *args],
        text=True,
    ).strip()


# ------------------------------------------------------------
# Execution boundary
# ------------------------------------------------------------

check(
    "QSV_EXECUTE_CRYPTO absent",
    os.environ.get("QSV_EXECUTE_CRYPTO") is None,
)


# ------------------------------------------------------------
# Exact candidate file set
# ------------------------------------------------------------

expected_candidate_files = {
    EVIDENCE_NAME,
    EVIDENCE_NAME + ".sha256",
    MANIFEST_NAME,
    MANIFEST_NAME + ".sha256",
    SELF_NAME,
    SELF_NAME + ".sha256",
}

actual_candidate_files = {
    p.name
    for p in CANDIDATE.iterdir()
    if p.is_file()
}

check(
    "exact six-file isolated candidate set",
    actual_candidate_files == expected_candidate_files,
)


# ------------------------------------------------------------
# Evidence + manifest hashes / sidecars
# ------------------------------------------------------------

evidence_path = CANDIDATE / EVIDENCE_NAME
evidence_sidecar = CANDIDATE / (EVIDENCE_NAME + ".sha256")

manifest_path = CANDIDATE / MANIFEST_NAME
manifest_sidecar = CANDIDATE / (MANIFEST_NAME + ".sha256")

self_path = CANDIDATE / SELF_NAME
self_sidecar = CANDIDATE / (SELF_NAME + ".sha256")

check(
    "evidence exists",
    evidence_path.is_file(),
)

check(
    "manifest exists",
    manifest_path.is_file(),
)

if evidence_path.is_file():
    check(
        "evidence SHA exact",
        sha256(evidence_path) == EXPECTED_EVIDENCE_SHA256,
    )

if manifest_path.is_file():
    check(
        "manifest SHA exact",
        sha256(manifest_path) == EXPECTED_MANIFEST_SHA256,
    )

if evidence_path.is_file() and evidence_sidecar.is_file():
    check(
        "evidence sidecar exact",
        evidence_sidecar.read_text(
            encoding="utf-8"
        )
        == (
            EXPECTED_EVIDENCE_SHA256
            + "  "
            + EVIDENCE_NAME
            + "\n"
        ),
    )
else:
    check(
        "evidence sidecar exists",
        False,
    )

if manifest_path.is_file() and manifest_sidecar.is_file():
    check(
        "manifest sidecar exact",
        manifest_sidecar.read_text(
            encoding="utf-8"
        )
        == (
            EXPECTED_MANIFEST_SHA256
            + "  "
            + MANIFEST_NAME
            + "\n"
        ),
    )
else:
    check(
        "manifest sidecar exists",
        False,
    )

if self_path.is_file() and self_sidecar.is_file():
    self_sha = sha256(self_path)

    check(
        "verifier self sidecar exact",
        self_sidecar.read_text(
            encoding="utf-8"
        )
        == (
            self_sha
            + "  "
            + SELF_NAME
            + "\n"
        ),
    )
else:
    check(
        "verifier self sidecar exists",
        False,
    )


# ------------------------------------------------------------
# Evidence semantics
# ------------------------------------------------------------

evidence = load_json(evidence_path)

check(
    "evidence type exact",
    evidence["evidence_type"]
    == "external_interpretation_with_source_code_policy_reference",
)

external = evidence["external_interpretation"]

check(
    "source repository exact",
    external["source_repository"] == "cloudflare/circl",
)

check(
    "issue exact",
    external["source_issue_number"] == 691,
)

check(
    "interpretation comment exact",
    external["interpretation_comment_id"] == 5570219154,
)

check(
    "source actor exact",
    external["source_actor"] == "bwesterb",
)

check(
    "source actor role not asserted",
    external["source_actor_role_asserted"] is False,
)

check(
    "external statement exact",
    external["statement_exact"] == EXPECTED_STATEMENT,
)

check(
    "external statement preserved verbatim",
    external["statement_preserved_verbatim"] is True,
)

check(
    "external interpretation classification exact",
    external["statement_interpretation"]
    == "deliberate_implementation_choice",
)

source = evidence["source_code_rationale"]

check(
    "source reference comment ID exact",
    source["reference_comment_id"] == 5571477664,
)

check(
    "source reference body exact",
    source["reference_comment_body_exact"]
    == EXPECTED_REFERENCE_BODY,
)

check(
    "mutable main identified",
    source["reference_original_url_uses_mutable_main"] is True,
)

check(
    "mutable main not authority",
    source["mutable_main_url_used_as_authority"] is False,
)

check(
    "fixed repository exact",
    source["fixed_repository"] == "cloudflare/circl",
)

check(
    "fixed rationale commit exact",
    source["fixed_commit"] == EXPECTED_RATIONALE_CIRCL_COMMIT,
)

check(
    "fixed source path exact",
    source["fixed_path"] == "sign/schemes/wycheproof_test.go",
)

check(
    "fixed function exact",
    source["fixed_function"] == "runSignGroup",
)

check(
    "Git blob exact",
    source["fixed_git_blob_sha"] == EXPECTED_RATIONALE_GIT_BLOB,
)

check(
    "fixed file SHA256 exact",
    source["fixed_file_sha256"] == EXPECTED_RATIONALE_FILE_SHA256,
)

check(
    "policy flag exact",
    source["policy_flag"] == "InvalidPrivateKey",
)

check(
    "policy action exact",
    source["policy_action"] == "skip",
)

check(
    "policy continue exact",
    source["policy_control_flow"] == "continue",
)

check(
    "inline rationale comment present",
    source["inline_rationale_comment_present"] is True,
)

check(
    "inline rationale exact lines",
    source["inline_rationale_comment_exact_lines"]
    == EXPECTED_COMMENT_LINES,
)

check(
    "test policy rationale documented",
    source["test_policy_rationale_documented"] is True,
)

check(
    "runtime root cause not fully traced",
    source["runtime_acceptance_root_cause_fully_traced"] is False,
)


# ------------------------------------------------------------
# Execution revision separation
# ------------------------------------------------------------

separation = evidence["execution_revision_separation"]

check(
    "Stage393 execution CIRCL commit exact",
    separation["stage393_execution_circl_commit"]
    == EXPECTED_STAGE393_EXECUTION_CIRCL_COMMIT,
)

check(
    "rationale commit exact in separation",
    separation["rationale_source_circl_commit"]
    == EXPECTED_RATIONALE_CIRCL_COMMIT,
)

check(
    "execution/rationale revisions differ",
    separation["rationale_source_same_as_stage393_execution_commit"]
    is False,
)

check(
    "no claim executed source contained rationale",
    separation[
        "stage393_executed_source_contained_this_rationale_claim"
    ] is False,
)

check(
    "historical observation unmodified",
    separation["historical_execution_observation_modified"] is False,
)


# ------------------------------------------------------------
# Six CIRCL-side case linkage
# ------------------------------------------------------------

wp = evidence["wycheproof_authority"]

check(
    "Wycheproof commit exact",
    wp["commit"] == EXPECTED_WYCHEPROOF_COMMIT,
)

check(
    "six CIRCL-side cases",
    wp["circl_side_case_count"] == 6,
)

check(
    "all six identities resolved",
    wp["all_six_case_identities_resolved"] is True,
)

check(
    "all six invalid",
    wp["all_six_results_invalid"] is True,
)

check(
    "all six InvalidPrivateKey",
    wp["all_six_cases_flagged_invalid_private_key"] is True,
)

check(
    "all six match referenced policy",
    wp["all_six_cases_match_referenced_skip_policy"] is True,
)

case_linkage = evidence["case_linkage"]

observed_six = {
    (
        case["neutral_case_id"],
        case["parameter_set"],
        case["tcId"],
        case["source_fixture"],
        case["source_fixture_sha256"],
    )
    for case in case_linkage
}

check(
    "six exact case records",
    len(case_linkage) == 6,
)

check(
    "six exact case identities and fixture hashes",
    observed_six == EXPECTED_SIX_CASES,
)

check(
    "all six case results invalid",
    all(
        case["result"] == "invalid"
        for case in case_linkage
    ),
)

check(
    "all six case flags exact",
    all(
        case["flags"] == ["InvalidPrivateKey"]
        for case in case_linkage
    ),
)


# ------------------------------------------------------------
# Non-claims / boundaries
# ------------------------------------------------------------

boundary = evidence["interpretation_boundary"]

check(
    "root cause unknown",
    boundary["root_cause"] == "unknown",
)

check(
    "root cause incomplete",
    boundary["root_cause_classification_complete"] is False,
)

check(
    "runtime root cause incomplete boundary",
    boundary["circl_runtime_acceptance_root_cause_fully_traced"] is False,
)

check(
    "OpenSSL primary confirmation absent",
    evidence["scope_boundary"]["openssl_project_primary_confirmation_present"] is False,
)

check(
    "not formal adjudication",
    boundary["formal_adjudication"] is False,
)

check(
    "not formal certification",
    boundary["formal_certification"] is False,
)

check(
    "no confirmed FIPS204 nonconformance",
    boundary["confirmed_fips204_nonconformance"] is False,
)

check(
    "no confirmed implementation bug",
    boundary["confirmed_implementation_bug"] is False,
)

check(
    "no confirmed security vulnerability",
    boundary["confirmed_security_vulnerability"] is False,
)

check(
    "no CIRCL endorsement",
    boundary["qsv_endorsement_by_circl"] is False,
)

check(
    "no Cloudflare endorsement",
    boundary["qsv_endorsement_by_cloudflare"] is False,
)


# ------------------------------------------------------------
# Manifest binding
# ------------------------------------------------------------

manifest = load_json(manifest_path)

evidence_summary = manifest["evidence_summary"]

check(
    "manifest Stage393 nine-case count exact",
    evidence_summary["stage393_ninecase_count"] == 9,
)

check(
    "manifest CIRCL expectation-difference count exact",
    evidence_summary["circl_expectation_difference_count"] == 6,
)

check(
    "manifest OpenSSL expectation-difference count exact",
    evidence_summary["openssl_expectation_difference_count"] == 3,
)

check(
    "manifest 6 plus 3 equals nine-case total",
    (
        evidence_summary["circl_expectation_difference_count"]
        + evidence_summary["openssl_expectation_difference_count"]
        == evidence_summary["stage393_ninecase_count"]
        == 9
    ),
)

check(
    "manifest schema exact",
    manifest["schema"]
    == "qsv.mldsa.stage393.external-interpretation-candidate-manifest.v0.1",
)

check(
    "manifest lane exact",
    manifest["candidate_scope"]["lane"]
    == "stage393_circl_ninecase_evidence_lane",
)

check(
    "OQS lane excluded",
    manifest["candidate_scope"]["oqs_lane_included"] is False,
)

check(
    "root verifier v0.2 absent from candidate scope",
    manifest["candidate_scope"]["root_verifier_v0_2_created"] is False,
)

check(
    "manifest QSV HEAD exact",
    manifest["source_qsv_authority"]["repository_head"]
    == EXPECTED_QSV_HEAD,
)

check(
    "manifest QSV TREE exact",
    manifest["source_qsv_authority"]["repository_tree"]
    == EXPECTED_QSV_TREE,
)

static_ref = manifest["stage393_static_candidate_reference"]

check(
    "manifest twelve-file count",
    static_ref["file_count"] == 12,
)

check(
    "manifest freeze SHA exact",
    static_ref["freeze_input_canonical_sha256"]
    == EXPECTED_FREEZE_SHA256,
)

check(
    "live files not copied",
    static_ref["files_copied_into_isolated_candidate"] is False,
)

check(
    "manifest evidence SHA exact",
    manifest["external_interpretation_artifact"]["sha256"]
    == EXPECTED_EVIDENCE_SHA256,
)

check(
    "manifest evidence sidecar hash matches actual",
    manifest["external_interpretation_artifact"]["sidecar_sha256"]
    == sha256(evidence_sidecar),
)


# ------------------------------------------------------------
# Verify referenced 12 live files exactly
# ------------------------------------------------------------

live_records = static_ref["files"]

check(
    "manifest 12 records exact count",
    len(live_records) == 12,
)

live_hashes_ok = True

for record in live_records:
    path = LIVE_ROOT / record["path"]

    if (
        not path.is_file()
        or sha256(path) != record["sha256"]
    ):
        live_hashes_ok = False

check(
    "all 12 live referenced file hashes match",
    live_hashes_ok,
)


# ------------------------------------------------------------
# Live repository authority and existing Stage393 verifier
# ------------------------------------------------------------

frozen_qsv_tree_resolves = False

try:
    frozen_qsv_tree_resolves = (
        git(
            "rev-parse",
            EXPECTED_QSV_HEAD + "^{tree}",
        )
        == EXPECTED_QSV_TREE
    )
except subprocess.CalledProcessError:
    frozen_qsv_tree_resolves = False

check(
    "frozen QSV HEAD/TREE provenance resolves",
    frozen_qsv_tree_resolves,
)

current_live_head = git(
    "rev-parse",
    "HEAD",
)

frozen_head_is_ancestor = (
    subprocess.run(
        [
            "git",
            "-C",
            str(LIVE_ROOT),
            "merge-base",
            "--is-ancestor",
            EXPECTED_QSV_HEAD,
            current_live_head,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode
    == 0
)

check(
    "frozen QSV HEAD is ancestor of current live HEAD",
    frozen_head_is_ancestor,
)

tracked_diff = subprocess.check_output(
    ["git", "-C", str(LIVE_ROOT), "diff", "--name-only"],
    text=True,
).splitlines()

staged = subprocess.check_output(
    ["git", "-C", str(LIVE_ROOT), "diff", "--cached", "--name-only"],
    text=True,
).splitlines()

lane_b_referenced_paths = {
    record["path"]
    for record in live_records
}

lane_b_tracked_overlap = sorted(
    set(tracked_diff) & lane_b_referenced_paths
)

lane_b_staged_overlap = sorted(
    set(staged) & lane_b_referenced_paths
)

check(
    "Lane B referenced tracked worktree diff absent",
    not lane_b_tracked_overlap,
)

check(
    "Lane B referenced staged diff absent",
    not lane_b_staged_overlap,
)

check(
    "root verifier v0.2 absent",
    not (
        LIVE_ROOT
        / "verify_qsv_mldsa_corpus_v0_2.py"
    ).exists(),
)

env = os.environ.copy()
env.pop("QSV_EXECUTE_CRYPTO", None)

stage393_verifier = (
    LIVE_ROOT
    / "verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py"
)

proc = subprocess.run(
    [
        "python3",
        str(stage393_verifier),
    ],
    cwd=str(LIVE_ROOT),
    env=env,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

check(
    "existing Stage393 static verifier exit zero",
    proc.returncode == 0,
)

check(
    "existing Stage393 static verifier PASS marker",
    "QSV_MLDSA_STAGE393_NINECASE_STATIC_INTEGRATION=PASS"
    in proc.stdout,
)

check(
    "existing Stage393 nine-case count marker",
    "IMPORTED_STAGE393_DIFFERENCE_CASE_COUNT=9"
    in proc.stdout,
)


# ------------------------------------------------------------
# Final decision
# ------------------------------------------------------------

if failures:
    print(
        "QSV_MLDSA_STAGE393_EXTERNAL_INTERPRETATION_CANDIDATE=FAIL"
    )
    print("CHECK_COUNT=" + str(checks))
    print("FAILURE_COUNT=" + str(len(failures)))

    for failure in failures:
        print("FAIL: " + failure)

    raise SystemExit(1)


print(
    "QSV_MLDSA_STAGE393_EXTERNAL_INTERPRETATION_CANDIDATE=PASS"
)

print("CHECK_COUNT=" + str(checks))
print("FAILURE_COUNT=0")

print("STAGE393_NINECASE_STATIC_LAYER_PRESERVED=YES")
print("STAGE393_NINECASE_COUNT=9")

print("CIRCL_EXPECTATION_DIFFERENCE_COUNT=6")
print("OPENSSL_EXPECTATION_DIFFERENCE_COUNT=3")

print("EXTERNAL_INTERPRETATION_RECORD_COUNT=1")
print("EXACT_EXTERNAL_STATEMENT_PRESERVED=YES")

print("CIRCL_SOURCE_CODE_POLICY_REFERENCE_PRESENT=YES")
print("CIRCL_TEST_POLICY_RATIONALE_DOCUMENTED=YES")
print("ALL_SIX_CASES_MATCH_DOCUMENTED_TEST_POLICY=YES")

print("CIRCL_RUNTIME_ACCEPTANCE_ROOT_CAUSE_FULLY_TRACED=NO")

print("OPENSSL_PROJECT_PRIMARY_CONFIRMATION_PRESENT=NO")

print("ROOT_CAUSE_CLASSIFICATION_COMPLETE=NO")
print("ROOT_CAUSE_DEFAULT=unknown")

print("FORMAL_ADJUDICATION=NO")
print("FORMAL_CERTIFICATION=NO")

print("CONFIRMED_FIPS204_NONCONFORMANCE=NO")
print("CONFIRMED_IMPLEMENTATION_BUG=NO")
print("CONFIRMED_SECURITY_VULNERABILITY=NO")

print("QSV_ENDORSEMENT_BY_CIRCL=NO")
print("QSV_ENDORSEMENT_BY_CLOUDFLARE=NO")

print("CRYPTOGRAPHIC_REEXECUTION_PERFORMED=NO")
print("NEW_QSV_CRYPTOGRAPHIC_EXECUTION=NO")

print("ROOT_VERIFIER_V0_2_CREATED=NO")
print("OQS_LANE_TOUCHED=NO")
