#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

AUTH_REL = "remediation/qsv_mldsa_workflow_configuration_remediation_authority_v0_1.json"
AUTH_SC_REL = AUTH_REL + ".sha256"
VERIFIER_REL = "remediation/verify_qsv_mldsa_workflow_configuration_remediation_v0_1.py"
VERIFIER_SC_REL = VERIFIER_REL + ".sha256"

SCHEMA = "qsv.mldsa.workflow-configuration-remediation-authority.v0.1"
DECISION = "historical_invalid_workflow_retired_from_active_actions"
REPOSITORY = "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus"

FROZEN_COMMIT = "05a0de455166bf2aa2f6696634d251339319066e"
FROZEN_TREE = "2a0dba64a1dda7addfa3bde740809a294a3a7f16"
FROZEN_FILE_COUNT = 90
ROOT_FINALIZATION_SHA256 = "1c9a3b57168f55696cce80a256180ee849b1766b71815389058d2d3096f99d11"

V02_ACTIVE = ".github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml"
V02_ACTIVE_SC = V02_ACTIVE + ".sha256"
V02_HIST = "historical/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml"
V02_HIST_SC = V02_HIST + ".sha256"
V02_SHA256 = "0351a06ab03e2ff27669f00e30e5e7647bcd54af20c6e905ba2e607233e035b9"
V02_SIDECAR_SHA256 = "8f7c07b069f486c75876de9eda7ace947a64ec22084204b1485179b79ca3ce9b"
V02_INTRO = "970bf929f32a25ca0648fb01f5378bdbfa8eba55"

V03_ACTIVE = ".github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml"
V03_SHA256 = "f4197f42e2ed6a76c66b12d9f10c069b2d1ef5d7f3653d46a3b80858c858cdc0"
V03_INTRO = "30e72a48f528ad350daec65bbc74da44eabd87d6"

MISINDENT_KEYS = [
    "GO_LINUX_AMD64_ARCHIVE",
    "GO_LINUX_AMD64_URL",
    "GO_LINUX_AMD64_SHA256",
    "PREVIOUS_FAILED_PRECHECK_RUN_ID",
    "PREVIOUS_FAILED_PRECHECK_RUN_LOG_SHA256",
]

ACTIVE_FINAL = [
    {
        "path": ".github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml",
        "sha256": "3b488f00990c11a796faa7638d39b5aa12874c3e21c9459aa264c77d6315ea16",
        "sidecar_sha256": "59aa85f6714da88735a7907c30024d40193973db07e3f9bd4dbcbd9ae4715ddc",
    },
    {
        "path": V03_ACTIVE,
        "sha256": V03_SHA256,
        "sidecar_sha256": "596ed58fcf00c1a4c2f9d0424027fb4c210acc95e7f59a62ec7d62ee0c59057c",
    },
    {
        "path": ".github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml",
        "sha256": "123d31afd0e2eaa6deba5ab42a90b040c452d08f72eb61e23db4b3dc1c7c8c52",
        "sidecar_sha256": "1b639eb1c35a6c67f66b3c3ab0e6641cd7d35f2d2994ba0563884b6d349c0eae",
    },
]

checks = 0
failures = []


def check(name, condition):
    global checks
    checks += 1
    ok = bool(condition)
    print(("PASS: " if ok else "FAIL: ") + name)
    if not ok:
        failures.append(name)
    return ok


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read_bytes(path):
    return path.read_bytes()


def is_regular_nonsymlink(path):
    return path.is_file() and not path.is_symlink()


def git_bytes(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "git command failed: "
            + " ".join(args)
            + ": "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    return result.stdout


def git_text(root, *args):
    return git_bytes(root, *args).decode("utf-8").strip()


def verify_exact_sidecar(root, rel, declared_sha, declared_path):
    path = root / rel
    expected = f"{declared_sha}  {declared_path}\n".encode("utf-8")
    return is_regular_nonsymlink(path) and read_bytes(path) == expected


def verify_active_entry(root, item):
    wf_rel = item["path"]
    sc_rel = wf_rel + ".sha256"
    wf = root / wf_rel
    sc = root / sc_rel

    check(
        f"active workflow regular non-symlink: {wf_rel}",
        is_regular_nonsymlink(wf),
    )
    check(
        f"active sidecar regular non-symlink: {sc_rel}",
        is_regular_nonsymlink(sc),
    )

    if is_regular_nonsymlink(wf):
        check(
            f"active workflow SHA-256: {wf_rel}",
            sha256_bytes(read_bytes(wf)) == item["sha256"],
        )

    if is_regular_nonsymlink(sc):
        check(
            f"active sidecar file SHA-256: {sc_rel}",
            sha256_bytes(read_bytes(sc)) == item["sidecar_sha256"],
        )
        check(
            f"active sidecar exact declaration: {sc_rel}",
            verify_exact_sidecar(root, sc_rel, item["sha256"], wf_rel),
        )


def active_workflow_paths(root):
    workflow_dir = root / ".github" / "workflows"
    paths = set()

    if workflow_dir.is_dir():
        for pattern in ("*.yml", "*.yaml"):
            for path in workflow_dir.glob(pattern):
                if path.is_file() and not path.is_symlink():
                    paths.add(path.relative_to(root).as_posix())

    return paths


def historical_misindent_observation(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    observed = {}

    for key in MISINDENT_KEYS:
        matches = []

        for index, line in enumerate(lines, start=1):
            if line.lstrip().startswith(key + ":"):
                matches.append(
                    (
                        index,
                        len(line) - len(line.lstrip(" ")),
                    )
                )

        observed[key] = matches

    return observed


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--mode",
        choices=(
            "pre-retirement",
            "post-retirement",
        ),
        required=True,
    )

    parser.add_argument(
        "--root",
        default=None,
        help="repository root; defaults to parent of remediation directory",
    )

    args = parser.parse_args()

    root = (
        Path(args.root).resolve()
        if args.root
        else Path(__file__).resolve().parent.parent
    )

    print(f"REPOSITORY_ROOT={root}")
    print(f"VERIFICATION_MODE={args.mode}")

    check(
        "repository .git exists",
        (root / ".git").is_dir(),
    )

    auth = root / AUTH_REL
    auth_sc = root / AUTH_SC_REL
    verifier = root / VERIFIER_REL
    verifier_sc = root / VERIFIER_SC_REL

    check(
        "authority regular non-symlink",
        is_regular_nonsymlink(auth),
    )
    check(
        "authority sidecar regular non-symlink",
        is_regular_nonsymlink(auth_sc),
    )
    check(
        "verifier regular non-symlink",
        is_regular_nonsymlink(verifier),
    )
    check(
        "verifier sidecar regular non-symlink",
        is_regular_nonsymlink(verifier_sc),
    )

    if not is_regular_nonsymlink(auth):
        print(f"REMEDIATION_VERIFIER_CHECK_COUNT={checks}")
        print(
            "REMEDIATION_VERIFIER_FAILURE_COUNT="
            + str(len(failures))
        )
        return 1

    auth_bytes = read_bytes(auth)
    auth_sha = sha256_bytes(auth_bytes)

    check(
        "authority sidecar exact declaration",
        verify_exact_sidecar(
            root,
            AUTH_SC_REL,
            auth_sha,
            AUTH_REL,
        ),
    )

    if is_regular_nonsymlink(verifier):
        verifier_sha = sha256_bytes(
            read_bytes(verifier)
        )

        check(
            "verifier sidecar exact declaration",
            verify_exact_sidecar(
                root,
                VERIFIER_SC_REL,
                verifier_sha,
                VERIFIER_REL,
            ),
        )

    try:
        data = json.loads(
            auth_bytes.decode("utf-8")
        )
        parsed = True
    except Exception:
        data = {}
        parsed = False

    check(
        "authority JSON parsed",
        parsed,
    )

    expected_top = {
        "schema",
        "version",
        "decision",
        "repository",
        "authority_lifecycle",
        "frozen_parent_authority",
        "historical_invalid_workflow",
        "successor_workflow",
        "historical_github_run_observation",
        "active_workflow_set_after_remediation",
        "remediation_actions",
        "publication_time_audit",
        "authority_boundaries",
    }

    check(
        "authority exact top-level key set",
        set(data) == expected_top,
    )

    check(
        "schema exact",
        data.get("schema") == SCHEMA,
    )

    check(
        "version exact",
        data.get("version") == "0.1",
    )

    check(
        "decision exact",
        data.get("decision") == DECISION,
    )

    check(
        "repository exact",
        data.get("repository") == REPOSITORY,
    )

    lifecycle = data.get(
        "authority_lifecycle",
        {},
    )

    check(
        "lifecycle final-state declaration role",
        lifecycle.get("document_role")
        == "final_state_declaration_subject_to_post_retirement_verification",
    )

    check(
        "lifecycle created before retirement",
        lifecycle.get(
            "created_before_active_v0_2_retirement"
        )
        is True,
    )

    check(
        "lifecycle not effective at candidate creation",
        lifecycle.get(
            "effective_at_candidate_creation"
        )
        is False,
    )

    check(
        "lifecycle requires post-retirement verifier pass",
        lifecycle.get(
            "effective_only_when_post_retirement_verifier_passes"
        )
        is True,
    )

    frozen = data.get(
        "frozen_parent_authority",
        {},
    )

    check(
        "frozen parent repository exact",
        frozen.get("repository") == REPOSITORY,
    )

    check(
        "frozen parent commit exact",
        frozen.get("commit") == FROZEN_COMMIT,
    )

    check(
        "frozen parent tree exact",
        frozen.get("tree") == FROZEN_TREE,
    )

    check(
        "frozen parent file count authority exact",
        frozen.get("published_file_count")
        == FROZEN_FILE_COUNT,
    )

    check(
        "root v0.3 finalization authority SHA-256 exact",
        frozen.get(
            "root_v0_3_finalization_authority_sha256"
        )
        == ROOT_FINALIZATION_SHA256,
    )

    check(
        "root v0.3 exact-fileset-sensitive boundary",
        frozen.get(
            "root_v0_3_exact_fileset_sensitive"
        )
        is True,
    )

    check(
        "root v0.3 frozen snapshot-only boundary",
        frozen.get(
            "root_v0_3_remains_authority_for_frozen_snapshot_only"
        )
        is True,
    )

    try:
        actual_frozen_tree = git_text(
            root,
            "rev-parse",
            FROZEN_COMMIT + "^{tree}",
        )
        frozen_commit_available = True
    except Exception:
        actual_frozen_tree = ""
        frozen_commit_available = False

    check(
        "frozen parent commit available in Git history",
        frozen_commit_available,
    )

    check(
        "frozen parent Git tree exact",
        actual_frozen_tree == FROZEN_TREE,
    )

    hist = data.get(
        "historical_invalid_workflow",
        {},
    )

    check(
        "historical original active path exact",
        hist.get("original_active_path")
        == V02_ACTIVE,
    )

    check(
        "historical original sidecar path exact",
        hist.get("original_active_sidecar_path")
        == V02_ACTIVE_SC,
    )

    check(
        "historical archive path exact",
        hist.get("historical_path")
        == V02_HIST,
    )

    check(
        "historical archive sidecar path exact",
        hist.get("historical_sidecar_path")
        == V02_HIST_SC,
    )

    check(
        "historical workflow SHA-256 authority exact",
        hist.get("workflow_sha256")
        == V02_SHA256,
    )

    check(
        "historical sidecar SHA-256 authority exact",
        hist.get("sidecar_sha256")
        == V02_SIDECAR_SHA256,
    )

    check(
        "historical introduction commit exact",
        hist.get("introduction_commit")
        == V02_INTRO,
    )

    check(
        "historical YAML-valid authority false",
        hist.get("yaml_valid") is False,
    )

    check(
        "historical misindented key count authority",
        hist.get("misindented_env_key_count")
        == 5,
    )

    check(
        "historical misindented key list exact",
        hist.get("misindented_env_keys")
        == MISINDENT_KEYS,
    )

    check(
        "historical bytes preservation authority",
        hist.get(
            "historical_bytes_preserved_without_modification"
        )
        is True,
    )

    check(
        "historical sidecar preservation authority",
        hist.get(
            "historical_sidecar_bytes_preserved_without_rewrite"
        )
        is True,
    )

    hist_path = root / V02_HIST
    hist_sc_path = root / V02_HIST_SC

    check(
        "historical workflow regular non-symlink",
        is_regular_nonsymlink(hist_path),
    )

    check(
        "historical sidecar regular non-symlink",
        is_regular_nonsymlink(hist_sc_path),
    )

    if is_regular_nonsymlink(hist_path):
        check(
            "historical workflow SHA-256 exact",
            sha256_bytes(
                read_bytes(hist_path)
            )
            == V02_SHA256,
        )

        observed = (
            historical_misindent_observation(
                hist_path
            )
        )

        check(
            "historical five keys each occur exactly once",
            all(
                len(observed[key]) == 1
                for key in MISINDENT_KEYS
            ),
        )

        check(
            "historical five keys each remain two-space-indented",
            all(
                len(observed[key]) == 1
                and observed[key][0][1] == 2
                for key in MISINDENT_KEYS
            ),
        )

    if is_regular_nonsymlink(hist_sc_path):
        check(
            "historical sidecar file SHA-256 exact",
            sha256_bytes(
                read_bytes(hist_sc_path)
            )
            == V02_SIDECAR_SHA256,
        )

        check(
            "historical sidecar preserved original declaration bytes",
            verify_exact_sidecar(
                root,
                V02_HIST_SC,
                V02_SHA256,
                V02_ACTIVE,
            ),
        )

    try:
        frozen_v02 = git_bytes(
            root,
            "show",
            FROZEN_COMMIT + ":" + V02_ACTIVE,
        )

        frozen_v02_sc = git_bytes(
            root,
            "show",
            FROZEN_COMMIT + ":" + V02_ACTIVE_SC,
        )

        intro_v02 = git_bytes(
            root,
            "show",
            V02_INTRO + ":" + V02_ACTIVE,
        )

        intro_v02_sc = git_bytes(
            root,
            "show",
            V02_INTRO + ":" + V02_ACTIVE_SC,
        )

        git_history_readable = True
    except Exception:
        frozen_v02 = b""
        frozen_v02_sc = b""
        intro_v02 = b""
        intro_v02_sc = b""
        git_history_readable = False

    check(
        "historical Git blob sources readable",
        git_history_readable,
    )

    if git_history_readable:
        check(
            "frozen v0.2 blob SHA-256 exact",
            sha256_bytes(frozen_v02)
            == V02_SHA256,
        )

        check(
            "introduction v0.2 blob SHA-256 exact",
            sha256_bytes(intro_v02)
            == V02_SHA256,
        )

        check(
            "frozen and introduction v0.2 bytes equal",
            frozen_v02 == intro_v02,
        )

        if is_regular_nonsymlink(hist_path):
            check(
                "archive equals frozen v0.2 bytes",
                read_bytes(hist_path)
                == frozen_v02,
            )

        check(
            "frozen v0.2 sidecar SHA-256 exact",
            sha256_bytes(frozen_v02_sc)
            == V02_SIDECAR_SHA256,
        )

        check(
            "introduction v0.2 sidecar SHA-256 exact",
            sha256_bytes(intro_v02_sc)
            == V02_SIDECAR_SHA256,
        )

        check(
            "frozen and introduction v0.2 sidecar bytes equal",
            frozen_v02_sc == intro_v02_sc,
        )

        if is_regular_nonsymlink(hist_sc_path):
            check(
                "archive sidecar equals frozen sidecar bytes",
                read_bytes(hist_sc_path)
                == frozen_v02_sc,
            )

    successor = data.get(
        "successor_workflow",
        {},
    )

    check(
        "successor active path exact",
        successor.get("active_path")
        == V03_ACTIVE,
    )

    check(
        "successor SHA-256 authority exact",
        successor.get("workflow_sha256")
        == V03_SHA256,
    )

    check(
        "successor introduction commit exact",
        successor.get("introduction_commit")
        == V03_INTRO,
    )

    check(
        "successor YAML-valid authority true",
        successor.get("yaml_valid") is True,
    )

    check(
        "successor corrected-for-v0.2 authority true",
        successor.get(
            "corrected_successor_for_v0_2"
        )
        is True,
    )

    try:
        v03_parent = git_text(
            root,
            "rev-parse",
            V03_INTRO + "^",
        )
        successor_history_readable = True
    except Exception:
        v03_parent = ""
        successor_history_readable = False

    check(
        "successor Git history readable",
        successor_history_readable,
    )

    check(
        "v0.3 introduction directly descends from v0.2 introduction",
        v03_parent == V02_INTRO,
    )

    run = data.get(
        "historical_github_run_observation",
        {},
    )

    check(
        "historical run id exact",
        run.get("run_id") == 34433796283,
    )

    check(
        "historical workflow id exact",
        run.get("workflow_id") == 351977127,
    )

    check(
        "historical run workflow path exact",
        run.get("workflow_path")
        == V02_ACTIVE,
    )

    check(
        "historical run event exact",
        run.get("event") == "push",
    )

    check(
        "historical run status exact",
        run.get("status") == "completed",
    )

    check(
        "historical run conclusion exact",
        run.get("conclusion") == "failure",
    )

    check(
        "historical run head exact",
        run.get("head_sha") == FROZEN_COMMIT,
    )

    check(
        "historical run zero jobs",
        run.get("job_count") == 0,
    )

    check(
        "historical run zero artifacts",
        run.get("artifact_count") == 0,
    )

    check(
        "historical actual job execution observed false",
        run.get("actual_job_execution_observed")
        is False,
    )

    check(
        "historical crypto execution observed false",
        run.get("cryptographic_execution_observed")
        is False,
    )

    check(
        "historical failure classification exact",
        run.get("failure_classification")
        == "workflow_configuration_or_parse_failure",
    )

    check(
        "GitHub internal parser mechanism exact-proof boundary false",
        run.get(
            "github_internal_parser_mechanism_exactly_proven"
        )
        is False,
    )

    active_authority = data.get(
        "active_workflow_set_after_remediation",
        {},
    )

    check(
        "final active workflow count authority is 3",
        active_authority.get(
            "expected_active_workflow_count"
        )
        == 3,
    )

    check(
        "final active workflow authority list exact",
        active_authority.get("workflows")
        == ACTIVE_FINAL,
    )

    for item in ACTIVE_FINAL:
        verify_active_entry(
            root,
            item,
        )

    active_now = active_workflow_paths(root)

    final_paths = {
        item["path"]
        for item in ACTIVE_FINAL
    }

    if args.mode == "pre-retirement":
        expected_now = (
            final_paths | {V02_ACTIVE}
        )

        check(
            "pre-retirement active workflow set exact",
            active_now == expected_now,
        )

        active_v02 = root / V02_ACTIVE
        active_v02_sc = root / V02_ACTIVE_SC

        check(
            "pre-retirement active v0.2 regular non-symlink",
            is_regular_nonsymlink(active_v02),
        )

        check(
            "pre-retirement active v0.2 sidecar regular non-symlink",
            is_regular_nonsymlink(active_v02_sc),
        )

        if is_regular_nonsymlink(active_v02):
            check(
                "pre-retirement active v0.2 SHA-256 exact",
                sha256_bytes(
                    read_bytes(active_v02)
                )
                == V02_SHA256,
            )

        if is_regular_nonsymlink(active_v02_sc):
            check(
                "pre-retirement active v0.2 sidecar file SHA-256 exact",
                sha256_bytes(
                    read_bytes(active_v02_sc)
                )
                == V02_SIDECAR_SHA256,
            )

            check(
                "pre-retirement active v0.2 sidecar exact declaration",
                verify_exact_sidecar(
                    root,
                    V02_ACTIVE_SC,
                    V02_SHA256,
                    V02_ACTIVE,
                ),
            )

    else:
        check(
            "post-retirement active workflow set exact",
            active_now == final_paths,
        )

        check(
            "post-retirement active v0.2 absent",
            not (root / V02_ACTIVE).exists(),
        )

        check(
            "post-retirement active v0.2 sidecar absent",
            not (root / V02_ACTIVE_SC).exists(),
        )

    actions = data.get(
        "remediation_actions",
        {},
    )

    check(
        "final historical-bytes-preserved assertion true",
        actions.get(
            "historical_bytes_preserved"
        )
        is True,
    )

    check(
        "final active-v0.2-retired assertion true",
        actions.get(
            "active_invalid_v0_2_retired"
        )
        is True,
    )

    check(
        "v0.2 in-place fix assertion false",
        actions.get(
            "v0_2_in_place_fix_performed"
        )
        is False,
    )

    check(
        "active stub assertion false",
        actions.get(
            "active_stub_created"
        )
        is False,
    )

    check(
        "v0.3 modified assertion false",
        actions.get(
            "v0_3_modified"
        )
        is False,
    )

    check(
        "root v0.3 modified assertion false",
        actions.get(
            "root_v0_3_modified"
        )
        is False,
    )

    check(
        "cryptographic execution performed assertion false",
        actions.get(
            "cryptographic_execution_performed"
        )
        is False,
    )

    check(
        "workflow dispatch performed assertion false",
        actions.get(
            "workflow_dispatch_performed"
        )
        is False,
    )

    check(
        "final assertions gated by post-retirement verification",
        actions.get("semantics")
        == "final_state_assertions_effective_only_after_post_retirement_verifier_passes",
    )

    publication = data.get(
        "publication_time_audit",
        {},
    )

    check(
        "publication-time expected tracked count authority 94",
        publication.get(
            "expected_tracked_file_count"
        )
        == 94,
    )

    check(
        "no persistent exact repository file-count requirement",
        publication.get(
            "persistent_repository_exact_file_count_requirement"
        )
        is False,
    )

    check(
        "no persistent exact repository fileset requirement",
        publication.get(
            "persistent_repository_exact_fileset_requirement"
        )
        is False,
    )

    check(
        "tracked count explicitly publication-time only",
        publication.get(
            "tracked_file_count_is_publication_time_audit_value_only"
        )
        is True,
    )

    boundaries = data.get(
        "authority_boundaries",
        {},
    )

    check(
        "root v0.3 remains frozen",
        boundaries.get(
            "root_v0_3_remains_frozen"
        )
        is True,
    )

    false_boundaries = [
        "remediation_implies_cryptographic_correctness",
        "remediation_implies_nist_validation",
        "remediation_implies_fips_204_certification",
        "remediation_implies_complete_fips_204_conformance",
        "remediation_implies_complete_sigver_coverage",
        "remediation_implies_third_party_independent_reproduction",
        "absolute_immutability_claim_allowed",
        "system_wide_quantum_safe_claim_allowed",
        "security_vulnerability_absence_proven",
        "openssl_bug_confirmed",
        "circl_bug_confirmed",
    ]

    for key in false_boundaries:
        check(
            f"authority boundary false: {key}",
            boundaries.get(key) is False,
        )

    for rel in (
        "verify_qsv_mldsa_corpus_v0_3.py",
        "verify_qsv_mldsa_corpus_v0_3.py.sha256",
    ):
        current = root / rel

        try:
            frozen_bytes = git_bytes(
                root,
                "show",
                FROZEN_COMMIT + ":" + rel,
            )
            available = True
        except Exception:
            frozen_bytes = b""
            available = False

        check(
            f"frozen root v0.3 artifact readable: {rel}",
            available,
        )

        check(
            f"current root v0.3 artifact regular non-symlink: {rel}",
            is_regular_nonsymlink(current),
        )

        if (
            available
            and is_regular_nonsymlink(current)
        ):
            check(
                f"root v0.3 artifact unchanged from frozen parent: {rel}",
                read_bytes(current)
                == frozen_bytes,
            )

    print(
        "REMEDIATION_VERIFIER_CHECK_COUNT="
        + str(checks)
    )

    print(
        "REMEDIATION_VERIFIER_FAILURE_COUNT="
        + str(len(failures))
    )

    if failures:
        print("REMEDIATION_VERIFIER=FAIL")
        return 1

    if args.mode == "pre-retirement":
        print(
            "PRE_RETIREMENT_CANDIDATE_VERIFICATION=PASS"
        )
        print(
            "REMEDIATION_AUTHORITY_EFFECTIVE=NO"
        )
        print(
            "ACTIVE_V0_2_RETIRED=NO"
        )
        print(
            "READY_FOR_RETIREMENT_GATE=YES"
        )

    else:
        print(
            "POST_RETIREMENT_REMEDIATION_VERIFICATION=PASS"
        )
        print(
            "REMEDIATION_AUTHORITY_EFFECTIVE=YES"
        )
        print(
            "ACTIVE_V0_2_RETIRED=YES"
        )
        print(
            "REMEDIATION_VERIFIER=PASS"
        )

    print(
        "CRYPTOGRAPHIC_EXECUTION_PERFORMED=NO"
    )

    print(
        "WORKFLOW_DISPATCH_PERFORMED=NO"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
