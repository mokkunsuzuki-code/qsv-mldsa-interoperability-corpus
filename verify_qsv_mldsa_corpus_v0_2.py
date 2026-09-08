#!/usr/bin/env python3

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent

SELF_REL = "verify_qsv_mldsa_corpus_v0_2.py"
SELF_SIDECAR_REL = SELF_REL + ".sha256"

INTEGRATION_DIR_REL = (
    "integration/"
    "lane_b_stage393_external_interpretation_v0_1"
)

LANE_A_HEAD = "018148be719cd912dfbe7238dbd0642ed30e244c"
LANE_A_TREE = "ab8d59086d2a70df4e5be6258bfeb5bea0da5036"
LANE_A_PARENT = "9147de5e27a2764a95d7ef296b24b8c5bf235286"

LANE_B_FROZEN_QSV_TREE = "ee64d8091cbe9b0b811b5310b1f58788142da70d"

PRE_LANE_A_ROOT_SHA256 = "323485b7d41ba631d04e577bb9666f4779db63eb9094bfdcee084fc7e873ba26"

EXPECTED_LANE_A_FREEZE_SHA256 = "0a839aa84cfc56eb00b99b8efe8cc936f738f91699ae4f425f193e429a43f457"
EXPECTED_STAGE393_12_FREEZE_SHA256 = "dd89fd8ee3c124d7fcc314ca1db61ad9bccd6f1c32fa3201f521a6ac50412015"
EXPECTED_LANE_B_SIX_FREEZE_SHA256 = "3f51ed0197a74773e7a4c4477ad6b3f12ce1201e1de0470dca696c432aaf80ee"

EXPECTED_INTERPRETATION_BODY_SHA256 = (
    "f4a996b609339b9bd5917f711fcd1bce1232a402cdedeb2d49d8d09a1f7e56c9"
)

EXPECTED_REFERENCE_BODY_SHA256 = (
    "9a81da2282cd3d0fa49f7b43af8220bfb1d94450077284eee4342a549ffbf904"
)

BASE64_FILES = ['.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml', '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml.sha256', '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml', '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml.sha256', '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml', '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml.sha256', '.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml', '.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml.sha256', 'LICENSE', 'README.md', 'VERSION', 'contracts/qsv-mldsa-interoperability-corpus-v0.1.json', 'cross-platform/qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.json', 'cross-platform/qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.json.sha256', 'lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json', 'lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json.sha256', 'lineage/qsv-mldsa-implementation-lineage-v0.1.json', 'manifest/qsv-mldsa-corpus-v0.1-manifest.json', 'manifest/qsv-mldsa-corpus-v0.1-manifest.json.sha256', 'plans/qsv-mldsa-fixture-plan-v0.1.json', 'profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json', 'profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json.sha256', 'provenance/qsv-mldsa-provenance-v0.1.json', 'qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json', 'qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json.sha256', 'results/qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.json', 'results/qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.json.sha256', 'runners/qsv-mldsa-runner-interface-v0.1.json', 'runtime/qsv_mldsa_circl_sigver_harness_v0_1.go', 'runtime/qsv_mldsa_circl_sigver_harness_v0_1.go.sha256', 'runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c', 'runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c.sha256', 'runtime/qsv_mldsa_runtime_harness_contract_v0_1.json', 'runtime/qsv_mldsa_runtime_harness_contract_v0_1.json.sha256', 'runtime/qsv_mldsa_sixcase_extractor_v0_1.py', 'runtime/qsv_mldsa_sixcase_extractor_v0_1.py.sha256', 'runtime/qsv_mldsa_sixcase_metadata_v0_1.json', 'runtime/qsv_mldsa_sixcase_metadata_v0_1.json.sha256', 'schemas/qsv-mldsa-fixture-v0.1.schema.json', 'templates/qsv-mldsa-fixture-template.json', 'vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json', 'vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json.sha256', 'verify_qsv_mldsa_corpus_v0_1.py', 'verify_qsv_mldsa_corpus_v0_1.py.sha256', 'verify_qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.py', 'verify_qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.py.sha256', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_1.py', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_1.py.sha256', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_2.py', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_2.py.sha256', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_3.py', 'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_3.py.sha256', 'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py', 'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py.sha256', 'verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py', 'verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py.sha256', 'verify_qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.py', 'verify_qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.py.sha256', 'verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py', 'verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py.sha256', 'verify_qsv_mldsa_source_lineage_v0_1.py', 'verify_qsv_mldsa_source_lineage_v0_1.py.sha256', 'verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py', 'verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py.sha256']
LANE_A_SIX = {'.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml': '123d31afd0e2eaa6deba5ab42a90b040c452d08f72eb61e23db4b3dc1c7c8c52', '.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml.sha256': '1b639eb1c35a6c67f66b3c3ab0e6641cd7d35f2d2994ba0563884b6d349c0eae', 'verify_qsv_mldsa_corpus_v0_1.py': 'e7ac0e02434414be3f4827caa4295352ff4fba855f4f68a59d1e6374ee75da4e', 'verify_qsv_mldsa_corpus_v0_1.py.sha256': 'b88d6cee582caf999ac87b4325cff9bbc9f5e20c456546f95fd8656252909a54', 'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py': '347b878dee465b14727cbdd7a08dac81a806669c31c14c2c4a62ae7b1003d6d2', 'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py.sha256': '9cbe4318fe79a84c5f3929a99b367bb1c69f82cbf80183f1d504ef60f84febf7'}
STAGE393_12 = [('claims/qsv_mldsa_stage393_ninecase_historical_claim_table_v0_1.json', '521c9909f93290dae6ddd16b06f5a810f76e720b3a40fde1c090a09f9280e8bf'), ('claims/qsv_mldsa_stage393_ninecase_historical_claim_table_v0_1.json.sha256', '26926fdae4917dd1c4118a016732889ef6930b87443793151f73c4b5dd8d03b6'), ('profiles/qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json', '7ce3fffa2284ddd3076cfbeaf5d7e009fa3b02b4064738ecf1d8b1d0d4e49fbe'), ('profiles/qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json.sha256', '5a36bd03c954d37ce5e37677d8ceeefc521755cfba46e431015eb252ab48e7e8'), ('provenance/bindings/qsv-mldsa-stage393-triage-provenance-v0.1.json', '1375d4927dc3b2d9dbe3befb745c9c10191a45be09fb6be5169bcd03f7241c9a'), ('provenance/bindings/qsv-mldsa-stage393-triage-provenance-v0.1.json.sha256', '25a1d12aa5f0d103bc04eb357f64ce8ba207715be43d95d12cc77e80526061f1'), ('results/qsv_mldsa_stage393_ninecase_historical_observation_evidence_v0_1.json', 'afdab2eed9329378a839d64e755435fa355147f9d0d17ddaff330e492c08ccb4'), ('results/qsv_mldsa_stage393_ninecase_historical_observation_evidence_v0_1.json.sha256', '90601fc1faa2138cb95a5cc52d0ca76d2aa4eb166d59e504838d56cfedd82a5c'), ('vectors/bindings/qsv-mldsa-wycheproof-vector-source-v0.1.json', '7e15181e7bce4b6b3b8748bcc4d53d8c9a6277a3ba6104f19adfe4b08aec2295'), ('vectors/bindings/qsv-mldsa-wycheproof-vector-source-v0.1.json.sha256', '917f0b9529957bf8984ccf9e23bf24aa8ff8636bfa0ff5900103506e93993c54'), ('verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py', '5df9d8f2cf16aa5eb5e74b01a8972e1e39fb243d35d9d547179c88fd96719776'), ('verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py.sha256', 'ceb5211e1fe0e49c0f7123de1c62a80ba49c70bdf205630e929a28d8e1be208e')]
LANE_B_SIX = {'qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json': '8fbd24c8253fca511f1fe12b94b85c92e8f23d9aeb7b46ff21e8b8fed9437d55', 'qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json.sha256': 'e9d456bbf5e7b837e874a10310971961fbff4cecad56a49d1f1bb2329ff151f7', 'qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json': 'e9b79df51996114dde54676464af4ae5906e77e8c351fb3ea240be0e27b16700', 'qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json.sha256': 'c99e91c4b380a4dc4bb405e15ba13fcf144e3ad89e9ab12b8c7e9eb43667bfd4', 'verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py': '5f27abfbdb7209db66745a21fbf05b44a2471594392bac140d9f23d00140c5de', 'verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py.sha256': '96fd0516dfbf078de7cf709018df89321cc28b4c73e04acf9d6b0d4bd0535575'}

failures = []
check_count = 0
pass_count = 0


def sha256(path):
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def text_sha256(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def check(name, condition):
    global check_count
    global pass_count

    check_count += 1

    if condition:
        pass_count += 1
    else:
        failures.append(
            name
        )


def recursive_contains_value(
    obj,
    expected,
):
    if obj == expected:
        return True

    if isinstance(
        obj,
        dict,
    ):
        return any(
            recursive_contains_value(
                value,
                expected,
            )
            for value
            in obj.values()
        )

    if isinstance(
        obj,
        list,
    ):
        return any(
            recursive_contains_value(
                value,
                expected,
            )
            for value
            in obj
        )

    return False


# ============================================================
# 1. Safety / self binding
# ============================================================

check(
    "QSV_EXECUTE_CRYPTO absent",
    os.environ.get(
        "QSV_EXECUTE_CRYPTO"
    ) is None,
)

check(
    "root v0.2 regular file",
    (
        ROOT
        / SELF_REL
    ).is_file(),
)

check(
    "root v0.2 sidecar regular file",
    (
        ROOT
        / SELF_SIDECAR_REL
    ).is_file(),
)

if (
    (
        ROOT
        / SELF_REL
    ).is_file()
    and
    (
        ROOT
        / SELF_SIDECAR_REL
    ).is_file()
):
    self_sha = sha256(
        ROOT
        / SELF_REL
    )

    expected_sidecar = (
        self_sha
        + "  "
        + SELF_REL
        + "\n"
    )

    actual_sidecar = (
        ROOT
        / SELF_SIDECAR_REL
    ).read_text(
        encoding="utf-8"
    )

    check(
        "root v0.2 self sidecar binding",
        actual_sidecar
        == expected_sidecar,
    )
else:
    check(
        "root v0.2 self sidecar binding",
        False,
    )


# ============================================================
# 2. Exact portable fileset
# ============================================================

expected_portable_files = (
    set(
        BASE64_FILES
    )
    |
    {
        rel
        for rel, _
        in STAGE393_12
    }
    |
    {
        (
            INTEGRATION_DIR_REL
            + "/"
            + name
        )
        for name
        in LANE_B_SIX
    }
    |
    {
        SELF_REL,
        SELF_SIDECAR_REL,
    }
)

actual_portable_files = set()

for path in ROOT.rglob("*"):
    if not path.is_file():
        continue

    rel_path = (
        path.relative_to(
            ROOT
        )
    )

    if (
        ".git"
        in rel_path.parts
    ):
        continue

    actual_portable_files.add(
        rel_path.as_posix()
    )

check(
    "portable expected file count 84",
    len(
        expected_portable_files
    ) == 84,
)

check(
    "portable physical file count 84",
    len(
        actual_portable_files
    ) == 84,
)

check(
    "portable exact fileset",
    actual_portable_files
    == expected_portable_files,
)

check(
    "all portable files regular",
    all(
        (
            ROOT
            / rel
        ).is_file()
        and not (
            ROOT
            / rel
        ).is_symlink()
        for rel
        in expected_portable_files
    ),
)


# ============================================================
# 3. Lane A six-file freeze
# ============================================================

lane_a_hashes_ok = True
lane_a_records = []

for rel in sorted(
    LANE_A_SIX
):
    path = (
        ROOT
        / rel
    )

    if (
        not path.is_file()
        or
        sha256(path)
        != LANE_A_SIX[rel]
    ):
        lane_a_hashes_ok = False

    if path.is_file():
        lane_a_records.append({
            "path":
                rel,
            "sha256":
                sha256(path),
        })

check(
    "Lane A six hashes exact",
    lane_a_hashes_ok
    and
    len(
        lane_a_records
    ) == 6,
)

lane_a_freeze_object = {
    "lane":
        "linux_sixcase_explicit_crypto_reproduction_gate",

    "repository_head":
        LANE_A_HEAD,

    "repository_tree":
        LANE_A_TREE,

    "parent_head":
        LANE_A_PARENT,

    "pre_lane_a_root_verifier_sha256":
        PRE_LANE_A_ROOT_SHA256,

    "pre_lane_a_root_check_count":
        573,

    "current_root_check_count":
        581,

    "lane_a_added_root_check_count":
        8,

    "authority_file_count":
        6,

    "files":
        lane_a_records,
}

lane_a_freeze_bytes = json.dumps(
    lane_a_freeze_object,
    sort_keys=True,
    separators=(
        ",",
        ":",
    ),
    ensure_ascii=False,
).encode(
    "utf-8"
)

lane_a_freeze_sha = hashlib.sha256(
    lane_a_freeze_bytes
).hexdigest()

check(
    "Lane A freeze identifier exact",
    lane_a_freeze_sha
    == EXPECTED_LANE_A_FREEZE_SHA256,
)


# ============================================================
# 4. Lane A exact64 root v0.1 re-verification
# ============================================================

python3 = shutil.which(
    "python3"
)

check(
    "python3 available",
    python3 is not None,
)

lane_a_root_ok = False

if python3 is not None:
    with tempfile.TemporaryDirectory(
        prefix="qsv-v02-lane-a-"
    ) as tmp:
        isolated = Path(
            tmp
        )

        copy_ok = True

        for rel in BASE64_FILES:
            source = (
                ROOT
                / rel
            )

            destination = (
                isolated
                / rel
            )

            if not source.is_file():
                copy_ok = False
                break

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copy2(
                source,
                destination,
            )

        if copy_ok:
            env = os.environ.copy()

            env.pop(
                "QSV_EXECUTE_CRYPTO",
                None,
            )

            env[
                "PYTHONDONTWRITEBYTECODE"
            ] = "1"

            proc = subprocess.run(
                [
                    python3,
                    str(
                        isolated
                        / "verify_qsv_mldsa_corpus_v0_1.py"
                    ),
                ],
                cwd=str(
                    isolated
                ),
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            def counter(
                name,
            ):
                match = re.search(
                    rf"(?im)^{re.escape(name)}=(\d+)\s*$",
                    proc.stdout,
                )

                return (
                    int(
                        match.group(1)
                    )
                    if match
                    else None
                )

            checks = counter(
                "qsv_mldsa_corpus_check_count"
            )

            passes = counter(
                "qsv_mldsa_corpus_pass_count"
            )

            failed = counter(
                "qsv_mldsa_corpus_failure_count"
            )

            lane_a_root_ok = (
                proc.returncode == 0
                and checks == 581
                and passes == 581
                and failed == 0
            )

check(
    "Lane A root v0.1 581 of 581",
    lane_a_root_ok,
)


# ============================================================
# 5. Stage393 twelve-file freeze
# ============================================================

stage393_hashes_ok = True
stage393_records = []

for (
    rel,
    expected_hash,
) in STAGE393_12:

    path = (
        ROOT
        / rel
    )

    if (
        not path.is_file()
        or
        sha256(path)
        != expected_hash
    ):
        stage393_hashes_ok = False

    if path.is_file():
        stage393_records.append({
            "path":
                rel,
            "sha256":
                sha256(path),
        })

check(
    "Stage393 twelve hashes exact",
    stage393_hashes_ok
    and
    len(
        stage393_records
    ) == 12,
)

stage393_freeze_object = {
    "source_repository_head":
        LANE_A_PARENT,

    "source_repository_tree":
        LANE_B_FROZEN_QSV_TREE,

    "file_count":
        len(
            stage393_records
        ),

    "files":
        stage393_records,
}

stage393_freeze_bytes = json.dumps(
    stage393_freeze_object,
    sort_keys=True,
    separators=(
        ",",
        ":",
    ),
    ensure_ascii=False,
).encode(
    "utf-8"
)

stage393_freeze_sha = hashlib.sha256(
    stage393_freeze_bytes
).hexdigest()

check(
    "Stage393 twelve freeze identifier exact",
    stage393_freeze_sha
    == EXPECTED_STAGE393_12_FREEZE_SHA256,
)


# ============================================================
# 6. Lane B frozen six-file authority
# ============================================================

lane_b_dir = (
    ROOT
    / INTEGRATION_DIR_REL
)

lane_b_hashes_ok = True
lane_b_records = []

for name in sorted(
    LANE_B_SIX
):
    path = (
        lane_b_dir
        / name
    )

    if (
        not path.is_file()
        or
        sha256(path)
        != LANE_B_SIX[
            name
        ]
    ):
        lane_b_hashes_ok = False

    if path.is_file():
        lane_b_records.append({
            "path":
                name,
            "sha256":
                sha256(path),
        })

check(
    "Lane B six copied hashes exact",
    lane_b_hashes_ok
    and
    len(
        lane_b_records
    ) == 6,
)

sidecars_ok = True

for name in (
    "qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json",
    "qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json",
    "verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py",
):
    data_path = (
        lane_b_dir
        / name
    )

    sidecar_path = (
        lane_b_dir
        / (
            name
            + ".sha256"
        )
    )

    if (
        not data_path.is_file()
        or
        not sidecar_path.is_file()
    ):
        sidecars_ok = False
        continue

    expected_text = (
        sha256(
            data_path
        )
        + "  "
        + name
        + "\n"
    )

    actual_text = sidecar_path.read_text(
        encoding="utf-8"
    )

    if (
        actual_text
        != expected_text
    ):
        sidecars_ok = False

check(
    "Lane B six sidecar bindings exact",
    sidecars_ok,
)

lane_b_freeze_object = {
    "lane":
        "stage393_circl_ninecase_evidence_lane",

    "authority_file_count":
        6,

    "frozen_qsv_head":
        LANE_A_PARENT,

    "frozen_qsv_tree":
        LANE_B_FROZEN_QSV_TREE,

    "stage393_12_file_freeze_input_canonical_sha256":
        EXPECTED_STAGE393_12_FREEZE_SHA256,

    "files":
        lane_b_records,
}

lane_b_freeze_bytes = json.dumps(
    lane_b_freeze_object,
    sort_keys=True,
    separators=(
        ",",
        ":",
    ),
    ensure_ascii=False,
).encode(
    "utf-8"
)

lane_b_freeze_sha = hashlib.sha256(
    lane_b_freeze_bytes
).hexdigest()

check(
    "Lane B six freeze identifier exact",
    lane_b_freeze_sha
    == EXPECTED_LANE_B_SIX_FREEZE_SHA256,
)


# ============================================================
# 7. Lane B selected semantic bindings
# ============================================================

evidence_path = (
    lane_b_dir
    / "qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json"
)

manifest_path = (
    lane_b_dir
    / "qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json"
)

try:
    evidence = json.loads(
        evidence_path.read_text(
            encoding="utf-8"
        )
    )
except Exception:
    evidence = None

try:
    manifest = json.loads(
        manifest_path.read_text(
            encoding="utf-8"
        )
    )
except Exception:
    manifest = None

check(
    "Lane B evidence JSON parses",
    evidence is not None,
)

check(
    "Lane B manifest JSON parses",
    manifest is not None,
)

if evidence is not None:
    try:
        external = evidence[
            "external_interpretation"
        ]

        rationale = evidence[
            "source_code_rationale"
        ]

        interpretation_statement = external[
            "statement_exact"
        ]

        reference_statement = rationale[
            "reference_comment_body_exact"
        ]

        check(
            "interpretation comment id exact",
            external[
                "interpretation_comment_id"
            ] == 5570219154,
        )

        check(
            "interpretation repository exact",
            external[
                "source_repository"
            ] == "cloudflare/circl",
        )

        check(
            "interpretation exact statement",
            interpretation_statement
            ==
            "These are deliberate choices of each implementation.",
        )

        check(
            "interpretation derived body hash exact",
            text_sha256(
                interpretation_statement
            )
            ==
            EXPECTED_INTERPRETATION_BODY_SHA256,
        )

        check(
            "reference comment id exact",
            rationale[
                "reference_comment_id"
            ] == 5571477664,
        )

        check(
            "reference exact body",
            reference_statement
            ==
            "[here](https://github.com/cloudflare/circl/blob/main/sign/schemes/wycheproof_test.go#L135-L137)",
        )

        check(
            "reference derived body hash exact",
            text_sha256(
                reference_statement
            )
            ==
            EXPECTED_REFERENCE_BODY_SHA256,
        )

    except Exception:
        for label in (
            "interpretation comment id exact",
            "interpretation repository exact",
            "interpretation exact statement",
            "interpretation derived body hash exact",
            "reference comment id exact",
            "reference exact body",
            "reference derived body hash exact",
        ):
            check(
                label,
                False,
            )

    six_case_ids = [
        "QSV-MLDSA-WYCHEPROOF-44-0052",
        "QSV-MLDSA-WYCHEPROOF-44-0053",
        "QSV-MLDSA-WYCHEPROOF-65-0056",
        "QSV-MLDSA-WYCHEPROOF-65-0057",
        "QSV-MLDSA-WYCHEPROOF-87-0047",
        "QSV-MLDSA-WYCHEPROOF-87-0048",
    ]

    check(
        "six CIRCL-side case ids exact",
        all(
            recursive_contains_value(
                evidence,
                case_id,
            )
            for case_id
            in six_case_ids
        ),
    )

    check(
        "fixed CIRCL rationale commit binding",
        recursive_contains_value(
            evidence,
            "352600b0a4b2380815cef55fc690c65049c7e56b",
        ),
    )

    check(
        "Stage393 execution CIRCL commit binding",
        recursive_contains_value(
            evidence,
            "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
        ),
    )
else:
    for label in (
        "interpretation comment id exact",
        "interpretation repository exact",
        "interpretation exact statement",
        "interpretation derived body hash exact",
        "reference comment id exact",
        "reference exact body",
        "reference derived body hash exact",
        "six CIRCL-side case ids exact",
        "fixed CIRCL rationale commit binding",
        "Stage393 execution CIRCL commit binding",
    ):
        check(
            label,
            False,
        )

if manifest is not None:
    check(
        "manifest schema binding",
        recursive_contains_value(
            manifest,
            "qsv.mldsa.stage393.external-interpretation-candidate-manifest.v0.1",
        ),
    )

    check(
        "manifest lane binding",
        recursive_contains_value(
            manifest,
            "stage393_circl_ninecase_evidence_lane",
        ),
    )

    check(
        "manifest twelve freeze binding",
        recursive_contains_value(
            manifest,
            EXPECTED_STAGE393_12_FREEZE_SHA256,
        ),
    )
else:
    check(
        "manifest schema binding",
        False,
    )
    check(
        "manifest lane binding",
        False,
    )
    check(
        "manifest twelve freeze binding",
        False,
    )


# ============================================================
# 8. Decision
# ============================================================

failure_count = len(
    failures
)

print(
    "qsv_mldsa_corpus_v0_2_check_count="
    + str(
        check_count
    )
)

print(
    "qsv_mldsa_corpus_v0_2_pass_count="
    + str(
        pass_count
    )
)

print(
    "qsv_mldsa_corpus_v0_2_failure_count="
    + str(
        failure_count
    )
)

if failures:
    for failure in failures:
        print(
            "FAIL: "
            + failure
        )

    print(
        "QSV_MLDSA_CORPUS_V0_2_UNIFIED_VERIFICATION=FAIL"
    )

    raise SystemExit(1)

print(
    "QSV_MLDSA_CORPUS_V0_2_UNIFIED_VERIFICATION=PASS"
)

print(
    "PORTABLE_EXACT_FILESET_COUNT=84"
)

print(
    "LANE_A_FREEZE_CANONICAL_SHA256="
    + lane_a_freeze_sha
)

print(
    "LANE_A_ROOT_V0_1_REVERIFICATION=581_OF_581_PASS"
)

print(
    "STAGE393_12_FILE_FREEZE_CANONICAL_SHA256="
    + stage393_freeze_sha
)

print(
    "LANE_B_SIX_FILE_FREEZE_CANONICAL_SHA256="
    + lane_b_freeze_sha
)

print(
    "LANE_B_COMMENT_BODY_HASHES_DERIVED_FROM_EXACT_STATEMENTS=YES"
)

print(
    "LANE_B_FROZEN_LOCATION_BOUND_VERIFIER_BYTES_PRESERVED=YES"
)

print(
    "LANE_B_FROZEN_LOCATION_BOUND_VERIFIER_DIRECT_REEXECUTION=NO"
)

print(
    "CRYPTOGRAPHIC_REEXECUTION_PERFORMED=NO"
)

print(
    "WORKFLOW_DISPATCHED=NO"
)

print(
    "FORMAL_CERTIFICATION_CLAIM_ALLOWED=NO"
)

print(
    "FIPS204_NONCONFORMANCE_CLAIM_ALLOWED=NO"
)

print(
    "IMPLEMENTATION_BUG_CLAIM_ALLOWED=NO"
)

print(
    "SECURITY_VULNERABILITY_CLAIM_ALLOWED=NO"
)

print(
    "CIRCL_ENDORSEMENT_CLAIM_ALLOWED=NO"
)

print(
    "CLOUDFLARE_ENDORSEMENT_CLAIM_ALLOWED=NO"
)

print(
    "OPENSSL_PRIMARY_CONFIRMATION_CLAIM_ALLOWED=NO"
)

print(
    "ROOT_CAUSE_DEFAULT=unknown"
)

print(
    "SEMANTIC_MUTATION_COVERAGE_IS_COMPLETE_CLAIM_ALLOWED=NO"
)
