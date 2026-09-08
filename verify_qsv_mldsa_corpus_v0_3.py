#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

BASELINE_HASHES = {
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml': '3b488f00990c11a796faa7638d39b5aa12874c3e21c9459aa264c77d6315ea16',
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_1.yml.sha256': '59aa85f6714da88735a7907c30024d40193973db07e3f9bd4dbcbd9ae4715ddc',
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml': '0351a06ab03e2ff27669f00e30e5e7647bcd54af20c6e905ba2e607233e035b9',
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_2.yml.sha256': '8f7c07b069f486c75876de9eda7ace947a64ec22084204b1485179b79ca3ce9b',
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml': 'f4197f42e2ed6a76c66b12d9f10c069b2d1ef5d7f3653d46a3b80858c858cdc0',
    '.github/workflows/qsv-mldsa-cross-platform-clean-environment-precheck-v0_3.yml.sha256': '596ed58fcf00c1a4c2f9d0424027fb4c210acc95e7f59a62ec7d62ee0c59057c',
    '.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml': '123d31afd0e2eaa6deba5ab42a90b040c452d08f72eb61e23db4b3dc1c7c8c52',
    '.github/workflows/qsv-mldsa-linux-sixcase-explicit-crypto-execution-v0_1.yml.sha256': '1b639eb1c35a6c67f66b3c3ab0e6641cd7d35f2d2994ba0563884b6d349c0eae',
    'LICENSE': 'a19e43c45dbca1d785a44d23699682cb72cae0aff110898eef5d9bb4a4043c90',
    'README.md': '8b7c23e59d08f79e3c9ee7051c8298762df40e7100c4813488cb21de448e9752',
    'VERSION': 'a6311009c6c322ca8ac2e620cff5204f0c3af23115d403293a0cb5be36796688',
    'claims/qsv_mldsa_stage393_ninecase_historical_claim_table_v0_1.json': '521c9909f93290dae6ddd16b06f5a810f76e720b3a40fde1c090a09f9280e8bf',
    'claims/qsv_mldsa_stage393_ninecase_historical_claim_table_v0_1.json.sha256': '26926fdae4917dd1c4118a016732889ef6930b87443793151f73c4b5dd8d03b6',
    'contracts/qsv-mldsa-interoperability-corpus-v0.1.json': '7f2e9903cee09136d1db497aa5bbeb205a0ba014dd5e761916d2d2c9c6a7f09c',
    'cross-platform/qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.json': '9f78c559fdcb564efe4320803ce55caa5fe26f379ec2627936fac3912aca2f71',
    'cross-platform/qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.json.sha256': 'ea0bfcc69ceb26c92a4a417c03c615a6da6f4a947fb8e34afeca8ad5ce4f0597',
    'integration/lane_b_stage393_external_interpretation_v0_1/qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json': '8fbd24c8253fca511f1fe12b94b85c92e8f23d9aeb7b46ff21e8b8fed9437d55',
    'integration/lane_b_stage393_external_interpretation_v0_1/qsv_mldsa_stage393_circl_issue_691_external_interpretation_v0_1.json.sha256': 'e9d456bbf5e7b837e874a10310971961fbff4cecad56a49d1f1bb2329ff151f7',
    'integration/lane_b_stage393_external_interpretation_v0_1/qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json': 'e9b79df51996114dde54676464af4ae5906e77e8c351fb3ea240be0e27b16700',
    'integration/lane_b_stage393_external_interpretation_v0_1/qsv_mldsa_stage393_external_interpretation_candidate_manifest_v0_1.json.sha256': 'c99e91c4b380a4dc4bb405e15ba13fcf144e3ad89e9ab12b8c7e9eb43667bfd4',
    'integration/lane_b_stage393_external_interpretation_v0_1/verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py': '5f27abfbdb7209db66745a21fbf05b44a2471594392bac140d9f23d00140c5de',
    'integration/lane_b_stage393_external_interpretation_v0_1/verify_qsv_mldsa_stage393_external_interpretation_candidate_v0_1.py.sha256': '96fd0516dfbf078de7cf709018df89321cc28b4c73e04acf9d6b0d4bd0535575',
    'lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json': 'bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289',
    'lineage/bindings/qsv-mldsa-implementation-source-lineage-v0.1.json.sha256': '34fb8f07486534e7a827cbb8027526d127de6fc1e231fd99f8924a862028ead8',
    'lineage/qsv-mldsa-implementation-lineage-v0.1.json': 'c93064925f59131570fae5e1609fe09bba089ca556de04939f4c61e151835747',
    'manifest/qsv-mldsa-corpus-v0.1-manifest.json': 'b60bf937aa825c783d0992f4975fd476ec8d7efabf879fe3a940b39bf38a7313',
    'manifest/qsv-mldsa-corpus-v0.1-manifest.json.sha256': '953095efc5a50cb6619f1fed0f65b5fcb32b9832b9ca426e3d432df949cf3ff1',
    'plans/qsv-mldsa-fixture-plan-v0.1.json': '1cc2606f2550cfce4fdec0953fd8c40fcdc81b0357da3074dc45d89392429ce4',
    'profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json': '0807afb1b87b73d556ba43a07943f62313edb623d74c13024b83c7dfa132e98d',
    'profiles/qsv-mldsa-nist-acvp-minimal-sigver-kat-profile-v0.1.json.sha256': 'ed44dfb7eaf86cdc4efbfd0b36ea2f7d4a34d5485d94b9a247b99fa41defe72d',
    'profiles/qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json': '7ce3fffa2284ddd3076cfbeaf5d7e009fa3b02b4064738ecf1d8b1d0d4e49fbe',
    'profiles/qsv-mldsa-wycheproof-stage393-ninecase-negative-sign-profile-v0.1.json.sha256': '5a36bd03c954d37ce5e37677d8ceeefc521755cfba46e431015eb252ab48e7e8',
    'provenance/bindings/qsv-mldsa-stage393-triage-provenance-v0.1.json': '1375d4927dc3b2d9dbe3befb745c9c10191a45be09fb6be5169bcd03f7241c9a',
    'provenance/bindings/qsv-mldsa-stage393-triage-provenance-v0.1.json.sha256': '25a1d12aa5f0d103bc04eb357f64ce8ba207715be43d95d12cc77e80526061f1',
    'provenance/qsv-mldsa-provenance-v0.1.json': 'ef5937f626a44beba9520a7635d3eac166d40b6f798e6f47746eab644214ac48',
    'qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json': 'bbc7f498231b96726e7bb7d4412269088d74e75cc7f15208974c937bbda2d31f',
    'qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.json.sha256': 'f78b230b8a7f516fd14a59d023c2207e0faa2393985e898b651ec386ba0e33d3',
    'results/qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.json': '1f73e8d2570063811bb065ae6fbabb34deae12d10d1778dcdee67a8245d1058c',
    'results/qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.json.sha256': 'c30295f7e48cf984eae5ad5af7bbe2ca81dcd51ddf4417e1df7ede8101f2a840',
    'results/qsv_mldsa_stage393_ninecase_historical_observation_evidence_v0_1.json': 'afdab2eed9329378a839d64e755435fa355147f9d0d17ddaff330e492c08ccb4',
    'results/qsv_mldsa_stage393_ninecase_historical_observation_evidence_v0_1.json.sha256': '90601fc1faa2138cb95a5cc52d0ca76d2aa4eb166d59e504838d56cfedd82a5c',
    'runners/qsv-mldsa-runner-interface-v0.1.json': '4a9334ed4ded02ed15a65129da18ac3c8daab8db137cbef78b8e0fcdf8dea0b8',
    'runtime/qsv_mldsa_circl_sigver_harness_v0_1.go': 'f3c551821f4c31b8f7fd7242e66002c4aa1cc3dd0abb0c56710f3d0a91fc0fed',
    'runtime/qsv_mldsa_circl_sigver_harness_v0_1.go.sha256': '4753507af9c941941bc4f5521fc6daa2b9492090d66cdb524e58d3285dcefb4b',
    'runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c': '0d5c2030409425115680d3140429918210fbc63c5f18bb0c08257314bd6e6240',
    'runtime/qsv_mldsa_openssl_sigver_harness_v0_1.c.sha256': '0936993aedade68497730c5f258826a38b4ccf569239f2f748d2fd32fedc6059',
    'runtime/qsv_mldsa_runtime_harness_contract_v0_1.json': '6e3c5161c978ec4a045ad1c72ed491967ae66c1501d83aab660ffcde7cca307e',
    'runtime/qsv_mldsa_runtime_harness_contract_v0_1.json.sha256': '205545b9af574ca52a9fa0e8682b79bf66ab1fdad13d2dce3fe2e8a32d7310e2',
    'runtime/qsv_mldsa_sixcase_extractor_v0_1.py': '0bdad8db61b008ce50e6c53a472d3e56d36cf8169318cb50474672d62e566679',
    'runtime/qsv_mldsa_sixcase_extractor_v0_1.py.sha256': 'acaaa4bccad7dd49e3e8092b75f0958ecdddc7ff5bac26521d87ba794d939420',
    'runtime/qsv_mldsa_sixcase_metadata_v0_1.json': '27104ea68cb2c47c10c0265ca8772b2c4af792ea7b2d5d34925511aefc2592d6',
    'runtime/qsv_mldsa_sixcase_metadata_v0_1.json.sha256': '3478d45f9e6857a4d528db0c556ae9516914be61e724aa122768e264033b95a7',
    'schemas/qsv-mldsa-fixture-v0.1.schema.json': 'd4bd741ab7960445e3e3f16cbf5605a47f52ad223edbd2f21b3dcc42b219c2cd',
    'templates/qsv-mldsa-fixture-template.json': 'bae6d921c7ce5bdecce4ba3228baa3c141d6b638a9d09fa1e0e3c0dabc5697b6',
    'vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json': '666cf0ca554fdcd91df3602ec37a74f4af36a905fe9549ae1c0a1030af6c0032',
    'vectors/bindings/qsv-mldsa-nist-acvp-vector-source-v0.1.json.sha256': '733fe6c577049dbfeff9500822ee056fca11b75894b2afbda77389f892c800d6',
    'vectors/bindings/qsv-mldsa-wycheproof-vector-source-v0.1.json': '7e15181e7bce4b6b3b8748bcc4d53d8c9a6277a3ba6104f19adfe4b08aec2295',
    'vectors/bindings/qsv-mldsa-wycheproof-vector-source-v0.1.json.sha256': '917f0b9529957bf8984ccf9e23bf24aa8ff8636bfa0ff5900103506e93993c54',
    'verify_qsv_mldsa_corpus_v0_1.py': 'e7ac0e02434414be3f4827caa4295352ff4fba855f4f68a59d1e6374ee75da4e',
    'verify_qsv_mldsa_corpus_v0_1.py.sha256': 'b88d6cee582caf999ac87b4325cff9bbc9f5e20c456546f95fd8656252909a54',
    'verify_qsv_mldsa_corpus_v0_2.py': '29c9efda22b2041bd658759696d707c4cd33b7942f199704acab30c6d075fe54',
    'verify_qsv_mldsa_corpus_v0_2.py.sha256': 'fc213d207946023d2e8fa3c6aa9afddebf984c67b7f5acc703c87c531e4c76ff',
    'verify_qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.py': 'fbbdb8ab12531fd80d34bddf6e58d92bbc961bf7c03e00580773cfeedfa8039b',
    'verify_qsv_mldsa_cross_platform_clean_environment_reproduction_contract_v0_1.py.sha256': '7de2ab4315346cecfd288b06f5c5176a614fa745b32bf09019763324ed3777f3',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_1.py': '67ebfa5817cdeface9381aa40bdec4fb5ce5e73e86d6dcd5288ffafaa01ce301',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_1.py.sha256': 'd545ab0703fffdc36be1c6805f50a700700f6a67ab8e1a0e4d576f78c644c812',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_2.py': '6788d28d8e1566e31553766d11aa99ec062735604ce8ef72896eecf06c32315a',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_2.py.sha256': 'a2e0f788fb4414e71ad6bb4648f6d4b952700c7d314a76885327b8cc306a5a2b',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_3.py': '8c628a36cb0ae548d4f3a1a3da4033ceccd02fe6b60683b1183bd36dc58b3f18',
    'verify_qsv_mldsa_cross_platform_precheck_workflow_candidate_v0_3.py.sha256': 'd46df9192158facf25c43af9d8bd75d5c0963b8426138a5cac29a4fcc5a2d95c',
    'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py': '347b878dee465b14727cbdd7a08dac81a806669c31c14c2c4a62ae7b1003d6d2',
    'verify_qsv_mldsa_linux_sixcase_crypto_workflow_candidate_v0_1.py.sha256': '9cbe4318fe79a84c5f3929a99b367bb1c69f82cbf80183f1d504ef60f84febf7',
    'verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py': '09d52ef872d23d054586dad2cfd4172db48a12c4e37a4f42b903831d3d61f6ae',
    'verify_qsv_mldsa_minimal_sigver_kat_profile_v0_1.py.sha256': '3e164762f97280501065912b217f3941118efa4340034a8b1597f2ba1b133b00',
    'verify_qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.py': '97961fedf922808b4e45eb409237edb23f548426eee89a7425cce27fc4acd947',
    'verify_qsv_mldsa_minimal_sixcase_execution_result_evidence_v0_1.py.sha256': '819052417122f253ee828df61d7dab445e06185ad53f85e48f40b4af183eea94',
    'verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py': '5a5c4399acba51c1e34d4b602415b61ef52f8ef162c87d8a454c2691c4250699',
    'verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py.sha256': 'f5d83320e454dbcd52f522f5f99cf0ca6d5bc4afb5af6645e803ca2432691a5b',
    'verify_qsv_mldsa_source_lineage_v0_1.py': 'c5b2b6cf9ab7045a8df9eadcb6f8435eab73f2e5951dc17461393e21a91257bd',
    'verify_qsv_mldsa_source_lineage_v0_1.py.sha256': '6f77de76f053b9e21be2b6d6a859abf6e5b1b34d6081dc11309727d61d87765d',
    'verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py': '5df9d8f2cf16aa5eb5e74b01a8972e1e39fb243d35d9d547179c88fd96719776',
    'verify_qsv_mldsa_stage393_ninecase_static_integration_v0_1.py.sha256': 'ceb5211e1fe0e49c0f7123de1c62a80ba49c70bdf205630e929a28d8e1be208e',
    'verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py': 'd37f60d22b172ed28655938dfe6afb02b3fe6a5f597fa3b04d721f5a3e547e1c',
    'verify_qsv_mldsa_v0_3_no_crypto_precheck_run_evidence_v0_1.py.sha256': 'f63e5bb37542dc4f41330e017ec2b8ba29800b1dc161bbfc4f346106c6ff8869',
}

FOUR_AUTHORITY_HASHES = {
    'results/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_v0_2/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_1.json': '1d696fe026845b8a4c3c12d3e6ae1a97e643f56e72035c79cbd1caed7a345643',
    'results/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_v0_2/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_1.json.sha256': '8aedf7ccfdd03738ecbab239d2d84e5558be7a330c97edbe2f71cdcd7836b82a',
    'results/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_v0_2/verify_qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_2.py': '59f421662f0ab06ad49f2f51cd08091738a2f3538b685854bc418143072d8493',
    'results/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_v0_2/verify_qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_2.py.sha256': '3c8417119bc151a8fd162d22596b75515c36ee4030b6957a164e79cd901dc762',
}

SEMANTIC_CONTRACT = {
    'absolute_openssl_build_provenance_complete_claim_allowed': 'false',
    'baseline_commit': '42f2229f1e70bd5e2ee3aa0a9c57295d2bc7e1e6',
    'baseline_file_count': 84,
    'baseline_tree': '031d50b64d1f484c0c040ff10663f7eb137493eb',
    'cryptographic_reexecution_performed': 'NO',
    'final_decision_on_pass': 'PASS',
    'github_runner_immutable_build_environment': 'false',
    'metadata_authority_file_count': 4,
    'portable_exact_fileset_count': 90,
    'result_equals_complete_fips_204_conformance': 'NO',
    'result_equals_complete_sigver_coverage': 'NO',
    'result_equals_fips_204_certification': 'NO',
    'result_equals_nist_validation': 'NO',
    'root_v0_3_authority_file_count': 2,
    'semantic_mutation_coverage_is_complete_claim_allowed': 'NO',
    'third_party_independent_reproduction': 'false',
    'workflow_dispatched': 'NO',
}

EXPECTED_SEMANTIC_CONTRACT_KEYS = ['absolute_openssl_build_provenance_complete_claim_allowed', 'baseline_commit', 'baseline_file_count', 'baseline_tree', 'cryptographic_reexecution_performed', 'final_decision_on_pass', 'github_runner_immutable_build_environment', 'metadata_authority_file_count', 'portable_exact_fileset_count', 'result_equals_complete_fips_204_conformance', 'result_equals_complete_sigver_coverage', 'result_equals_fips_204_certification', 'result_equals_nist_validation', 'root_v0_3_authority_file_count', 'semantic_mutation_coverage_is_complete_claim_allowed', 'third_party_independent_reproduction', 'workflow_dispatched']

EXPECTED_SEMANTIC_CONTRACT_SHA256 = 'b20b228493e780d0eb6aa6c64280e4cfeaf138856fe7e8f418056f36f2402874'

ROOT_V02 = 'verify_qsv_mldsa_corpus_v0_2.py'
ROOT_V02_SIDECAR = 'verify_qsv_mldsa_corpus_v0_2.py.sha256'

ROOT_V02_SHA = '29c9efda22b2041bd658759696d707c4cd33b7942f199704acab30c6d075fe54'
ROOT_V02_SIDECAR_FILE_SHA = 'fc213d207946023d2e8fa3c6aa9afddebf984c67b7f5acc703c87c531e4c76ff'
ROOT_V02_OUTPUT_SHA = '131b38797c5f57513402a8205d45a3c6de094e773785bfd6dc7cb15c0f944416'

PLANNED_DIR = (
    "results/"
    "qsv_mldsa_linux_sixcase_"
    "metadata_only_public_run_evidence_v0_2"
)

PLANNED_DEDICATED_VERIFIER = 'results/qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_v0_2/verify_qsv_mldsa_linux_sixcase_metadata_only_public_run_evidence_candidate_v0_2.py'

DEDICATED_OUTPUT_SHA = 'b5746100759870b260f5452273307f384a7d203eba2cafb22ae16f3b0610361f'

SELF_NAME = 'verify_qsv_mldsa_corpus_v0_3.py'
SELF_SIDECAR_NAME = 'verify_qsv_mldsa_corpus_v0_3.py.sha256'

BASE_COMMIT = SEMANTIC_CONTRACT["baseline_commit"]
BASE_TREE = SEMANTIC_CONTRACT["baseline_tree"]

EXPECTED_FILES = (
    set(BASELINE_HASHES)
    | set(FOUR_AUTHORITY_HASHES)
    | {
        SELF_NAME,
        SELF_SIDECAR_NAME,
    }
)


def semantic_contract_canonical_bytes():
    return json.dumps(
        SEMANTIC_CONTRACT,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def expected_directories():
    result = set()

    for rel in EXPECTED_FILES:
        parent = Path(rel).parent

        while str(parent) not in ("", "."):
            result.add(
                parent.as_posix()
            )

            parent = parent.parent

    return result


EXPECTED_DIRECTORIES = expected_directories()

ROOT = (
    Path(sys.argv[1]).resolve()
    if len(sys.argv) == 2
    else Path(__file__).resolve().parent
)

failures = []
checks = 0


def check(name, condition):
    global checks

    checks += 1

    if condition:
        print(
            "PASS: " + name
        )
    else:
        print(
            "FAIL: " + name
        )

        failures.append(
            name
        )


def digest(path):
    h = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            block = handle.read(
                1024 * 1024
            )

            if not block:
                break

            h.update(block)

    return h.hexdigest()


actual_files = {
    path.relative_to(
        ROOT
    ).as_posix()
    for path in ROOT.rglob("*")
    if path.is_file()
}

actual_directories = {
    path.relative_to(
        ROOT
    ).as_posix()
    for path in ROOT.rglob("*")
    if path.is_dir()
    and not path.is_symlink()
}

symlinks = [
    path.relative_to(
        ROOT
    ).as_posix()
    for path in ROOT.rglob("*")
    if path.is_symlink()
]

check(
    "portable physical file count 90",
    len(actual_files)
    == SEMANTIC_CONTRACT[
        "portable_exact_fileset_count"
    ],
)

check(
    "portable exact fileset",
    actual_files == EXPECTED_FILES,
)

check(
    "portable exact directory topology",
    actual_directories
    == EXPECTED_DIRECTORIES,
)

check(
    "portable symlink absence",
    symlinks == [],
)

self_path = ROOT / SELF_NAME
self_sidecar = ROOT / SELF_SIDECAR_NAME

check(
    "root v0.3 self file exists",
    self_path.is_file()
    and not self_path.is_symlink(),
)

check(
    "root v0.3 sidecar exists",
    self_sidecar.is_file()
    and not self_sidecar.is_symlink(),
)

sidecar_tokens = []

if self_sidecar.is_file():
    sidecar_tokens = (
        self_sidecar.read_text(
            encoding="utf-8"
        ).strip().split()
    )

check(
    "root v0.3 sidecar token count",
    len(sidecar_tokens) == 2,
)

check(
    "root v0.3 sidecar basename",
    len(sidecar_tokens) == 2
    and sidecar_tokens[1] == SELF_NAME,
)

check(
    "root v0.3 self integrity",
    len(sidecar_tokens) == 2
    and self_path.is_file()
    and digest(self_path)
        == sidecar_tokens[0],
)

check(
    "semantic contract exact key set",
    set(SEMANTIC_CONTRACT)
    == set(
        EXPECTED_SEMANTIC_CONTRACT_KEYS
    ),
)

observed_semantic_contract_sha = (
    hashlib.sha256(
        semantic_contract_canonical_bytes()
    ).hexdigest()
)

check(
    "semantic contract canonical SHA-256 binding",
    observed_semantic_contract_sha
    == EXPECTED_SEMANTIC_CONTRACT_SHA256,
)

baseline_hash_match = True

for rel, expected_sha in BASELINE_HASHES.items():
    path = ROOT / rel

    if (
        not path.is_file()
        or path.is_symlink()
        or digest(path) != expected_sha
    ):
        baseline_hash_match = False
        break

check(
    "exact 84-file baseline hash binding",
    baseline_hash_match,
)

four_hash_match = True

for rel, expected_sha in FOUR_AUTHORITY_HASHES.items():
    path = ROOT / rel

    if (
        not path.is_file()
        or path.is_symlink()
        or digest(path) != expected_sha
    ):
        four_hash_match = False
        break

check(
    "exact four-file metadata authority hash binding",
    four_hash_match,
)

check(
    "root v0.2 byte binding",
    (
        ROOT / ROOT_V02
    ).is_file()
    and digest(
        ROOT / ROOT_V02
    ) == ROOT_V02_SHA,
)

check(
    "root v0.2 sidecar byte binding",
    (
        ROOT / ROOT_V02_SIDECAR
    ).is_file()
    and digest(
        ROOT / ROOT_V02_SIDECAR
    ) == ROOT_V02_SIDECAR_FILE_SHA,
)

root_v02_rc = None
root_v02_output = b""

if baseline_hash_match:
    with tempfile.TemporaryDirectory(
        prefix="qsv-root-v03-hardened-baseline84-"
    ) as temp_name:

        temp_root = Path(
            temp_name
        )

        for rel in BASELINE_HASHES:
            src = ROOT / rel
            dst = temp_root / rel

            dst.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copy2(
                src,
                dst,
            )

        env = os.environ.copy()

        env[
            "PYTHONDONTWRITEBYTECODE"
        ] = "1"

        env.pop(
            "QSV_EXECUTE_CRYPTO",
            None,
        )

        proc = subprocess.run(
            [
                sys.executable,
                "-B",
                str(
                    temp_root
                    / ROOT_V02
                ),
                str(
                    temp_root
                ),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )

        root_v02_rc = proc.returncode
        root_v02_output = proc.stdout

check(
    "isolated exact84 root v0.2 execution",
    root_v02_rc == 0,
)

check(
    "isolated exact84 root v0.2 output binding",
    root_v02_rc == 0
    and hashlib.sha256(
        root_v02_output
    ).hexdigest()
        == ROOT_V02_OUTPUT_SHA,
)

dedicated_path = (
    ROOT
    / PLANNED_DEDICATED_VERIFIER
)

dedicated_root = (
    ROOT
    / PLANNED_DIR
)

dedicated_rc = None
dedicated_output = b""

if (
    four_hash_match
    and dedicated_path.is_file()
):

    env = os.environ.copy()

    env[
        "PYTHONDONTWRITEBYTECODE"
    ] = "1"

    env.pop(
        "QSV_EXECUTE_CRYPTO",
        None,
    )

    proc = subprocess.run(
        [
            sys.executable,
            "-B",
            str(
                dedicated_path
            ),
            str(
                dedicated_root
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )

    dedicated_rc = proc.returncode
    dedicated_output = proc.stdout

check(
    "dedicated metadata verifier execution",
    dedicated_rc == 0,
)

check(
    "dedicated metadata verifier output binding",
    dedicated_rc == 0
    and hashlib.sha256(
        dedicated_output
    ).hexdigest()
        == DEDICATED_OUTPUT_SHA,
)

check(
    "parent crypto execution environment absent",
    "QSV_EXECUTE_CRYPTO"
    not in os.environ,
)

print(
    "qsv_mldsa_corpus_v0_3_check_count="
    + str(checks)
)

print(
    "qsv_mldsa_corpus_v0_3_pass_count="
    + str(
        checks
        - len(failures)
    )
)

print(
    "qsv_mldsa_corpus_v0_3_failure_count="
    + str(
        len(failures)
    )
)

print(
    "PORTABLE_EXACT_FILESET_COUNT="
    + str(
        SEMANTIC_CONTRACT[
            "portable_exact_fileset_count"
        ]
    )
)

print(
    "BASELINE_84_FILE_COUNT="
    + str(
        SEMANTIC_CONTRACT[
            "baseline_file_count"
        ]
    )
)

print(
    "METADATA_ONLY_AUTHORITY_FILE_COUNT="
    + str(
        SEMANTIC_CONTRACT[
            "metadata_authority_file_count"
        ]
    )
)

print(
    "ROOT_V0_3_AUTHORITY_FILE_COUNT="
    + str(
        SEMANTIC_CONTRACT[
            "root_v0_3_authority_file_count"
        ]
    )
)

print(
    "BASELINE_COMMIT="
    + SEMANTIC_CONTRACT[
        "baseline_commit"
    ]
)

print(
    "BASELINE_TREE="
    + SEMANTIC_CONTRACT[
        "baseline_tree"
    ]
)

print(
    "SEMANTIC_CONTRACT_SHA256="
    + observed_semantic_contract_sha
)

print(
    "CRYPTOGRAPHIC_REEXECUTION_PERFORMED="
    + SEMANTIC_CONTRACT[
        "cryptographic_reexecution_performed"
    ]
)

print(
    "WORKFLOW_DISPATCHED="
    + SEMANTIC_CONTRACT[
        "workflow_dispatched"
    ]
)

print(
    "THIRD_PARTY_INDEPENDENT_REPRODUCTION="
    + SEMANTIC_CONTRACT[
        "third_party_independent_reproduction"
    ]
)

print(
    "GITHUB_RUNNER_IMMUTABLE_BUILD_ENVIRONMENT="
    + SEMANTIC_CONTRACT[
        "github_runner_immutable_build_environment"
    ]
)

print(
    "ABSOLUTE_OPENSSL_BUILD_PROVENANCE_COMPLETE_CLAIM_ALLOWED="
    + SEMANTIC_CONTRACT[
        "absolute_openssl_build_provenance_complete_claim_allowed"
    ]
)

print(
    "RESULT_EQUALS_NIST_VALIDATION="
    + SEMANTIC_CONTRACT[
        "result_equals_nist_validation"
    ]
)

print(
    "RESULT_EQUALS_FIPS_204_CERTIFICATION="
    + SEMANTIC_CONTRACT[
        "result_equals_fips_204_certification"
    ]
)

print(
    "RESULT_EQUALS_COMPLETE_FIPS_204_CONFORMANCE="
    + SEMANTIC_CONTRACT[
        "result_equals_complete_fips_204_conformance"
    ]
)

print(
    "RESULT_EQUALS_COMPLETE_SIGVER_COVERAGE="
    + SEMANTIC_CONTRACT[
        "result_equals_complete_sigver_coverage"
    ]
)

print(
    "SEMANTIC_MUTATION_COVERAGE_IS_COMPLETE_CLAIM_ALLOWED="
    + SEMANTIC_CONTRACT[
        "semantic_mutation_coverage_is_complete_claim_allowed"
    ]
)

if failures:
    print(
        "QSV_MLDSA_CORPUS_V0_3_UNIFIED_VERIFICATION=FAIL"
    )

    raise SystemExit(1)

print(
    "QSV_MLDSA_CORPUS_V0_3_UNIFIED_VERIFICATION="
    + SEMANTIC_CONTRACT[
        "final_decision_on_pass"
    ]
)
