#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

BINDING = (
    ROOT
    / "vectors"
    / "bindings"
    / "qsv-mldsa-nist-acvp-vector-source-v0.1.json"
)

BINDING_SIDECAR = Path(
    str(BINDING) + ".sha256"
)

SELF = (
    ROOT
    / "verify_qsv_mldsa_nist_acvp_vector_source_v0_1.py"
)

SELF_SIDECAR = Path(
    str(SELF) + ".sha256"
)

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


data = json.loads(
    BINDING.read_text(
        encoding="utf-8"
    )
)

expected_top_keys = {
    "schema",
    "version",
    "status",
    "role",
    "base_corpus_authority",
    "source_authority",
    "selected_vector_surface",
    "selection_evidence",
    "truth_boundaries",
    "execution_state",
}

check(
    "top-level key set exact",
    set(data.keys()) == expected_top_keys,
)

check(
    "identity exact",
    (
        data["schema"]
        == "qsv.mldsa.nist-acvp-vector-source-binding.v0.1"
        and data["version"] == "0.1"
        and data["status"]
        == "authoritative_vector_source_bound_execution_pending"
        and data["role"]
        == "append_only_known_answer_vector_source_authority"
    ),
)

check(
    "base corpus authority exact",
    data["base_corpus_authority"]
    == {
        "repository":
            "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
        "commit":
            "27967c03620f099793a1edb3aa1c07487487c736",
        "tree":
            "a9bd9e3dff66a2267cf66ed26ace8be0ed8c1078",
    },
)

expected_source_authority = {
    "organization": "NIST",
    "repository": "https://github.com/usnistgov/ACVP-Server.git",
    "selected_tag": "v1.1.0.43",
    "selected_commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
    "selected_tree": "a6b81add7faf8a8b647afcdc54268615decde9b5",
    "prior_tag": "v1.1.0.42",
    "prior_commit": "15c0f3deeefbfa8cb6cd32a99e1ca3b738c66bf0",
    "prior_tree": "757c230c95b7b90c9f0f0def5ea5b813347bf8f2",
    "master_equal_selected_at_discovery": True,
    "selected_release_metadata_sha256":
        "89db9445342a74034e463257e6023fd81921751927ea99d5bb03c18f06fa23a9",
    "prior_release_metadata_sha256":
        "4e7d0b005c5dc67362182721496fe8199a8b846609481235bdcfaff0d15a3e3d",
    "selected_github_release_immutable": False,
    "selected_release_published_at": "2026-08-12T19:32:51Z",
    "selected_release_updated_at": "2026-08-20T17:48:32Z",
}

check(
    "source authority exact",
    data["source_authority"]
    == expected_source_authority,
)

expected_files = [
    {
        "path": "gen-val/json-files/ML-DSA-keyGen-FIPS204/expectedResults.json",
        "sha256": "361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df",
        "git_blob": "38213cd71c20c019cc49bf140f616ed86c81ad98",
        "size_bytes": 873632,
    },
    {
        "path": "gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json",
        "sha256": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
        "git_blob": "ebf2104da140b725675aea4cc47676c0536421f7",
        "size_bytes": 882437,
    },
    {
        "path": "gen-val/json-files/ML-DSA-keyGen-FIPS204/prompt.json",
        "sha256": "43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef",
        "git_blob": "f53809df5fefee2c1b80da1122885a2e0e843e32",
        "size_bytes": 10062,
    },
    {
        "path": "gen-val/json-files/ML-DSA-keyGen-FIPS204/registration.json",
        "sha256": "2e9b42aebf24105d8d76c7fbb13b572d992fa32bde21efdd7033cfd077e99f49",
        "git_blob": "819a0d60bb17941355261cb12f9b79d05ad235bd",
        "size_bytes": 183,
    },
    {
        "path": "gen-val/json-files/ML-DSA-keyGen-FIPS204/validation.json",
        "sha256": "aa9f9c13a14403e2fbb5c15ec94373f71295a481b7942a2087cf87b943495743",
        "git_blob": "35d613401d1e056d9f75a17953d3f39bb620a192",
        "size_bytes": 4251,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204/expectedResults.json",
        "sha256": "228d011bbe274aeb93e22eea1e0d57b78f43795cf6a64fb5ef1e626485a0bedb",
        "git_blob": "d9923ac185db3955a1a1c8e4009ded404a4eec9b",
        "size_bytes": 2511972,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json",
        "sha256": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22",
        "git_blob": "c090942249958e2071d56bf458b19e31256ded3e",
        "size_bytes": 8971659,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204/prompt.json",
        "sha256": "447749d72817b211160d243311ce32302f3023e59c355b0f70be2bd3e9e7830d",
        "git_blob": "d8325788fe4805a9598490f14c6adec07fe648fe",
        "size_bytes": 5044293,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204/registration.json",
        "sha256": "77d55da953f3d4b0f4ce08363c40957cb70a8105a03edcf5437eb3e76f33dcc6",
        "git_blob": "8eb9d77ff71344e7cdad946d96c20b8a6d43c7ec",
        "size_bytes": 960,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204/validation.json",
        "sha256": "68d9c349b122dfe2fad75e1379a62874c0eeda0ebb924d7d47c36303eb8bd816",
        "git_blob": "e7d566b874d82b737754b3c27735af052ff37950",
        "size_bytes": 20472,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/expectedResults.json",
        "sha256": "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6",
        "git_blob": "dba8bcfe5f090503c9390701c11677389752cecd",
        "size_bytes": 13956,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "sha256": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
        "git_blob": "4c8caf12220e44dfa711fefe20e0285aaad844be",
        "size_bytes": 4533178,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json",
        "sha256": "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e",
        "git_blob": "22b0803253f7aa24644229acd04c387d260e874a",
        "size_bytes": 3125947,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/registration.json",
        "sha256": "55878cee2c7a8cf275f4138231f1b5f98880ff81a99face609207415053fb859",
        "git_blob": "23dcb3ef6e694c4e95c99914e581fb2b37ba1bc8",
        "size_bytes": 914,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/validation.json",
        "sha256": "2433c4bada43c5257e7424490cdccacf2cb0a08dc302cadd9d9447ecf79c5a89",
        "git_blob": "45d48577e235403393be9b4af8cfc7e60952270d",
        "size_bytes": 10212,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/expectedResults.json",
        "sha256": "8d86d120d128d2f2d29afb7843b7351677ac0f1bf649295d85b7bf3dd533949c",
        "git_blob": "bc66e2ac41133210152da3365fb0bcf7775f3ec2",
        "size_bytes": 5023936,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/internalProjection.json",
        "sha256": "b61576c765b1eb0e6a667a67a68380df944592be8740f9c020c9ea5a89136f18",
        "git_blob": "a509348a466eff95244d791818cf7c1b9e386212",
        "size_bytes": 17939006,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/prompt.json",
        "sha256": "0a81a213fb4825f0a9d8893a20445a3fed88a6f1832703548120b9588c74a08e",
        "git_blob": "01d04c264d991ca3598c848566ed8c24f3b35c8f",
        "size_bytes": 7288994,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/registration.json",
        "sha256": "62b73d04720e6cd567067c13079ccf436b2e2b07b77740887b4c7d093a09a4cb",
        "git_blob": "893c1362ca68c8ecbcecd13dff5188fc50a20343",
        "size_bytes": 1014,
    },
    {
        "path": "gen-val/json-files/ML-DSA-sigGen-FIPS204-tr1/validation.json",
        "sha256": "d776dc4dbc879bfaf69a66083fe3ef4f2f28c27f109290b4351504c56dbefcd1",
        "git_blob": "2a65c58aeee8c4050cd068bc7be997c934177c22",
        "size_bytes": 40992,
    },
]

surface = data["selected_vector_surface"]

check(
    "selected vector counts exact",
    (
        surface["base_fips204_file_count"] == 15
        and surface["fips204_tr1_siggen_file_count"] == 5
        and surface["total_file_count"] == 20
        and surface["prior_revision_tr1_siggen_file_count"] == 0
        and surface["selected_revision_tr1_siggen_file_count"] == 5
    ),
)

check(
    "parameter sets exact",
    surface["parameter_sets"]
    == [
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
    ],
)

check(
    "discovery binding-set digest exact",
    surface["discovery_binding_set_sha256"]
    == "5ecee116974b667aada74e91823d987174f500605a13f13b70db379844c9b2df",
)

check(
    "exact 20 file binding records",
    surface["files"] == expected_files,
)

check(
    "selection evidence exact",
    data["selection_evidence"]
    == {
        "selected_release_declares_mldsa_fips204_tr1": True,
        "selected_release_declares_externalmu_fix": True,
        "selected_release_declares_modifyz_fix": True,
        "selected_release_declares_tr1_prod_enablement": True,
        "stable_to_selected_base15_changed_file_count": 9,
        "selected_to_master_base15_changed_file_count_at_discovery": 0,
    },
)

check(
    "truth boundaries exact",
    data["truth_boundaries"]
    == {
        "source_snapshot_implies_cryptographic_correctness": False,
        "vector_presence_implies_implementation_conformance": False,
        "nist_source_binding_implies_nist_validation_of_qsv": False,
        "selected_revision_implies_all_implementations_support_all_vector_semantics": False,
    },
)

check(
    "execution state exact",
    data["execution_state"]
    == {
        "nist_vector_payload_copied_to_corpus": False,
        "public_test_secret_material_copied_to_corpus": False,
        "public_test_secret_material_authorized": False,
        "cryptographic_fixture_generation_performed": False,
        "cryptographic_fixture_execution_performed": False,
        "fixture_results_published": False,
    },
)

declared_binding_sha = (
    BINDING_SIDECAR
    .read_text(
        encoding="utf-8"
    )
    .split()[0]
)

check(
    "binding sidecar hash",
    declared_binding_sha == sha256(BINDING),
)

check(
    "self sidecar exists",
    SELF_SIDECAR.is_file(),
)

if SELF_SIDECAR.is_file():
    declared_self_sha = (
        SELF_SIDECAR
        .read_text(
            encoding="utf-8"
        )
        .split()[0]
    )

    check(
        "self hash",
        declared_self_sha == sha256(SELF),
    )
else:
    check(
        "self hash",
        False,
    )

print(
    "qsv_mldsa_nist_vector_check_count="
    + str(checks)
)

print(
    "qsv_mldsa_nist_vector_pass_count="
    + str(checks - len(failures))
)

print(
    "qsv_mldsa_nist_vector_failure_count="
    + str(len(failures))
)

if failures:
    for name in failures:
        print("FAIL: " + name)

    raise SystemExit(1)

print(
    "QSV_MLDSA_NIST_ACVP_VECTOR_SOURCE_VERIFICATION=PASS"
)
