#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

BINDING = (
    ROOT
    / "lineage"
    / "bindings"
    / "qsv-mldsa-implementation-source-lineage-v0.1.json"
)

BINDING_SIDECAR = Path(
    str(BINDING) + ".sha256"
)

SELF = ROOT / "verify_qsv_mldsa_source_lineage_v0_1.py"

SELF_SIDECAR = ROOT / (
    "verify_qsv_mldsa_source_lineage_v0_1.py.sha256"
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

check(
    "schema",
    data["schema"]
    == "qsv.mldsa.implementation-source-lineage-binding.v0.1",
)

check(
    "version",
    data["version"] == "0.1",
)

check(
    "status",
    data["status"]
    == "source_lineage_bound_fixture_execution_pending",
)

check(
    "role",
    data["role"]
    == "append_only_implementation_source_lineage_evidence",
)

base = data["base_corpus_authority"]

check(
    "base repository",
    base["repository"]
    == "mokkunsuzuki-code/qsv-mldsa-interoperability-corpus",
)

check(
    "base commit",
    base["commit"]
    == "5c43415a2570ec0e1e3e8211b589f7a9916108a1",
)

check(
    "base tree",
    base["tree"]
    == "67fd0ecdf14f49523dd94f95fbfee908b39312a3",
)

norm = data["normative_reference"]

check(
    "QSV repository",
    norm["repository"]
    == "mokkunsuzuki-code/qsv-reference-model",
)

check(
    "QSV tag",
    norm["tag"] == "v1.0",
)

check(
    "QSV target",
    norm["target_commit"]
    == "a900f9c19aae2b165472290dbd4ccc83137433f9",
)

historical = data["historical_evidence_source"]

check(
    "Stage393 repository",
    historical["repository"]
    == "mokkunsuzuki-code/stage393",
)

check(
    "Stage393 commit",
    historical["commit"]
    == "61809515b6db87123ea60b404d6db4e6751bcac2",
)

check(
    "Stage393 tree",
    historical["tree"]
    == "1ddb9e5d54b4de5e91a3e1b75c635b82213c0d17",
)

openssl = data["implementations"]["openssl"]

check(
    "OpenSSL id",
    openssl["implementation_id"]
    == "openssl",
)

runtime = openssl["observed_runtime"]

check(
    "OpenSSL runtime",
    runtime["version"]
    == "OpenSSL 3.6.3 9 Jun 2026 (Library: OpenSSL 3.6.3 9 Jun 2026)",
)

check(
    "OpenSSL binary",
    runtime["binary"]
    == "/opt/homebrew/Cellar/openssl@3/3.6.3/bin/openssl",
)

check(
    "OpenSSL binary hash",
    runtime["binary_sha256"]
    == "5d8f84484b7317ec5639ce68ccecc1d6f565ca6df483c8ae731e25265d83466d",
)

upstream = openssl["upstream_release"]

check(
    "OpenSSL upstream repository",
    upstream["repository"]
    == "https://github.com/openssl/openssl.git",
)

check(
    "OpenSSL release tag",
    upstream["tag"]
    == "openssl-3.6.3",
)

check(
    "OpenSSL tag object",
    upstream["tag_object"]
    == "e5c234b0c471a676ae6141d2f157df61eb293477",
)

check(
    "OpenSSL source commit",
    upstream["source_commit"]
    == "aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f",
)

check(
    "OpenSSL source tree",
    upstream["source_tree"]
    == "a8a306c000bc2426afd3264b2c41bc7223728475",
)

check(
    "OpenSSL VERSION.dat hash",
    upstream["version_dat_sha256"]
    == "13996b257fa122047907c75bb6605cf9b18859099e555d8091dfc95df6344470",
)

check(
    "OpenSSL VERSION.dat blob",
    upstream["version_dat_git_blob"]
    == "1926982f6388b752f19dde368a04b4b09e6a66a6",
)

brew = openssl["homebrew_observation"]

check(
    "Homebrew formula",
    brew["formula"] == "openssl@3",
)

check(
    "Homebrew stable observed",
    brew["stable_version_observed"]
    == "3.6.4",
)

check(
    "Homebrew installed observed",
    brew["installed_version_observed"]
    == "3.6.3",
)

check(
    "Homebrew metadata hash",
    brew["metadata_sha256"]
    == "312f2abccd4297078aa7c4f11d2906a5f8e2b820c39b4c78ecf47d5857bdf1fd",
)

build = openssl["build_provenance"]

check(
    "OpenSSL binary source commit not proven",
    build["local_binary_source_commit_proven"]
    is False,
)

check(
    "OpenSSL build provenance incomplete",
    build["complete"] is False,
)

check(
    "OpenSSL provenance status",
    build["status"] == "incomplete",
)

check(
    "OpenSSL provenance reason exact",
    build["reason"]
    == 'runtime_version_and_upstream_tag_are_verified_but_source_to_local_binary_build_chain_is_not_yet_cryptographically_established',
)

check(
    "implementation set exact",
    set(data["implementations"].keys())
    == {
        "openssl",
        "cloudflare_circl",
    },
)

circl = data[
    "implementations"
][
    "cloudflare_circl"
]

check(
    "CIRCL id",
    circl["implementation_id"]
    == "cloudflare-circl",
)

check(
    "CIRCL repository",
    circl["repository"]
    == "https://github.com/cloudflare/circl.git",
)

check(
    "CIRCL source commit",
    circl["source_commit"]
    == "cfa7c70defd831ffb0792ab2af560bfef43d60ca",
)

check(
    "CIRCL source tree",
    circl["source_tree"]
    == "b3a50c3f1b7a5f8cfac0cce655ae7ea7900e9139",
)

check(
    "CIRCL go.mod hash",
    circl["go_mod_sha256"]
    == "79b9daccc7f033377bcbc70524418d999a1677849924d7b5e488e646c4cf00d7",
)

check(
    "CIRCL go.sum hash",
    circl["go_sum_sha256"]
    == "3d75d69d3b553e9aa69e1278de681b8dc55c28c6e4233bb398c5b7373c3abd0a",
)

check(
    "CIRCL go.mod blob",
    circl["go_mod_git_blob"]
    == "f4ab94067d62a67bb50733fab6e41eab38434146",
)

check(
    "CIRCL go.sum blob",
    circl["go_sum_git_blob"]
    == "c6d3ed6c6bc51c566570ee9c19b4187f094fca49",
)

check(
    "CIRCL upstream commit match",
    circl["upstream_commit_match"]
    is True,
)

check(
    "CIRCL upstream tree match",
    circl["upstream_tree_match"]
    is True,
)

check(
    "CIRCL execution pending",
    circl[
        "fixture_execution_from_pinned_source_performed"
    ] is False,
)

truth = data["truth_boundaries"]

check(
    "agreement not correctness",
    truth["agreement_implies_correctness"]
    is False,
)

check(
    "hash not provenance",
    truth["hash_alone_implies_build_provenance"]
    is False,
)

check(
    "version not provenance",
    truth["version_string_implies_build_provenance"]
    is False,
)

execution = data["execution_state"]

check(
    "fixture generation pending",
    execution[
        "cryptographic_fixture_generation_performed"
    ] is False,
)

check(
    "fixture execution pending",
    execution[
        "cryptographic_fixture_execution_performed"
    ] is False,
)

check(
    "fixture results unpublished",
    execution[
        "fixture_results_published"
    ] is False,
)

check(
    "independence not verified",
    execution[
        "two_independent_implementations_verified"
    ] is False,
)

declared_binding_sha = (
    BINDING_SIDECAR
    .read_text(
        encoding="utf-8"
    )
    .split()[0]
)

check(
    "binding sidecar",
    declared_binding_sha
    == sha256(BINDING),
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
        declared_self_sha
        == sha256(SELF),
    )
else:
    check(
        "self hash",
        False,
    )

print(
    "qsv_mldsa_source_lineage_check_count="
    + str(checks)
)

print(
    "qsv_mldsa_source_lineage_pass_count="
    + str(
        checks - len(failures)
    )
)

print(
    "qsv_mldsa_source_lineage_failure_count="
    + str(len(failures))
)

if failures:
    for name in failures:
        print(
            "FAIL: " + name
        )

    raise SystemExit(1)

print(
    "QSV_MLDSA_SOURCE_LINEAGE_BINDING_VERIFICATION=PASS"
)
