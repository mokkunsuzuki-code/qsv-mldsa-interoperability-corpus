# QSV ML-DSA Interoperability Corpus

Version: **0.1**

This repository is an implementation artifact for the **Quantum Security Verification (QSV) Reference Model v1.0**.

It is intended to turn ML-DSA interoperability and conformance claims into small, versioned, reproducible evidence units.

## Status

**F7 six-case runtime invocation evidence is durably published, a deterministic metadata-only normalized result layer is available, and the append-only neutral fixture v0.3 gap-closure layer is publicly available in this repository.**

Version 0.1 defines the corpus contract, fixture schema, provenance requirements, implementation-lineage model, fixture plan, and common runner interface.

The current F7 scope publishes metadata-only evidence for six selected NIST ACVP ML-DSA `sigVer` cases across OpenSSL and Cloudflare CIRCL. No private keys, secret keys, raw vector payloads, raw stdout, raw stderr, or harness binaries are published by the normalized result layer.

## F7 normalized result

The F7 normalized layer contains **12 implementation-level records**: six OpenSSL invocations and six Cloudflare CIRCL invocations over the same six selected cases.

`observed_acceptance` is marked as **derived**, not directly captured. Its derivation is fail-closed and uses the pinned harness semantics, F7 exact runtime `argv`, the actual process exit status, and the SHA-256 commitment of the successful-path stdout. `expected_valid` is not unconditionally copied into `observed_acceptance`, and workflow success is not used as the observation.

Normalization performs **no new cryptographic execution**.

To independently regenerate and verify the normalized result from the published F7 evidence:

`PYTHONDONTWRITEBYTECODE=1 python3 runtime/verify_qsv_mldsa_normalized_result_adapter_v0_1.py .`

This remains first-party instrumented reproduction evidence. It is **not** third-party independent reproduction, NIST validation, FIPS 204 certification, proof of complete FIPS 204 conformance, proof of complete `sigVer` coverage, or proof of universal ML-DSA correctness.

## Neutral fixture v0.3

The append-only neutral fixture v0.3 layer provides an implementation-neutral fixture envelope without rewriting the existing v0.2 normalized-result authority.

It includes:

- a machine-readable `urn:qsv:mldsa:fixture:0.3` JSON Schema;
- a deterministic offline NIST ACVP `prompt.json` + `expectedResults.json` to neutral-fixture mapper;
- one NIST ACVP positive `sigVer` canonical example;
- one NIST ACVP negative `sigVer` canonical example;
- one Wycheproof negative signing canonical example; and
- explicit source-case and neutral-fixture canonicalization rules.

All three canonical examples are metadata-only. Raw vector payloads, raw private test keys, raw secret material, and raw private seeds are not copied into the canonical example files.

`case_source_sha256` is **not** a hash of raw source-file bytes. It is a domain-separated SHA-256 commitment over the canonical source-case descriptor, including pinned source-file hashes, source-case identity, expected outcome, and artifact commitments. The actual upstream source-file SHA-256 values remain separately recorded in `source_binding.source_files[]`.

`neutral_fixture_sha256` is a separate domain-separated SHA-256 commitment over the canonical neutral fixture with the self-hash field excluded.

The ACVP mapper performs metadata transformation only. It performs **no new ML-DSA cryptographic execution**.

Public metadata-only verification can be run with:

`PYTHONDONTWRITEBYTECODE=1 python3 runtime/verify_qsv_mldsa_neutral_fixture_gap_closure_v0_1.py --root .`

Full source regeneration additionally requires locally supplied bytes from the exact pinned NIST ACVP and Wycheproof commits. The verifier itself performs no network fetch.

This layer does **not** imply NIST validation, FIPS 204 certification, complete FIPS 204 conformance, universal ML-DSA correctness, third-party independent reproduction, or security-vulnerability absence.

## Normative methodology

QSV Reference Model v1.0:

`Claim → Evidence → Binding → Verification → Independent Reproduction → Adjudication`

The corpus applies four evidence dimensions:

1. Known-answer conformance
2. Cross-implementation interoperability
3. Negative behavior
4. Reproduction integrity

## Initial ML-DSA scope

The plan covers:

- ML-DSA-44
- ML-DSA-65
- ML-DSA-87
- key generation
- signing
- verification
- bidirectional interoperability
- empty contexts
- maximum-length contexts where supported
- mismatched contexts
- deterministic signing
- hedged/randomized signing where supported
- malformed and non-canonical negative cases

## Critical boundaries

**Agreement ≠ Correctness**

Two implementations producing the same result does not independently prove correctness.

**Timestamp ≠ Cryptographic Correctness**

Timestamp evidence can establish ordering or existence of artifacts, but not ML-DSA conformance.

**Unknown / Pending ≠ Verified**

Unsupported, pending, unknown, or unexecuted cases remain explicit and must never be promoted to verified.

**Randomized Signature ≠ Byte Equality**

For hedged or randomized signing, interoperability is evaluated through successful verification and recorded randomness mode, not signature byte equality.

**Wrapper Diversity ≠ Implementation Independence**

Two wrappers around the same underlying implementation do not count as two independent implementations.

## Initial implementations

The first planned matrix uses:

- OpenSSL
- Cloudflare CIRCL

Their implementation lineage must be recorded independently of wrapper names.

## Stage393 relationship

Stage393 is retained only as historical evidence and engineering provenance for the initial design.

Stage393 is **not** a normative runtime dependency of this corpus.

A completed corpus release must be independently runnable without requiring Stage393.

## Public test-secret boundary

No production private keys are permitted.

Version 0.1 does not yet authorize publication of generated test secret material. Any later public deterministic test seed or private test key must be explicitly classified as non-production test material and deliberately approved for publication before inclusion.

## What this corpus does not prove

This repository does not itself establish:

- formal certification
- universal ML-DSA correctness
- security-vulnerability absence
- implementation bug absence
- package-wide PQC readiness
- hardware-wide PQC readiness
- system-wide quantum safety
- PQCA endorsement
- Open Quantum Safe endorsement

## License

MIT

## Proposed one-case source-bound acceptance v0.2 (not merged)

The neutral fixture v0.3 schema and verifier remain unchanged. The historical
metadata-only default that reports `SOURCE_REGENERATION_PERFORMED=NO` is not a
source-bound PASS. The separate proposed `source_bound` path requires a fresh
pinned A03 gate, A04 regeneration twice from original NIST Raw, exact published
fixture byte matching, and both actual consumed source-file SHA-256 values in
each accepted normalized evidence record. The consumer has exactly 11 bound
identity fields; historical source-to-runtime provenance remains `incomplete`.

Only OpenSSL / ML-DSA-44 / NIST sigVer `tgId=1`, `tcId=1`,
`expected_valid=false` is within scope. Evidence-record acceptance does **not**
mean that an ML-DSA signature was accepted. The historical three-source
Wycheproof mode and original R2 adapter have not been retroactively repaired.

The **migrated v0.1** adapter (21,742 bytes; SHA-256
`d1e51068bbadbae4d1214f6e9f0c9df35f8c9ea934fa5028fd63cd1a5dfcbe59`)
has one local, unattested fixed-case Positive ACCEPT + N01 REJECT experiment,
with read-only evidence postflight (`PASS_LOCAL_UNATTESTED`). This is not
third-party independent reproduction or official acceptance.

The **v0.2** adapter in
`runtime/qsv_mldsa_source_bound_gate_first_adapter_v0_2.py` was run in a
fresh, explicitly authorized **fixed one-case local E2E** on **2026-11-09 JST**
(`PASS_LOCAL_UNATTESTED`). The external Supervisor recorded one launch, exit
code 0, no timeout, and no retry. The original NIST Raw inputs passed the
current A03 source gate (`PREACCEPTANCE_PASS`); the Target observed two A04
regenerations and **one accepted normalized evidence record**. The previously
saved one-byte N01 mutation was rejected with
`PINNED_SOURCE_DIGEST_MISMATCH` before construction, yielding **zero accepted
negative results**. The positive record contains the current source-gate
status, two consumed NIST Raw SHA-256 digests, and eleven consumer bindings.
These findings cover only OpenSSL / ML-DSA-44 / `tgId=1` / `tcId=1` /
`expected_valid=false`, not universal ACVP/Wycheproof support.

This is a local unattested observation, **not** third-party independent
reproduction, NIST validation, cryptographic certification, or official
acceptance. A positive accepted *evidence record* does not mean the signature
is valid. Call counts for A03/A04/constructor are **Target-self-observed**,
not external function-level witnessing. The full A03 Envelope was not saved
as an independently rehashable Raw file. The local Supervisor and four saved
execution Evidence files are **not in this public source patch**; standalone
public reproduction of the private CORE-bound workflow is `NOT_ESTABLISHED`.

The ordinary discoverable v0.2 tests contain synthetic schema/source checks
only and cannot launch real P01/N01 via an environment variable. The private `_accept_lane` function is created
inside `run_one_shot` only after fixed CORE, module source pins and schemas
have been read and checked; no public lane API accepts caller-supplied A03,
policy, validator, gate status, or origin as a verified authority. Arbitrary
hostile Python in-process callers or modified `sys.modules` / `sys.path` are
**UNSUPPORTED_PUBLIC_CALLER_API**, not an attested trust boundary.

The negative `NEGATIVE_RECEIPT_PREPARED` event is a logical event recorded
**before** physical file persistence, not a claim of an O_EXCL save. Only a
separate read-only postflight of the saved Raw file can substantiate storage.
No additional timestamping or circular Trace→Receipt digest dependency is
implied. The local run recorded 11 ordered Trace events. The prepared event
is not proof of persistence; a separate read-only saved-Raw postflight
confirmed the persisted evidence files.

The v0.2 CLI does not authorize itself: `--run-one-shot` requires separate,
explicit authorization, a frozen source/input environment, a one-time fixed
argv/output root and external Supervisor, followed by independent Raw readback.
Do not use general `pytest`/`unittest` to launch real P01/N01. Real testing
is not part of this proposed source patch.

The SHA-pinned v0.2 Python source contains older build-stage words such as
`SOURCE-ONLY` and `UNEXECUTED` in its docstring or CLI help. They describe the
source-only drafting stage **before** the later fresh experiment. These Source
bytes are intentionally frozen to preserve the Adapter SHA-256 bound to the
accepted local evidence. This README records the later verified local status.
Changing those Python strings requires a new Source pin and a separate
decision about runtime evidence for the changed Source.

The original v0.3 `verify_fixture()` metadata-only default can report
`SOURCE_REGENERATION_PERFORMED=NO`: such a PASS is **not** source-bound
acceptance. That historical three-source/Wycheproof default has not been
remediated; the original R2 Adapter E2E remains `NOT_VERIFIED`, historical
complete Source-to-Runtime Provenance remains `INCOMPLETE`, and Official
Acceptance remains `NOT_GRANTED`. Arbitrary hostile in-process Python callers
are outside the supported public API.

The program depends on a separately obtained, privately held SHA-pinned CORE
evidence archive. This public source patch contains no NIST Raw, ISO, private
CORE ZIP, saved Evidence/Receipts, private absolute paths, or Runtime binary.
CORE redistribution, privacy/internal-path review, recipient/channel approval
and any external release are still unresolved. The proposed nine-file source
patch has **not** modified GitHub. This work does not prove universal ML-DSA
correctness, complete FIPS 204 conformance, or third-party reproduction.
