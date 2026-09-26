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
