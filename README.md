# QSV ML-DSA Interoperability Corpus

Version: **0.1**

This repository is an implementation artifact for the **Quantum Security Verification (QSV) Reference Model v1.0**.

It is intended to turn ML-DSA interoperability and conformance claims into small, versioned, reproducible evidence units.

## Status

**Design ready / cryptographic fixture execution pending.**

Version 0.1 defines the corpus contract, fixture schema, provenance requirements, implementation-lineage model, fixture plan, and common runner interface.

It does **not** yet publish generated private test keys, seeds, signatures, or completed cryptographic fixture results.

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
