# QSV ER-1 Self-Contained Freeze Package v0.1.1

This package is a packaging / serialization / reproducibility repair of the
ER-1 v0.1-final freeze package.

The five canonical ER-1 artifacts are preserved byte-for-byte. Their historical
content is not rewritten by v0.1.1.

v0.1-final remains historical evidence.

This package contains:

- five canonical ER-1 artifacts;
- `freeze-manifest.json`;
- `freeze-manifest.json.sha256`;
- `verify-freeze-manifest.py`;
- this README.

Local verification:

    PYTHONDONTWRITEBYTECODE=1 python3 verify-freeze-manifest.py .

The verifier uses only files contained in this package and the Python standard
library. It does not require author chat history, hidden Python variables,
external email history, private paths, GitHub API access, OpenSSL, CIRCL,
ML-DSA execution, or GitHub Actions.

This package verifies ER-1 freeze artifact integrity and reproducibility.

It does not prove ML-DSA correctness.

It does not establish NIST validation.

It does not establish FIPS 204 certification.

It does not establish complete FIPS 204 conformance.

It does not establish complete sigVer coverage.

It does not establish universal ML-DSA correctness.

It does not establish vulnerability absence.

It does not establish system-wide quantum safety.

It does not establish formal verifier correctness.

It does not establish organizational endorsement.

It does not establish independent cryptographic execution reproduction.

No new ML-DSA execution was performed for this repair.

No OpenSSL or CIRCL execution was performed for this repair.

No workflow execution is required by this package.

`EXTERNAL_ER1_COUNT` remains `0` until an actual unrelated external reviewer
returns an ER-1 result.
