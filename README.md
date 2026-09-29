# sigstore_erl

Dependency-free Sigstore client for Erlang/OTP (sign + verify, Rekor v1/v2,
Fulcio, TSA, bundle v0.1–v0.3), targeting the sigstore-conformance suite in CI.

Status: M2 done (certificate chains, SCTs, identity policy, signatures). Transparency-log and timestamp verification are next, so verification cannot succeed yet. See [SPEC.md](SPEC.md) and [docs/plans](docs/plans).

Motivation: hexpm/hexpm#1290 (build provenance / SLSA for Hex packages).
