# sigstore_erl

Dependency-free Sigstore client for Erlang/OTP (sign + verify, Rekor v1/v2,
Fulcio, TSA, bundle v0.1–v0.3), targeting the sigstore-conformance suite in CI.

Status: M3 done. Offline verification works end to end for bundles without RFC 3161 timestamps, including every CPython release bundle. Timestamp verification (M4) and signing (M5) are next. See [SPEC.md](SPEC.md) and [docs/plans](docs/plans).

Motivation: hexpm/hexpm#1290 (build provenance / SLSA for Hex packages).
