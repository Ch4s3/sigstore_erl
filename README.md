# sigstore_erl

Dependency-free Sigstore client for Erlang/OTP (sign + verify, Rekor v1/v2,
Fulcio, TSA, bundle v0.1–v0.3), targeting the sigstore-conformance suite in CI.

Status: M4 done. Offline verification is complete: it passes every verification test in [sigstore-conformance](https://github.com/sigstore/sigstore-conformance) (except the deprecated `intoto 0.0.2` entry type, deliberately unsupported) and verifies every CPython release bundle. Signing (M5) is next. See [SPEC.md](SPEC.md) and [docs/plans](docs/plans).

Motivation: hexpm/hexpm#1290 (build provenance / SLSA for Hex packages).
