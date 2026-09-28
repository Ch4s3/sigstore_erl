# sigstore_erl — a dependency-free Sigstore client for Erlang/OTP

Status: DRAFT v0.1. M0 (skeleton, CI) and M1 (data models, structural validation) done; see docs/plans/M1.md. No cryptographic verification yet.

## 0. Why

hexpm/hexpm#1290 tracks the OpenSSF "Principles for Package Repository Security".
The open Level-3 item is build provenance. maennchen's comment (2026-09-23):

> "we should possibly start looking into SLSA. For that we would need a pure
> erlang sigstore client library."

The follow-up discussion set the shape:

1. **Layer 0 (this spec):** a client that can sign and verify with Sigstore,
   passing [sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
   in CI, standalone in Erlang with no dependencies.
2. Layer 1: in-toto Statement/DSSE (message format).
3. Layer 2: SLSA provenance predicates.
4. Layer 3: integration into hex (client), hexpm (server), rebar3.

Slack follow-up (maennchen, 2026-09-24): "hex would have to vendor it into
hex_core, which is also why we can't have another level of dependencies."
That single sentence drives most of §2a below: the library must survive
hex_core's copy-and-sed vendoring, not merely have an empty deps list.

Layers 1-3 are sketched in §12 only so that Layer 0 does not paint us into a
corner. This document specs Layer 0.

Reference implementations consulted: sigstore-rs 0.14 (module layout, API
shape), sigstore-python (behavioural reference; it is the conformance suite's
own "selftest" client), the Sigstore client spec
(architecture-docs/client-spec.md), protobuf-specs, rekor-tiles.

## 1. Goals and non-goals

### Goals

- G1. Pure Erlang. Only OTP applications: `kernel`, `stdlib`, `crypto`,
  `public_key`, `asn1` (runtime), `ssl`, `inets`. No hex deps, no NIFs, no
  ports.
- G2. Pass `sigstore-conformance` (production + staging environments) in
  GitHub Actions on every PR. Every `test_verify[*]` fixture, `test_simple`,
  `test_sign_verify_dsse`, `test_sign_does_not_produce_root`,
  `test_sign_verify_rekor2`, and the CPython release bundles.
- G3. Full verification per the client spec: certificate chain at signed time,
  SCT, identity policy, inclusion proof + checkpoint, SET, RFC 3161 timestamps,
  body cross-check against bundle content. No skipped steps (sigstore-rs skips
  inclusion proof and SET; we will not).
- G4. Signing: keyless (OIDC token in, bundle out), Rekor v1 and v2, DSSE and
  hashedrekord, TSA timestamps, bundle v0.3 output.
- G5. Usable as a library from Erlang and Elixir with a small, data-oriented
  API (maps in, maps out; `{ok, _} | {error, _}` everywhere; no exceptions
  crossing the API boundary).
- G6. Offline verification is the default and needs no network. Trust material
  is passed in explicitly or loaded from an embedded, TUF-refreshable root.

### Non-goals (Layer 0)

- Interactive OIDC browser flow. Callers supply an identity token (CI
  ambient credentials, or a token obtained elsewhere). Can be added later
  without API change.
- Cosign container-image workflows, OCI registries, cosign encrypted key files.
- Rekor v1 online lookup/search, consistency proofs, monitoring.
- Any SLSA/in-toto semantics beyond "DSSE payload is an in-toto Statement with
  subjects" (needed for verification).
- Protobuf binary encoding. Bundles are JSON only (the spec's canonical form).

## 2. Constraints from the platform

Verified against OTP 29.1 on 2026-09-24 (`probe.erl` in scratch):

| Need | OTP provides | Notes |
|---|---|---|
| ECDSA P-256/384/521 sign+verify, prehashed | `public_key:sign/3`, `public_key:verify({digest,D},…)` | verified `{digest, D}` works for P-256 |
| Ed25519 verify (Rekor v2 checkpoints) | `public_key:verify(Msg, none, Sig, {#'ECPoint'{}, {namedCurve, ?'id-Ed25519'}})` | verified |
| RSA PKCS1v15 / PSS verify | `public_key:verify/4,5` with `{rsa_padding, rsa_pkcs1_pss_padding}` | for managed keys |
| SHA-256/384/512 | `crypto:hash/2` | |
| X.509 decode/encode | `public_key:pkix_decode_cert/2` (`otp` and `plain`), `public_key:pkix_encode/3`, `'OTP-PKIX'` | need re-encoding of TBSCertificate minus one extension for SCT |
| CSR encode | `'PKCS-10'` ASN.1 module ships compiled | `CertificationRequest` |
| CMS SignedData (RFC 3161 response wrapper) | `'CryptographicMessageSyntax-2009'` ships compiled | `TSTInfo` does **not** ship → hand-written DER walker (`sigstore_der`), no build-time asn1ct (§2a V3) |
| JSON | `json` on OTP 27+, pluggable below (§8.5) | decode via adapter; ALL output via own `sigstore_jcs` serializer |
| HTTPS | `httpc` + `ssl` with `public_key:cacerts_get()` | must set `verify_peer`, `cacerts`, SNI, `customize_hostname_check` explicitly; httpc defaults are insecure |
| Path validation at arbitrary time | **not available**: `pkix_path_validation/3` uses `calendar:universal_time()` (pubkey_cert.erl:181) | we implement chain building + validation at time T ourselves (§6.4). Same choice sigstore-python made. |
| base64 | `base64:encode/decode` | standard padded; also need url-safe for JWT |

**OTP floor: 25**, dictated by hex's CI matrix (§2a V1). JSON decode is an adapter (§8.5).

## 2a. Vendoring into hex_core (hard constraints)

hex vendors hex_core with `scripts/vendor_hex_core.sh`: a fixed list of
`src/*.erl|*.hrl` files is copied flat into hex's `src/` with a `mix_` prefix,
and a fixed list of module-name tokens is rewritten with `sed`. rebar3 does
the same with `r3_`. Generated code (hex_core's gpb protobuf modules) is
**checked in as source**. Therefore:

- V1. **OTP floor is 25** (hex CI matrix: 25.3 → 29.0). JSON decoding is
  pluggable (§8.5): the default adapter uses OTP 27's `json` when loaded and
  fails cleanly otherwise, following the `mix hex.search` precedent; hosts on
  25/26 plug in their own codec. No codec is shipped. Also avoid: `binary:decode_hex` shape changes, `maps:groups_from_list`
  (25 ok), `public_key:cacerts_get/0` (25 ok), `crypto:hash/2` ed25519 (ok).
- V2. **Flat `src/`** holding every vendorable `.erl` and `.hrl`
  (`-include("sigstore.hrl")`, never `-include_lib("sigstore_erl/…")`).
  No `include/`, no `priv/`, no `asn1/` at runtime.
- V3. **No build-time codegen.** RFC 3161 `TSTInfo` is parsed by a small
  hand-written DER walker in `sigstore_der` (~80 lines), not an `asn1ct`
  module (D2 revised). OTP's compiled CMS module is still used for the
  `SignedData` envelope since it ships with OTP.
- V4. **Embedded trust roots are Erlang source**: `sigstore_trust_embedded.erl`
  is generated by `scripts/embed_trust_roots.sh` from root-signing targets
  and checked in (with the source URL + sha256 in a header comment).
- V5. **No processes, no app env, no supervisors.** Pure functions plus
  `httpc`. Configuration travels in a config map like `hex_core:default_config/0`:
  `sigstore:default_config() -> #{http_adapter => {sigstore_http_httpc, #{}}, …}`
  and every network-touching function takes it. `sigstore_http` is a
  behaviour with the same `request/5` callback shape as `hex_http`, so hex
  can plug its existing adapter in and tests can stub the transport.
- V6. **Module tokens must be sed-safe.** Every module is `sigstore_<name>`;
  the façade is `sigstore` (rewritten via the `sigstore:` / `sigstore)`
  tokens exactly as hex_core does for `hex_core`). Never write a
  `sigstore_<module>` token inside a string literal or atom that is not a
  module reference; never build module names dynamically. Media types and
  URLs contain `sigstore.` / `sigstore-` only, which the rewrite ignores.
- V7. `scripts/vendor_list.txt` is the authoritative list of files + tokens;
  a CT test vendors the tree into a temp dir with prefix `t_`, compiles it,
  and runs the offline verify suite against the prefixed modules, so
  vendorability is CI-enforced rather than discovered by hex.
- V8. Not vendored: `sigstore_conformance` (escript), test suites, scripts.
- V9. **Two-hop chain.** hex_core vendors nothing today (maennchen, Slack
  2026-09-28), so we would be its first vendored dependency: hex_core copies
  us with a prefix, then hex (`mix_`) and rebar3 (`r3_`) re-vendor hex_core
  and rewrite our names a second time. Our files and tokens therefore have
  to be appended to *their* vendor lists too. The V7 test vendors twice
  (`a_` then `b_a_`) to prove the double rewrite is lossless.

## 3. Repository layout

```
sigstore_erl/
  rebar.config              # no deps; erl_opts; escript for conformance
  src/
    sigstore_erl.app.src   # OTP app name is sigstore_erl; module prefix sigstore_
    sigstore.erl            # public façade: sign/verify/trust helpers
    sigstore_bundle.erl     # Bundle model: parse/validate/emit JSON (v0.1–v0.3)
    sigstore_trust.erl      # TrustedRoot + SigningConfig models; selection by time/operator
    sigstore_tuf.erl        # minimal TUF client (root rotation, timestamp/snapshot/targets)
    sigstore_verify.erl     # the verification procedure (§6)
    sigstore_sign.erl       # the signing procedure (§7)
    sigstore_policy.erl     # identity/issuer/extension policies
    sigstore_x509.erl       # cert helpers: chain build+validate at time, leaf profile, SAN, Fulcio OIDs, SPKI hashing
    sigstore_sct.erl        # RFC 6962 SCT reconstruct+verify (embedded + detached)
    sigstore_merkle.erl     # RFC 6962 hashing + inclusion proof
    sigstore_checkpoint.erl # C2SP signed note / checkpoint parse+verify, key-ID hints
    sigstore_rekor.erl      # Rekor v1 + v2 clients; body build/cross-check; SET
    sigstore_fulcio.erl     # Fulcio v2 client; CSR build
    sigstore_tsa.erl        # RFC 3161 request build; response parse+verify
    sigstore_dsse.erl       # DSSE PAE, envelope model
    sigstore_intoto.erl     # in-toto Statement v1 parse + subject match (minimal)
    sigstore_jcs.erl        # RFC 8785 canonical JSON (restricted, §8.3)
    sigstore_json.erl       # decode behaviour + dispatch via #{json_adapter => {Mod, Cfg}}
    sigstore_json_otp.erl   # default adapter: OTP 27+ `json` if loaded, else clean error
    sigstore_der.erl        # minimal DER TLV walker (TSTInfo, SCT list, misc)
    sigstore_trust_embedded.erl # GENERATED, checked in: prod+staging trusted_root/signing_config
    sigstore_http.erl       # behaviour (request/5) + dispatch via config map
    sigstore_http_httpc.erl # default adapter: hardened httpc/ssl
    sigstore.hrl            # media types, OIDs (lives in src/ for vendoring)
    sigstore_oidc.erl       # JWT claim extraction (unverified), token validity check
    sigstore_keys.erl       # key_details enum ↔ OTP key terms; SPKI ↔ PEM/DER; algorithm registry
    sigstore_pem.erl        # PEM helpers (public_key:pem_* is enough; small)
  scripts/
    embed_trust_roots.sh    # regenerates sigstore_trust_embedded.erl from root-signing
    vendor_list.txt         # files + tokens for hex_core-style vendoring (V7)
    sigstore_conformance.erl # escript entrypoint (cli_protocol.md); lives in src/ so `rebar3 escriptize` picks it up
  test/
    *_SUITE.erl                    # Common Test; vectors under test/vectors/
    vectors/                       # copied conformance bundle-verify fixtures + unit vectors
  .github/workflows/
    ci.yml                         # unit + dialyzer + xref
    conformance.yml                # sigstore/sigstore-conformance action, prod + staging
  docs/
    SPEC.md (this) ; DECISIONS.md ; CONFORMANCE.md
```

Build tool: rebar3 (a *build-time* tool, not a runtime dep). The library must
also compile with plain `erlc` + a Makefile so hex/rebar3 can vendor it if
they want; nothing may depend on rebar3 plugins.

## 4. Public API

All functions return `{ok, Result} | {error, Reason}`; `Reason` is a tagged
tuple, never a string, so callers can pattern-match (`{error, {cert, expired}}`,
`{error, {tlog, inclusion_proof_mismatch}}`, …). Full error catalogue in
`docs/ERRORS.md` (to write).

```erlang
%% ---- Trust material ----
-type trusted_root()  :: #{…}.        % parsed trusted_root.json (map form, §5.2)
-type signing_config():: #{…}.        % parsed signing_config.v0.2.json
-type source()        :: {file, file:name_all()} | {json, binary()} | map().
-type trust_opts()    :: #{config => config(),
                           instance => production | staging,   % embedded snapshot
                           trusted_root => source(),            % wins over instance
                           signing_config => source()}.

sigstore:trusted_root(trust_opts())   -> {ok, trusted_root()} | {error, _}.
sigstore:signing_config(trust_opts()) -> {ok, signing_config()} | {error, _}.

%% ---- Verification (offline) ----
-type artifact() :: {file, file:name()} | {binary, binary()} | {digest, sha256, binary()}.
-type policy()   :: sigstore_policy:t().   % see §6.6
-type verify_opts() :: #{trusted_root := trusted_root(),
                         policy := policy(),
                         now => calendar:datetime()}.   % for tests

sigstore:verify(artifact(), Bundle :: binary() | map(), verify_opts())
    -> {ok, verified()} | {error, _}.
%% verified() :: #{certificate => #'OTPCertificate'{}, identity => binary(),
%%                 issuer => binary(), signed_times => [{tsa|tlog, Time}],
%%                 statement => map() | undefined, log_entries => [...]}.

%% ---- Signing (online) ----
-type sign_opts() :: #{identity_token := binary(),
                       signing_config := signing_config(),
                       trusted_root := trusted_root(),   % for self-verification
                       payload => artifact() | {dsse, PayloadType :: binary(), Payload :: binary()},
                       key => ephemeral_p256 | {ephemeral, KeyType} | PrivateKey,
                       tsa => required | optional | none,   % default required for rekor v2
                       self_verify => boolean()}.           % default true

sigstore:sign(sign_opts()) -> {ok, Bundle :: map()} | {error, _}.
sigstore_bundle:to_json(map()) -> iodata().
sigstore_bundle:from_json(binary()) -> {ok, map()} | {error, _}.
```

Policy construction:

```erlang
sigstore_policy:identity(Identity, Issuer)          % SAN == Identity AND issuer ext == Issuer
sigstore_policy:key(PublicKeyPemOrDer)              % managed-key verification (no cert)
sigstore_policy:all_of([P1, P2]) ; any_of([...])
sigstore_policy:extension(OidName, Expected)        % e.g. source_repository_uri
```

Elixir sees this as `:sigstore.verify/3` etc. Maps use binary keys matching the
protobuf-JSON field names, so `Bundle` maps are JSON-shaped and round-trip.

## 5. Data models

### 5.1 Bundle (`sigstore_bundle`)

Internal representation is an atom-keyed, snake_case map (`sigstore_bundle:t()`),
not the JSON-shaped map: a camelCase binary-keyed map holding already-decoded
bytes looks exactly like raw JSON and invites double-decoding bugs (D3
revised). Normalisations applied once at parse time, reversed at emit time:

- `bytes` fields → decoded binaries (`rawBytes`, `signature`, `digest`,
  `keyId`, `rootHash`, `hashes[]`, `canonicalizedBody`, `signedEntryTimestamp`,
  `signedTimestamp`, `payload`, `sig`).
- `int64` fields (`logIndex`, `integratedTime`, `treeSize`) → integers.
  Accept both JSON string and number on input; emit strings.
- JSON `null` members are dropped before parsing (proto3: null = unset).
  Real trust roots carry `"end": null` and `"checkpointKeyId": null`.
- base64: standard or URL-safe, padded or not, `\r`/`\n` skipped (Go,
  Python, and sigstore-rs all tolerate line breaks; a conformance fixture
  carries `base64`-CLI line-wrapped output). Any other stray byte rejects.
- Times are integer microseconds since the Unix epoch (`sigstore_time`).
- Enums stay as binaries (`<<"SHA2_256">>`); validated against the registry.

Parse-time structural validation (all produce `{error, {bundle, _}}`):

| Check | Fixture(s) |
|---|---|
| valid JSON, object | `bundle-malformed-json_fail` |
| `mediaType` ∈ {`…bundle+json;version=0.1`, `…;version=0.2`, `…;version=0.3`, `…bundle.v0.3+json`} | `bundle-unknown-version_fail` |
| exactly one of `messageSignature` / `dsseEnvelope` | |
| `verificationMaterial` present, exactly one of `certificate` / `x509CertificateChain` / `publicKey` | `bundle-empty-certificate-chain_fail` |
| v0.3 ⇒ `certificate`; v0.1/0.2 ⇒ `x509CertificateChain` non-empty | |
| leaf = chain[0] passes leaf profile; other chain certs are not root CAs (root present ⇒ **reject**, per conformance `bundle-with-root-cert_fail`; spec says ignore-with-warning, suite is stricter, follow suite) | `bundle-with-root-cert_fail` |
| `tlogEntries` length == 1 (multi-entry deferred; v2 threshold verification later) | |
| `logIndex >= 0` | `bundle-negative-log-index_fail` |
| base64 decodes | `bundle-invalid-base64-signature_fail` |
| v0.1 ⇒ `inclusionPromise` required; v0.2+ ⇒ `inclusionProof.checkpoint` required | `intoto-missing-inclusion-proof_fail`, `rekor2-no-inclusion-proof_fail` |
| DSSE ⇒ exactly one signature | |
| `kindVersion` ∈ {hashedrekord 0.0.1, dsse 0.0.1, hashedrekord 0.0.2, intoto 0.0.2}; else `{error,{bundle,{unsupported_entry, {K, V}}}}`. intoto 0.0.2 is deprecated Rekor v1, used by six v0.2 fixtures; parsed so they fail for the intended reason, verification support decided in M3 (Q7) | |
| v0.2+ with no `inclusionPromise` and no RFC 3161 timestamp ⇒ no signed time source | `rekor2-no-timestamp_fail` |

Emit: producer always writes `application/vnd.dev.sigstore.bundle.v0.3+json`,
`verificationMaterial.certificate` (leaf only), padded base64, int64 as
strings, omit empty/default fields, `inclusionPromise` omitted for v2 entries.

### 5.2 TrustedRoot / SigningConfig (`sigstore_trust`)

Parsed into maps with the same normalisation. Accept media types
`trustedroot+json;version=0.1`, `trustedroot.v0.1+json`, `trustedroot.v0.2+json`,
and `clienttrustconfig.v0.1+json` (unwrap). Time ranges → `{Start, End | infinity}`
in gregorian seconds; **inclusive** on both ends
(`trust-root-tlog-validity-end-inclusive`, `trust-root-tsa-validity-end-inclusive`).
A tlog with no `validFor.start` is invalid (`trust-root-tlog-missing-validity-start_fail`).

Selectors (pure functions, all take a time):

```erlang
sigstore_trust:tlogs_for(Root, KeyId, Time)   % by logId or checkpointKeyId, validFor covers Time (expired allowed only when Time within range — never "now")
sigstore_trust:ctlogs_for(Root, LogId, Time)
sigstore_trust:cas_at(Root, Time)             % CAs whose validFor covers Time; each → {Anchor, Intermediates}
sigstore_trust:tsas(Root)                     % all; validity checked against genTime after parsing
sigstore_trust:select_services(SigningConfig, Kind, Now, SupportedMajors) % §7.1
```

### 5.3 Key material (`sigstore_keys`)

Single place mapping protobuf `PublicKeyDetails` names ↔ `{Alg, Curve|Bits, Hash}`
↔ OTP key terms; SPKI DER ↔ `public_key` term; `SHA-256(SPKI DER)` for log IDs;
C2SP key IDs (§6.5). Algorithm registry allow-list:

verify: `PKIX_ECDSA_P256_SHA_256`, `PKIX_ECDSA_P384_SHA_384`, `PKIX_ECDSA_P521_SHA_512`,
`PKIX_ED25519`, `PKIX_ED25519_PH`, `PKIX_RSA_PKCS1V15_{2048,3072,4096}_SHA256`,
`PKIX_RSA_PSS_{2048,3072,4096}_SHA256`. Sign (Layer 0): P-256 only, matching
every other client's default; the code path is generic.

## 6. Verification procedure (`sigstore_verify`)

Implements client-spec §4 exactly, in this order. Each step is its own
function so tests can hit it in isolation and so failures name the step.

```
verify(Artifact, Bundle, Opts) ->
  0. parse+validate bundle (§5.1); decode leaf cert (or managed key)
  1. signed_times(Bundle, Root)            -> [{tsa,T}] ++ [{tlog,T}]  (need ≥1)
  2. cert_chain(Leaf, Root, Times)         -> path valid at EVERY time; leaf profile; CA validFor covers time
  3. sct(Leaf, Chain, Root)                -> embedded SCT verified against ctlogs
  4. policy(Leaf, Policy)                  -> identity/issuer/extensions
  5. tlog_entry(Bundle, Root, Leaf|Key, Artifact) -> checkpoint sig, inclusion proof, body cross-check, SET
  6. leaf validity: notBefore ≤ T ≤ notAfter for every T in Times
  7. signature(Artifact, Bundle, Leaf|Key) -> hashedrekord digest or DSSE PAE; in-toto subject match
```

### 6.1 Signed times

- TSA: for each `rfc3161Timestamps[i]` (cap 32, reject duplicates): parse
  `TimeStampResp` (§6.8), `messageImprint` must equal `H(signature bytes)`
  (`rekor2-timestamp-payload-mismatch_fail`), verify CMS signature with a TSA
  chain from the trusted root whose `validFor` covers `genTime`
  (`rekor2-timestamp-outside-trust-root-tsa-validity_fail`), TSA leaf cert
  valid at `genTime` (`rekor2-timestamp-outside-tsa-cert-validity_fail`),
  embedded certs in the response are **not** trusted unless they chain to a
  trusted-root TSA (`rekor2-timestamp-untrusted-tsa-with[out]-embedded-cert_fail`,
  `rekor2-timestamp-with-embedded-cert`, `…-with-expired-cert-chain`: root-supplied
  chain wins). Bundle has timestamps but root has no TSAs ⇒ fail.
- tlog: only if `inclusionPromise` present and kind/version is `*/0.0.1`;
  T = `integratedTime`. Must not be in the future relative to `now`
  (`integrated-time-in-future_fail`). For 0.0.2 entries `integratedTime` is ignored.
- Zero times ⇒ `{error, {time, no_verified_time}}` (`rekor2-no-timestamp_fail`).

### 6.2 Chain validation at time T (own implementation, `sigstore_x509`)

Because OTP validates against wall-clock only:

1. Candidate anchors = every `certificateAuthorities[].certChain` whose
   `validFor` covers T; anchor = last cert, extra intermediates = the rest.
   Bundle-supplied intermediates (v0.1/v0.2 chains) are added as candidates,
   never as anchors.
2. Build path leaf → … → anchor by issuer/subject name match + AKI/SKI when
   present; try each anchor (`bundle-from-wrong-instance_fail`).
3. For each edge: verify signature with issuer SPKI (`public_key:pkix_verify`
   is fine here), `notBefore ≤ T ≤ notAfter` for every cert, issuer has
   `basicConstraints.cA`, `keyCertSign`, path length respected, no
   critical unknown extensions on leaf. EKU on intermediates not enforced
   (Fulcio intermediates carry codeSigning).
4. Leaf profile: v3, not CA, `digitalSignature`, EKU contains codeSigning,
   exactly one SAN.

Repeat for every T in signed times; any failure fails
(`intoto-expired-certificate_fail`, `intoto-set-outside-signing-cert-validity_fail`,
`intoto-tsa-timestamp-outside-cert-validity_fail`).

### 6.3 SCT (`sigstore_sct`)

- Extract `1.3.6.1.4.1.11129.2.4.2` from leaf; exactly one SCT (list parse:
  `u16 len || (u16 len || SCT)*`). SCT: `version(1) logId(32) ts(8) ext(u16) hashAlg(1) sigAlg(1) sig(u16)`.
- Rebuild TBS: decode leaf as `plain`, drop that extension from
  `tbsCertificate.extensions`, re-encode `TBSCertificate` with
  `'OTP-PKIX'`/`public_key:pkix_encode('TBSCertificate', …, plain)`.
  **Verified byte-faithful (2026-09-24, OTP 29.1):** `test/probes/sct_probe.erl`
  decodes two real Fulcio leaves (conformance `happy-path-v0.3`, production;
  `rekor2-happy-path`, staging), re-encodes the unmodified TBSCertificate
  byte-identically (1979/1979 bytes), drops the SCT extension, rebuilds the
  RFC 6962 signed struct and the embedded SCT signature **verifies** against
  the CT log key from the respective trusted root. Implementation notes:
  use `pkix_decode_cert(Der, plain)` and `pkix_encode('TBSCertificate', TBS, plain)`;
  there is no standalone `Extension` encoder in `public_key`/`'OTP-PKIX'`, so
  strip by filtering the record list, not by DER splicing; `der_decode('SubjectPublicKeyInfo', _)`
  already yields `{namedCurve, OID}` parameters, do not decode them again.
- Issuer = chain[0], unless it has the precert-signing EKU
  `1.3.6.1.4.1.11129.2.4.4` (then chain[1]). `issuerKeyHash = SHA-256(issuer SPKI DER)`.
- Signed struct: `0x00 || 0x00 || ts(8) || 0x0001 || issuerKeyHash || len24(TBS) || TBS || u16(ext) || ext`.
- Key lookup: `ctlogs` where `logId.keyId == sct.logId`, `validFor` covers
  `ts` (`invalid-ct-key_fail`); fall back to trying all CT keys.
- Detached SCT (Fulcio v2 response variant): `0x0000 || len24(DER leaf) || leaf` entry type.

### 6.4 Policy (`sigstore_policy`)

- Identity: SAN rfc822Name | URI | otherName(`1.3.6.1.4.1.57264.1.7`, UTF8String) == expected.
- Issuer: `1.3.6.1.4.1.57264.1.8` (DER UTF8String) preferred; fall back to
  `.1.1` (raw bytes). Both must be parsed.
- Extensions table for `.1.9`–`.1.24` (DER UTF8String) and deprecated `.1.2`–`.1.6` (raw).
- Managed key mode (`--key`): no cert; skip 2, 3, 4; verify signature with the
  key; SCT/chain N/A (`managed-key-*`).

### 6.5 Transparency log entry (`sigstore_rekor`, `sigstore_checkpoint`, `sigstore_merkle`)

1. Select tlog instance: match `logId.keyId` against `tlogs[].logId` or
   `tlogs[].checkpointKeyId`; `validFor` must cover the signed time
   (`trust-root-tlog-validity-end-inclusive`).
2. Parse checkpoint envelope as C2SP signed note: text lines until blank line
   (`origin`, `size`, base64 root, optional extension lines), then signature
   lines `— name base64(hint4 || sig)`. Missing origin/size/root ⇒ fail
   (`rekor2-checkpoint-missing-{origin,size,root-hash}_fail`; origin must be
   first line — `rekor2-checkpoint-origin-not-first` is a *pass* fixture, so
   the check is "origin line == log's expected origin", see fixture README).
   Signature selection: ignore unknown key hints (witness cosigs:
   `rekor2-checkpoint-cosigned`, `-multiple-cosigs`, `-two-sigs-*`); require ≥1
   signature whose hint matches the selected log's key ID prefix **and**
   verifies (`checkpoint-bad-keyhint_fail`, `invalid-checkpoint-signature_fail`,
   `rekor2-checkpoint-missing-log-signature_fail`, `rekor2-checkpoint-no-matching-signature_fail`).
   Key ID hint: v1 ECDSA `SHA-256(SPKI)[:4]`; v2 Ed25519
   `SHA-256(name || 0x0A || 0x01 || pubkey32)[:4]`, name = origin.
3. `checkpoint.root == inclusionProof.rootHash` (`checkpoint-wrong-roothash_fail`).
   Trust `size`/`root` from the verified checkpoint, index from top-level `logIndex`.
4. Leaf hash `SHA-256(0x00 || canonicalizedBody)`; RFC 6962 §2.1.1 inclusion
   proof; proof length must equal `inner + border`
   (`invalid-inclusion-proof_fail`, `inclusion-proof-corrupted-hash_fail`).
5. Body cross-check (anti CVE-2022-36056): decode `canonicalizedBody` as JSON and
   compare structurally with a body rebuilt from bundle content:
   - hashedrekord 0.0.1: `sig`, `PEM(leaf)` base64, `sha256` hex(digest).
   - dsse 0.0.1: `payloadHash == sha256(payload)`; `signatures == [{sig, PEM(leaf)}]`.
   - hashedrekord 0.0.2: `{kind, apiVersion, spec.hashedRekordV002{data{algorithm,digest}, signature{content, verifier{x509Certificate.rawBytes | publicKey.rawBytes, keyDetails}}}}`;
     for DSSE bundles digest = `SHA-256(PAE)`.
   Fixtures: `wrong-hashedrekord-{artifact,cert-and-sig,entry}_fail`,
   `intoto-log-entry-mismatch_fail`, `rekor2-dsse-mismatch-{envelope,sig}_fail`,
   `dsse-mismatch-*_fail`.
6. SET (v1 only): payload = JCS of `{"body": b64(body), "integratedTime": Int,
   "logID": hex(keyId), "logIndex": Int}`; verify with the tlog key
   (`set-invalid-signature_fail`). Required for v0.1 bundles and whenever the
   integrated time is the only signed time.

### 6.6 Signature

- hashedrekord: `D = SHA-256(artifact)` or the given digest; if
  `messageDigest` present it must equal D (informational only:
  `message-digest-mismatch_fail`); `public_key:verify({digest, D}, sha256, Sig, Key)`
  (`signature-mismatch_fail`, `incorrect-public-key_fail`, `wrong-material_fail`).
- DSSE: verify `sig` over `PAE(payloadType, payload)`; `payloadType` must be
  `application/vnd.in-toto+json`; parse Statement v1; artifact digest must
  appear in some `subject[].digest.sha256` (`dsse-invalid-sig_fail`,
  `rekor2-dsse-invalid-sig_fail`, `happy-path-intoto-in-dsse-v3`).

### 6.7 Result

`{ok, #{certificate, identity, issuer, signed_times, log_entries, statement}}`.
Never partial success.

### 6.8 RFC 3161 (`sigstore_tsa`)

`TimeStampReq` is emitted and `TimeStampResp`/`TSTInfo` parsed with
`sigstore_der` (hand-written DER, §2a V3); `ContentInfo`/`SignedData` are
decoded with OTP's compiled CMS module. Verification:
`status ∈ {granted, grantedWithMods}`; `eContentType == id-ct-TSTInfo`;
signer cert = from response `certificates` or from trusted root chain;
`SignerInfo` signed attributes must contain `messageDigest == H(eContent)`;
signature over the DER of the signed attributes (with SET tag) with the TSA
leaf key; TSA leaf EKU `timeStamping` critical; chain to trusted-root TSA
anchor at `genTime`.

## 7. Signing procedure (`sigstore_sign`)

Client-spec §2, in order:

1. **Config:** `select_services/4` per §5.2: `caUrls`/`oidcUrls` → highest
   supported major within `validFor`; `rekorTlogUrls`/`tsaUrls` → one per
   `operator`, highest supported major (Rekor 1 and 2; TSA 1), then selector
   `ALL | ANY | EXACT{count}`. `--signing-config` file overrides TUF.
2. **Token:** `sigstore_oidc:claims/1` decodes JWT payload (no signature
   check — Fulcio does that); require `aud == <<"sigstore">>`, `exp` in
   future; extract `sub`/`email` for later self-verification.
3. **Key:** `public_key:generate_key({namedCurve, secp256r1})`; zeroed after
   use (best effort; Erlang binaries are immutable — document this).
4. **Fulcio:** build PKCS-10 CSR with empty subject, sign with the ephemeral
   key; `POST {ca}/api/v2/signingCert`, body
   `{"certificateSigningRequest": b64(PEM CSR)}`, `Authorization: Bearer`,
   `Accept: application/pem-certificate-chain`. Parse
   `signedCertificateEmbeddedSct | signedCertificateDetachedSct`. Validate the
   chain against trusted root immediately; verify SCT; check SAN == token identity.
   Never include chain certs beyond the leaf in the bundle
   (`test_sign_does_not_produce_root`).
5. **Sign:** hashedrekord: `Sig = sign({digest, SHA-256(artifact)})`. DSSE:
   `Sig = sign(PAE("application/vnd.in-toto+json", Payload))`; payload bytes
   are stored verbatim (suite checks byte-equality).
6. **TSA:** `TimeStampReq{messageImprint = SHA-256(Sig), nonce, certReq=true}`
   → `POST` `application/timestamp-query` to the full TSA URL; store the DER
   response verbatim. Required when any Rekor v2 log is selected or
   `tsa => required`.
7. **Rekor:**
   - v1: `POST {rekor}/api/v1/log/entries` with hashedrekord 0.0.1 / dsse 0.0.1
     proposed entry; convert `LogEntry` (hex → bytes) to `TransparencyLogEntry`;
     `kindVersion` 0.0.1; keep SET as `inclusionPromise`.
   - v2: `POST {rekor}/api/v2/log/entries` with `hashedRekordRequestV002`
     (`digest`, `signature.content`, `verifier.x509Certificate.rawBytes`,
     `keyDetails: PKIX_ECDSA_P256_SHA_256`); DSSE = hashedrekord over
     `SHA-256(PAE)`. Response is already a `TransparencyLogEntry`. Timeout ≥ 20 s.
     (`test_sign_verify_rekor2` expects `hashedrekord/0.0.2`.)
8. **Self-verify:** run §6 on the assembled bundle with policy
   `identity(TokenIdentity, TokenIssuer)`; fail signing if it fails.
9. **Emit** v0.3 bundle.

## 8. Cross-cutting components

### 8.1 TUF client (`sigstore_tuf`)

Minimal TUF 1.0 client sufficient for root-signing: embedded `root.json`
bootstrap per instance; update loop root(N+1)… → timestamp → snapshot →
targets, threshold signature verification (ECDSA P-256, Ed25519, RSA),
expiry enforcement, consistent-snapshot filenames (`N.role.json`,
`targets/<sha256>.<name>`), no delegations (we only need `trusted_root.json`
and `signing_config.v0.2.json`). Cache dir optional. The embedded bootstrap
root and snapshot live in `sigstore_trust_embedded` (§2a V4). **Not required for
conformance** (suite never forces TUF), so it is milestone M5 and the
embedded `trusted_root.json` snapshot is the M1-M4 fallback. Document the
staleness risk of the embedded snapshot (e.g. new Rekor shards).

### 8.2 HTTP (`sigstore_http` behaviour, `sigstore_http_httpc` adapter)

Same shape as `hex_http`: `request(Method, URI, Headers, Body, AdapterConfig)`
selected via `#{http_adapter => {Mod, Cfg}}` in the config map. Default
adapter is `httpc` with a private profile; `ssl` options: `verify_peer`,
`cacerts => public_key:cacerts_get()`, `customize_hostname_check` with
`public_key:pkix_verify_hostname_match_fun(https)`, `server_name_indication`,
TLS 1.2+; connect/recv timeouts; JSON and binary bodies; 2 retries on 5xx.
Tests plug a stub adapter to fake Fulcio/Rekor/TSA.

### 8.3 JCS (`sigstore_jcs`)

RFC 8785 restricted to what Sigstore emits: objects (keys sorted by UTF-16
code units), arrays, strings (RFC 8785 escaping), integers, booleans, null.
Floats ⇒ `{error, {jcs, float_unsupported}}`. Used for SET payload and for
optional byte-exact leaf recomputation; structural comparison (§6.5.5) does
not need it.

### 8.5 JSON (`sigstore_json` behaviour, `sigstore_json_otp` adapter)

hex_core has no JSON codec at all (its wire formats are ETF and protobuf);
the only JSON in hex, `mix hex.search`, uses OTP 27's `json` when loaded and
otherwise tells the user to upgrade. We do the same, one step more general:

- **Decode** goes through `sigstore_json:decode(Config, Bin)`, dispatching on
  `#{json_adapter => {Mod, Cfg}}` (same shape as `http_adapter`). The
  behaviour has a single callback `decode(Bin, Cfg) -> {ok, Value} | {error, R}`.
  Default `sigstore_json_otp`: `json:decode/1` if `code:ensure_loaded(json)`
  succeeds, else `{error, {json, {unavailable, _}}}`. An Elixir host on OTP 26
  supplies a three-line Jason wrapper; rebar3 could wrap its vendored codec.
- **Encode is never pluggable.** Every byte of JSON we emit (bundles, Rekor
  and Fulcio request bodies, SET payloads) is produced by `sigstore_jcs`, our
  RFC 8785 serializer, which is deterministic, sorted-key, valid JSON. Sorted
  keys are harmless to every consumer and mandatory for the SET, so one
  serializer covers both. Floats are rejected (Sigstore never emits any).
- Value model: maps with binary keys, lists, binaries, integers, floats,
  `true | false | null`. Adapters must conform; the dispatcher wraps crashes
  and bad returns into `{error, {json, _}}`.

Consequence: on OTP 25/26 without a configured adapter, verify and sign
return `{error, {json, {unavailable, _}}}` rather than being unavailable at
compile time, so hex_core can still vendor and compile the code everywhere.

### 8.4 JWT (`sigstore_oidc`)

Split on `.`, url-safe base64 decode part 2, JSON decode. No signature
verification (out of scope; Fulcio is the verifier of the token).

## 9. Conformance harness (`conformance/sigstore_conformance.erl`)

An escript implementing `docs/cli_protocol.md` verbatim. Argument order is
guaranteed by the suite; parse positionally-tolerant anyway.

```
sign-bundle   [--staging] [--in-toto] --identity-token T --bundle OUT [--trusted-root TR] [--signing-config SC] FILE
verify-bundle [--staging] --bundle B (--key K | --certificate-identity I --certificate-oidc-issuer URL) [--trusted-root TR] FILE_OR_DIGEST
```

- `--staging` ⇒ `instance => staging`; explicit `--trusted-root` /
  `--signing-config` override everything else.
- `FILE_OR_DIGEST`: `sha256:` + 64 hex and not an existing path ⇒ digest.
- Exit 0 on success, 1 on any error with the tagged reason printed to stderr.
- `--in-toto` ⇒ `{dsse, <<"application/vnd.in-toto+json">>, FileBytes}`.

Note the suite's `test_sign_verify_rekor2` passes a *staging* trusted root and
signing config without `--staging`; the harness must not assume instance from
the flag alone.

## 10. CI

`.github/workflows/conformance.yml`:

```yaml
on: [push, pull_request, schedule: cron '0 6 * * *']
jobs:
  conformance:
    strategy: { matrix: { environment: [production, staging] } }
    steps:
      - uses: actions/checkout@v4
      - uses: erlef/setup-beam@v1   { otp-version: '27', rebar3-version: '3.27' }
      - run: rebar3 escriptize          # builds _build/default/bin/sigstore_conformance
      - uses: sigstore/sigstore-conformance@v0.0.29   # pin; bump deliberately
        with:
          entrypoint: ${{ github.workspace }}/_build/default/bin/sigstore_conformance
          environment: ${{ matrix.environment }}
          xfail: ""                     # start with the README-suggested patterns, burn down to empty
```

The identity token is fetched by the suite itself from a public GCS bucket,
so no repo secrets are needed. Production runs upload `conformance-report.json`.
`ci.yml`: `rebar3 ct`, `rebar3 dialyzer`, `rebar3 xref`, `erlfmt --check`,
OTP matrix 25/26/27/28/29 (hex's floor is 25), plus the vendorability test (§2a V7).

## 11. Milestones

Each milestone ends with the named conformance tests green in CI (using
`xfail` for everything not yet done, burning it down).

| M | Scope | Conformance targets |
|---|---|---|
| M0 | repo, rebar3, escript skeleton that exits 1, CI wiring with everything xfail'd | suite runs, report uploads |
| M1 | JCS serializer, bundle/trust-root models, JSON normalisation, `sigstore_keys`, structural validation, vendorability test | `bundle-*_fail` structural fixtures |
| M2 | x509 chain-at-time, leaf profile, Fulcio OIDs, policy, SCT, message signature | `happy-path-v0.2/0.3`, `signature-mismatch_fail`, `*-expired-certificate_fail`, `invalid-ct-key_fail`, `bundle-with-sct-with-extensions` |
| M3 | merkle, checkpoint (v1+v2 key IDs, cosigs), SET, body cross-check, DSSE/in-toto | all `rekor2-checkpoint-*`, `inclusion-proof-*`, `set-*`, `wrong-hashedrekord-*`, `dsse-*`, `intoto-*`, `happy-path-v0.1`, managed-key |
| M4 | RFC 3161 (asn1 module, CMS verify), TSA-based signed time | all `rekor2-timestamp-*`, `rekor2-*happy-path`, `trust-root-tsa-*`, CPython release bundles ⇒ **verify 100%** |
| M5 | HTTP, Fulcio, CSR, Rekor v1+v2 upload, TSA request, self-verify, bundle emit | `test_simple`, `test_sign_verify_dsse`, `test_sign_does_not_produce_root`, `test_sign_verify_rekor2` ⇒ **xfail empty** |
| M6 | TUF client, embedded roots refresh, hex.pm publish of `sigstore` package | n/a (unit tests against a recorded root-signing snapshot) |

Rough effort: M1-M4 are pure functions with abundant fixtures — the
conformance `bundle-verify/` directory is the unit-test corpus (copy into
`test/vectors/`, run in `ct` without the Python suite). M5 needs network in
tests (use the suite) plus stubbed-transport unit tests.

## 12. Layering above (sketch, non-binding)

- **in-toto (`intoto` app or `sigstore_intoto` growth):** Statement v1
  encode/validate, DSSE multi-signature envelopes, predicate registry. Layer 0
  already stores DSSE payloads verbatim and matches subjects, so nothing here
  changes bundle handling.
- **SLSA (`slsa` app):** `https://slsa.dev/provenance/v1` predicate builder +
  verifier (builder id, source repo, build type against expectations);
  consumes `sigstore:verify/3`'s `statement`.
- **hex integration:** `mix hex.publish` / `rebar3 hex publish` in GitHub
  Actions produces a provenance Statement whose subject is the package tarball
  `sha256` (hex already computes `outer_checksum`), signs it keyless with the
  Actions OIDC token via `sigstore:sign/1`, uploads the `.sigstore.json` bundle
  alongside the tarball. hexpm verifies on upload (`sigstore:verify/3` with a
  policy pinned to the Trusted Publishing claims from #1193: repo, workflow,
  ref) and stores/serves the bundle; clients verify on fetch. Keeping Layer 0's
  policy API extension-based (§6.4) is what makes the #1193 claims pluggable.

### 12.1 How deep does OpenID go? (maennchen's question)

Shallow, and it stops at Layer 0. In the Sigstore model the client only
*presents* an OIDC ID token to Fulcio; Fulcio verifies it. The client
never validates the JWT signature, never does discovery, never needs an
OpenID library. What a client needs is:

- **Ambient credentials (CI):** one HTTPS GET. GitHub Actions:
  `GET $ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore` with
  `Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN`. GitLab, Buildkite,
  CircleCI etc. are env-var reads or one similar request. This is the hex
  publishing path (Trusted Publishing already assumes CI).
- **Interactive login (laptop):** the browser/PKCE flow against Dex
  (`oauth2.sigstore.dev`). This is the only piece that pulls `openidconnect`
  crates into sigstore-rs. We do not need it; if ever wanted, the OAuth
  device-code flow is two HTTPS requests over `httpc`, still no dependency.
- **Claim extraction:** base64url-decode the JWT payload, read `sub`/`email`/`iss`.
  ~20 lines (`sigstore_oidc`).

in-toto and SLSA contain no OIDC at all; they are JSON envelopes and
predicates. The only other place identity shows up is *verification
policy*: the expected SAN + issuer (and later the Trusted Publishing claims)
are plain string comparisons against Fulcio certificate extensions.

## 13. Decisions and open questions

Decided:
- D1. Hand-rolled chain validation (OTP cannot validate at a past time).
- D2 (revised). Hand-written DER for RFC 3161 TSTInfo (no build-time asn1ct, §2a V3); OTP's CMS for the envelope.
- D3 (revised in M1). Atom-keyed snake_case maps as the internal model; JSON-shaped binary-keyed maps only at the codec boundary; no records at the API boundary.
- D4. Structural (not byte-exact) body cross-check by default; JCS available for byte-exact.
- D5. Follow the conformance suite where it is stricter than the client spec (root cert in chain ⇒ reject).
- D6. `tlogEntries` must have exactly one entry in Layer 0.
- D8. Vendoring constraints V1–V8 (§2a) are binding; OTP floor 25; config-map + `http_adapter`/`json_adapter` behaviours mirroring hex_core.
- D9. JSON decode is pluggable with OTP 27 `json` as default (§8.5); no codec shipped; all encoding via own `sigstore_jcs`.
- D7. SCT precert TBS is rebuilt via OTP `plain` record round-trip; proven byte-faithful on real Fulcio certs (§6.3). No DER-splice fallback needed.

Open:
- Q3. Embedded trust-root refresh policy before TUF (M6) lands: ship a snapshot per release, warn if older than N days.
- Q4. Package name on hex: `sigstore` (unclaimed as of writing — check) vs `sigstore_erl`.
- Q5. Should the escript be shipped in the hex package (handy `sigstore verify` CLI) or stay CI-only?
- Q7. Support deprecated Rekor v1 `intoto 0.0.2` entries (six v0.2 fixtures, one happy path `intoto-with-custom-trust-root`) or xfail them permanently as the conformance README suggests? Decide in M3.
- Q6. Threshold verification across multiple Rekor operators (v2 future) — API shape reserves `signed_times`/`log_entries` lists for it.
