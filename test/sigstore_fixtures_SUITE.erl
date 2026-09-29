%% Every sigstore-conformance bundle-verify fixture (test/vectors/bundle-verify,
%% pinned in UPSTREAM) through the M1 parsers. A fixture is rejected here only
%% if it is structurally invalid; everything else must parse and round-trip,
%% so later milestones reject it for the *intended* reason.
-module(sigstore_fixtures_SUITE).

-include_lib("stdlib/include/assert.hrl").

-define(DEFAULT_IDENTITY,
    <<"https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main">>
).
-define(DEFAULT_ISSUER, <<"https://token.actions.githubusercontent.com">>).

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([
    structural_rejections/1, others_parse/1, round_trip/1, trusted_roots_parse/1, verify_stages/1
]).

all() -> [structural_rejections, others_parse, round_trip, trusted_roots_parse, verify_stages].

%% Fixture => expected structural error. invalid-inclusion-proof_fail is
%% rejected earlier than its README intends, for a correct reason: v0.2+
%% bundles MUST carry a checkpoint (client spec §4).
expected() ->
    #{
        "bundle-empty-certificate-chain_fail" => {bundle, empty_certificate_chain},
        "bundle-invalid-base64-signature_fail" => {bundle, {invalid_base64, <<"signature">>}},
        "bundle-malformed-json_fail" => malformed_json,
        "bundle-negative-log-index_fail" => {bundle, {negative, <<"logIndex">>}},
        "bundle-unknown-version_fail" =>
            {bundle,
                {unknown_media_type, <<"application/vnd.dev.sigstore.bundle+json;version=99.9">>}},
        "bundle-with-root-cert_fail" => {bundle, root_certificate_in_chain},
        "intoto-missing-inclusion-proof_fail" => {bundle, missing_inclusion_proof},
        "invalid-inclusion-proof_fail" => {bundle, missing_checkpoint},
        "rekor2-no-inclusion-proof_fail" => {bundle, missing_inclusion_proof},
        "rekor2-no-timestamp_fail" => {bundle, no_signed_time_source},
        "trust-root-tlog-missing-validity-start_fail" => {trust, {valid_for, missing_start}}
    }.

init_per_suite(Config) ->
    Dir = filename:join(sigstore_test_util:root(), "test/vectors/bundle-verify"),
    {ok, Names} = file:list_dir(Dir),
    Fixtures = lists:sort([N || N <- Names, filelib:is_dir(filename:join(Dir, N))]),
    [{dir, Dir}, {fixtures, Fixtures}, {json, sigstore_test_json:config()} | Config].

end_per_suite(Config) -> Config.

structural_rejections(Config) ->
    maps:foreach(
        fun(Name, Expected) ->
            Got = load(Config, Name),
            case {Expected, Got} of
                {malformed_json, {error, {bundle, {malformed_json, _}}}} -> ok;
                _ -> ?assertEqual({Name, {error, Expected}}, {Name, Got})
            end
        end,
        expected()
    ).

others_parse(Config) ->
    Others = [N || N <- proplists:get_value(fixtures, Config), not maps:is_key(N, expected())],
    %% 70 fixtures at the pinned commit; a refresh must revisit expected/0.
    ?assertEqual(70, length(proplists:get_value(fixtures, Config))),
    ?assertEqual(59, length(Others)),
    [?assertMatch({N, {ok, _}}, {N, load(Config, N)}) || N <- Others].

round_trip(Config) ->
    Cfg = proplists:get_value(json, Config),
    lists:foreach(
        fun(N) ->
            case load(Config, N) of
                {ok, {B, _Root}} ->
                    {ok, Json} = sigstore_bundle:to_json(B),
                    ?assertEqual({N, {ok, B}}, {N, sigstore_bundle:from_json(Cfg, Json)});
                _ ->
                    ok
            end
        end,
        proplists:get_value(fixtures, Config)
    ).

trusted_roots_parse(Config) ->
    Cfg = proplists:get_value(json, Config),
    ?assertMatch({ok, #{tlogs := [_ | _]}}, sigstore:trusted_root(#{config => Cfg})),
    ?assertMatch(
        {ok, #{tlogs := [_ | _]}}, sigstore:trusted_root(#{config => Cfg, instance => staging})
    ),
    ?assertMatch({ok, #{rekor_tlog_urls := [_ | _]}}, sigstore:signing_config(#{config => Cfg})),
    ?assertMatch(
        {ok, #{tsa_urls := [_ | _]}}, sigstore:signing_config(#{config => Cfg, instance => staging})
    ).

%% {ok, {Bundle, Root}} | {error, Reason} — root errors surface first.
load(Config, Name) ->
    Cfg = proplists:get_value(json, Config),
    P = filename:join(proplists:get_value(dir, Config), Name),
    TR = filename:join(P, "trusted_root.json"),
    RootOpts =
        case filelib:is_file(TR) of
            true -> #{config => Cfg, trusted_root => {file, TR}};
            false -> #{config => Cfg}
        end,
    case sigstore:trusted_root(RootOpts) of
        {ok, Root} ->
            {ok, Bin} = file:read_file(filename:join(P, "bundle.sigstore.json")),
            case sigstore_bundle:from_json(Cfg, Bin) of
                {ok, B} -> {ok, {B, Root}};
                E -> E
            end;
        E ->
            E
    end.

%% Where each fixture stops in the full verifier, reviewed against its
%% README. `ok' = verifies end to end. No `_fail' fixture may ever be
%% `ok'. The only non-`_fail' fixture not `ok' is intoto-with-custom-trust-
%% root (deprecated entry type, SPEC D10). Update deliberately.
stages() ->
    #{
        "bundle-empty-certificate-chain_fail" => {bundle, empty_certificate_chain},
        "bundle-from-wrong-instance_fail" => {tlog, unknown_log},
        "bundle-invalid-base64-signature_fail" => {bundle, {invalid_base64, <<"signature">>}},
        "bundle-malformed-json_fail" => malformed_json,
        "bundle-negative-log-index_fail" => {bundle, {negative, <<"logIndex">>}},
        "bundle-unknown-version_fail" =>
            {bundle,
                {unknown_media_type, <<"application/vnd.dev.sigstore.bundle+json;version=99.9">>}},
        "bundle-with-root-cert_fail" => {bundle, root_certificate_in_chain},
        "bundle-with-sct-with-extensions" => ok,
        "checkpoint-bad-keyhint_fail" => {tlog, {checkpoint, no_matching_signature}},
        "checkpoint-wrong-roothash_fail" => {tlog, checkpoint_does_not_match_proof},
        "dsse-invalid-sig_fail" => {tlog, {body, {mismatch, signature}}},
        "dsse-mismatch-envelope_fail" => {tlog, {body, {mismatch, payload_hash}}},
        "dsse-mismatch-sig_fail" => {tlog, {body, {mismatch, signature}}},
        "happy-path-intoto-in-dsse-v3" => ok,
        "happy-path-v0.1" => ok,
        "happy-path-v0.2" => ok,
        "happy-path-v0.3" => ok,
        "happy-path-v0.3-new-mediaType" => ok,
        "inclusion-proof-corrupted-hash_fail" => {tlog, {merkle, root_mismatch}},
        "incorrect-public-key_fail" => {tlog, {merkle, root_mismatch}},
        "integrated-time-in-future_fail" => {chain, {expired_or_not_yet_valid, 0}},
        "intoto-expired-certificate_fail" => {tlog, {unsupported_entry, intoto}},
        "intoto-log-entry-mismatch_fail" => {tlog, {unsupported_entry, intoto}},
        "intoto-missing-inclusion-proof_fail" => {bundle, missing_inclusion_proof},
        "intoto-set-outside-signing-cert-validity_fail" => {tlog, {unsupported_entry, intoto}},
        "intoto-tsa-timestamp-outside-cert-validity_fail" => {tlog, {unsupported_entry, intoto}},
        "intoto-with-custom-trust-root" => {tlog, {unsupported_entry, intoto}},
        "invalid-checkpoint-signature_fail" => {tlog, {checkpoint, invalid_signature}},
        "invalid-ct-key_fail" => {sct, bad_signature},
        "invalid-inclusion-proof_fail" => {bundle, missing_checkpoint},
        "managed-key-and-trusted-root" => ok,
        "managed-key-happy-path" => ok,
        "managed-key-no-key_fail" => {policy, bundle_has_no_certificate},
        "managed-key-wrong-key_fail" => {tlog, {body, {mismatch, verifier}}},
        "message-digest-mismatch_fail" => {signature, message_digest_mismatch},
        "rekor2-checkpoint-cosigned" => ok,
        "rekor2-checkpoint-missing-log-signature_fail" => {tlog, {checkpoint, no_signatures}},
        "rekor2-checkpoint-missing-origin_fail" => {tlog, {checkpoint, too_few_lines}},
        "rekor2-checkpoint-missing-root-hash_fail" => {tlog, {checkpoint, too_few_lines}},
        "rekor2-checkpoint-missing-size_fail" => {tlog, {checkpoint, too_few_lines}},
        "rekor2-checkpoint-multiple-cosigs" => ok,
        "rekor2-checkpoint-no-matching-signature_fail" =>
            {tlog, {checkpoint, no_matching_signature}},
        "rekor2-checkpoint-origin-not-first" => ok,
        "rekor2-checkpoint-two-sigs-cosigned" => ok,
        "rekor2-checkpoint-two-sigs-from-origin" => ok,
        "rekor2-dsse-happy-path" => ok,
        "rekor2-dsse-invalid-sig_fail" => {tlog, {body, {mismatch, signature}}},
        "rekor2-dsse-mismatch-envelope_fail" => {tlog, {body, {mismatch, signature}}},
        "rekor2-dsse-mismatch-sig_fail" => {tlog, {body, {mismatch, signature}}},
        "rekor2-happy-path" => ok,
        "rekor2-no-inclusion-proof_fail" => {bundle, missing_inclusion_proof},
        "rekor2-no-timestamp_fail" => {bundle, no_signed_time_source},
        "rekor2-timestamp-outside-trust-root-tsa-validity_fail" => {tsa, no_trusted_tsa_at_time},
        "rekor2-timestamp-outside-tsa-cert-validity_fail" =>
            {tsa, {chain, {expired_or_not_yet_valid, 0}}},
        "rekor2-timestamp-payload-mismatch_fail" => {tsa, message_imprint_mismatch},
        "rekor2-timestamp-untrusted-tsa-with-embedded-cert_fail" => {tsa, invalid_signature},
        "rekor2-timestamp-untrusted-tsa-without-embedded-cert_fail" => {tsa, invalid_signature},
        "rekor2-timestamp-with-embedded-cert" => ok,
        "rekor2-timestamp-with-expired-cert-chain" => ok,
        "rekor2-timestamp-with-incorrect-time_fail" => {chain, {expired_or_not_yet_valid, 0}},
        "rekor2-timestamp-without-embedded-cert" => ok,
        "set-invalid-signature_fail" => {tlog, invalid_set},
        "signature-mismatch_fail" => {tlog, {body, {mismatch, signature}}},
        "trust-root-tlog-missing-validity-start_fail" => {trust, {valid_for, missing_start}},
        "trust-root-tlog-validity-end-inclusive" => ok,
        "trust-root-tsa-validity-end-inclusive" => ok,
        "wrong-hashedrekord-artifact_fail" => {tlog, {body, {mismatch, signature}}},
        "wrong-hashedrekord-cert-and-sig_fail" => {tlog, {body, {mismatch, signature}}},
        "wrong-hashedrekord-entry_fail" => {tlog, {body, {mismatch, signature}}},
        "wrong-material_fail" => {tlog, {body, {mismatch, artifact_digest}}}
    }.

verify_stages(Config) ->
    Stages = stages(),
    ?assertEqual(lists:sort(proplists:get_value(fixtures, Config)), lists:sort(maps:keys(Stages))),
    maps:foreach(
        fun(Name, Expected) ->
            Got = verify_fixture(Config, Name),
            case {Expected, Got} of
                {malformed_json, {error, {bundle, {malformed_json, _}}}} -> ok;
                {ok, {ok, #{signed_times := [_ | _]}}} -> ok;
                _ -> ?assertEqual({Name, {error, Expected}}, {Name, Got})
            end,
            IsFail = lists:suffix("_fail", Name),
            ?assertNot(IsFail andalso element(1, Got) =:= ok)
        end,
        Stages
    ).

%% Mirrors the conformance suite's per-directory conventions
%% (test/assets/bundle-verify/README.md upstream).
verify_fixture(Config, Name) ->
    Cfg = proplists:get_value(json, Config),
    Dir = proplists:get_value(dir, Config),
    P = filename:join(Dir, Name),
    Rd = fun(F) ->
        case file:read_file(filename:join(P, F)) of
            {ok, B} -> string:trim(B);
            _ -> undefined
        end
    end,
    Artifact =
        case filelib:is_file(filename:join(P, "artifact")) of
            true -> filename:join(P, "artifact");
            false -> filename:join(Dir, "a.txt")
        end,
    Policy =
        case Rd("key.pub") of
            undefined ->
                sigstore_policy:identity(
                    default(Rd("identity"), ?DEFAULT_IDENTITY),
                    default(Rd("issuer"), ?DEFAULT_ISSUER)
                );
            Pem ->
                {ok, K} = sigstore_keys:from_pem(Pem),
                sigstore_policy:key(K)
        end,
    case load(Config, Name) of
        {ok, {_B, Root}} ->
            {ok, Bin} = file:read_file(filename:join(P, "bundle.sigstore.json")),
            sigstore:verify({file, Artifact}, Bin, #{
                config => Cfg, trusted_root => Root, policy => Policy
            });
        {error, {bundle, _}} ->
            %% Structural failure: re-run through verify to get the same error.
            {ok, Root} = sigstore:trusted_root(#{config => Cfg}),
            {ok, Bin} = file:read_file(filename:join(P, "bundle.sigstore.json")),
            sigstore:verify({file, Artifact}, Bin, #{
                config => Cfg, trusted_root => Root, policy => Policy
            });
        {error, _} = E ->
            E
    end.

default(undefined, D) -> D;
default(V, _) -> V.
