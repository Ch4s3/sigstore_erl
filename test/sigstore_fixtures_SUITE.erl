%% Every sigstore-conformance bundle-verify fixture (test/vectors/bundle-verify,
%% pinned in UPSTREAM) through the M1 parsers. A fixture is rejected here only
%% if it is structurally invalid; everything else must parse and round-trip,
%% so later milestones reject it for the *intended* reason.
-module(sigstore_fixtures_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([structural_rejections/1, others_parse/1, round_trip/1, trusted_roots_parse/1]).

all() -> [structural_rejections, others_parse, round_trip, trusted_roots_parse].

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
