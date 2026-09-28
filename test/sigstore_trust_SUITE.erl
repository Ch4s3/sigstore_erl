-module(sigstore_trust_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    tlog_lookup_by_time/1,
    ctlog_lookup/1,
    cas_at_time/1,
    select_services_prod/1,
    select_services_rules/1,
    client_trust_config_unwrap/1,
    rejects_bad_roots/1
]).

all() ->
    [
        tlog_lookup_by_time,
        ctlog_lookup,
        cas_at_time,
        select_services_prod,
        select_services_rules,
        client_trust_config_unwrap,
        rejects_bad_roots
    ].

cfg() -> sigstore_test_json:config().

root() ->
    {ok, R} = sigstore:trusted_root(#{config => cfg()}),
    R.

t(Iso) ->
    {ok, T} = sigstore_time:parse_rfc3339(Iso),
    T.

tlog_lookup_by_time(_) ->
    R = root(),
    #{log_id := V1Id} = hd([
        L
     || #{base_url := <<"https://rekor.sigstore.dev">>} = L <- maps:get(tlogs, R)
    ]),
    ?assertMatch([_], sigstore_trust:tlogs_for(R, V1Id, t(<<"2024-01-01T00:00:00Z">>))),
    ?assertEqual([], sigstore_trust:tlogs_for(R, V1Id, t(<<"2020-01-01T00:00:00Z">>))),
    ?assertEqual([], sigstore_trust:tlogs_for(R, <<0:256>>, t(<<"2024-01-01T00:00:00Z">>))).

ctlog_lookup(_) ->
    R = root(),
    [#{log_id := Id, valid_for := {S, _}} | _] = maps:get(ctlogs, R),
    ?assertMatch([_], sigstore_trust:ctlogs_for(R, Id, S)).

cas_at_time(_) ->
    R = root(),
    ?assert(length(sigstore_trust:cas_at(R, t(<<"2024-01-01T00:00:00Z">>))) >= 1),
    ?assertEqual([], sigstore_trust:cas_at(R, t(<<"2019-01-01T00:00:00Z">>))).

select_services_prod(_) ->
    {ok, SC} = sigstore:signing_config(#{config => cfg()}),
    Now = sigstore_time:now(),
    ?assertMatch(
        {ok, [#{url := <<"https://fulcio.sigstore.dev">>}]},
        sigstore_trust:select_services(SC, ca, Now, [1])
    ),
    ?assertMatch({ok, [_]}, sigstore_trust:select_services(SC, rekor, Now, [1, 2])),
    ?assertMatch({ok, [_]}, sigstore_trust:select_services(SC, tsa, Now, [1])),
    ?assertMatch(
        {error, {trust, {no_service, ca}}}, sigstore_trust:select_services(SC, ca, Now, [99])
    ).

svc(Url, V, Start, Op) ->
    #{
        <<"url">> => Url,
        <<"majorApiVersion">> => V,
        <<"validFor">> => #{<<"start">> => Start},
        <<"operator">> => Op
    }.

select_services_rules(_) ->
    Doc = #{
        <<"mediaType">> => <<"application/vnd.dev.sigstore.signingconfig.v0.2+json">>,
        <<"rekorTlogUrls">> => [
            svc(<<"https://v2.a">>, 2, <<"2025-01-01T00:00:00Z">>, <<"a">>),
            svc(<<"https://v1.a">>, 1, <<"2021-01-01T00:00:00Z">>, <<"a">>),
            svc(<<"https://v1.b">>, 1, <<"2021-01-01T00:00:00Z">>, <<"b">>),
            svc(<<"https://future.c">>, 1, <<"2999-01-01T00:00:00Z">>, <<"c">>)
        ],
        <<"rekorTlogConfig">> => #{<<"selector">> => <<"ALL">>},
        <<"tsaConfig">> => #{<<"selector">> => <<"EXACT">>, <<"count">> => 2},
        <<"tsaUrls">> => [svc(<<"https://tsa.a">>, 1, <<"2021-01-01T00:00:00Z">>, <<"a">>)]
    },
    {ok, SC} = sigstore_trust:signing_config_from_map(Doc),
    Now = t(<<"2026-01-01T00:00:00Z">>),
    %% One per operator, highest supported version first, future ones excluded.
    {ok, All} = sigstore_trust:select_services(SC, rekor, Now, [1, 2]),
    ?assertEqual([<<"https://v2.a">>, <<"https://v1.b">>], [U || #{url := U} <- All]),
    {ok, V1Only} = sigstore_trust:select_services(SC, rekor, Now, [1]),
    ?assertEqual([<<"https://v1.a">>, <<"https://v1.b">>], [U || #{url := U} <- V1Only]),
    ?assertEqual(
        {error, {trust, {not_enough_services, tsa, 2, 1}}},
        sigstore_trust:select_services(SC, tsa, Now, [1])
    ).

client_trust_config_unwrap(_) ->
    TR = json_decode(sigstore_trust_embedded:trusted_root(staging)),
    SC = json_decode(sigstore_trust_embedded:signing_config(staging)),
    CTC = #{
        <<"mediaType">> => <<"application/vnd.dev.sigstore.clienttrustconfig.v0.1+json">>,
        <<"trustedRoot">> => TR,
        <<"signingConfig">> => SC
    },
    ?assertMatch({ok, #{tlogs := [_ | _]}}, sigstore:trusted_root(#{trusted_root => CTC})),
    ?assertMatch({ok, #{ca_urls := [_ | _]}}, sigstore:signing_config(#{signing_config => CTC})).

rejects_bad_roots(_) ->
    ?assertMatch(
        {error, {trust, {unknown_media_type, _}}},
        sigstore_trust:trusted_root_from_map(#{<<"mediaType">> => <<"x">>})
    ),
    ?assertMatch(
        {error, {trust, {missing, <<"mediaType">>}}}, sigstore_trust:trusted_root_from_map(#{})
    ),
    ?assertMatch(
        {error, {trust, {read, _, enoent}}},
        sigstore:trusted_root(#{trusted_root => {file, "/nonexistent.json"}})
    ),
    ?assertMatch(
        {error, {trust, {invalid_source, _}}}, sigstore:trusted_root(#{trusted_root => 42})
    ).

json_decode(Bin) ->
    {ok, M} = sigstore_json:decode(cfg(), Bin),
    M.
