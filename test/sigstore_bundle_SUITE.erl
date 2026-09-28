-module(sigstore_bundle_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    parses_v03/1,
    parses_v01_chain/1,
    parses_managed_key/1,
    parses_dsse/1,
    emits_int64_as_strings/1,
    rejects_unknown_media_type/1,
    rejects_malformed_json/1,
    rejects_conflicting_content/1,
    custom_json_adapter/1,
    adapter_errors_are_wrapped/1,
    decode/2
]).

all() ->
    [
        parses_v03,
        parses_v01_chain,
        parses_managed_key,
        parses_dsse,
        emits_int64_as_strings,
        rejects_unknown_media_type,
        rejects_malformed_json,
        rejects_conflicting_content,
        custom_json_adapter,
        adapter_errors_are_wrapped
    ].

parse(Fixture) ->
    Bin = sigstore_test_util:read_vector("bundle-verify/" ++ Fixture ++ "/bundle.sigstore.json"),
    sigstore_bundle:from_json(sigstore_test_json:config(), Bin).

parses_v03(_) ->
    {ok, B} = parse("happy-path-v0.3"),
    ?assertMatch(
        #{
            version := v0_3,
            material := {certificate, <<16#30, _/binary>>},
            tlog_entries := [
                #{
                    kind_version := {<<"hashedrekord">>, <<"0.0.1">>},
                    inclusion_proof := #{checkpoint := <<_/binary>>, hashes := [_ | _]},
                    inclusion_promise := <<_/binary>>
                }
            ],
            content := {message_signature, #{signature := <<_/binary>>}}
        },
        B
    ).

parses_v01_chain(_) ->
    {ok, B} = parse("happy-path-v0.1"),
    ?assertMatch(#{version := v0_1, material := {x509_certificate_chain, [_ | _]}}, B).

parses_managed_key(_) ->
    {ok, B} = parse("managed-key-happy-path"),
    ?assertMatch(#{material := {public_key, <<_/binary>>}, rfc3161_timestamps := [_]}, B).

parses_dsse(_) ->
    {ok, B} = parse("rekor2-dsse-happy-path"),
    ?assertMatch(
        {dsse_envelope, #{
            payload_type := <<"application/vnd.in-toto+json">>, signatures := [#{sig := _}]
        }},
        maps:get(content, B)
    ),
    ?assertMatch(
        [#{kind_version := {<<"hashedrekord">>, <<"0.0.2">>}, inclusion_promise := undefined}],
        maps:get(tlog_entries, B)
    ).

emits_int64_as_strings(_) ->
    {ok, B} = parse("happy-path-v0.3"),
    {ok, Json} = sigstore_bundle:to_json(B),
    {ok, M} = sigstore_json:decode(sigstore_test_json:config(), Json),
    #{<<"verificationMaterial">> := #{<<"tlogEntries">> := [E]}} = M,
    ?assert(is_binary(maps:get(<<"logIndex">>, E))),
    ?assert(is_binary(maps:get(<<"integratedTime">>, E))).

rejects_unknown_media_type(_) ->
    ?assertMatch(
        {error, {bundle, {unknown_media_type, _}}},
        sigstore_bundle:from_map(#{
            <<"mediaType">> => <<"application/vnd.dev.sigstore.bundle+json;version=9.9">>
        })
    ).

rejects_malformed_json(_) ->
    ?assertMatch(
        {error, {bundle, {malformed_json, _}}},
        sigstore_bundle:from_json(sigstore_test_json:config(), <<"{not json">>)
    ).

rejects_conflicting_content(_) ->
    {ok, B} = parse("happy-path-v0.3"),
    M = sigstore_bundle:to_map(B),
    Both = M#{
        <<"dsseEnvelope">> => #{
            <<"payload">> => <<>>, <<"payloadType">> => <<"x">>, <<"signatures">> => []
        }
    },
    ?assertEqual({error, {bundle, conflicting_content}}, sigstore_bundle:from_map(Both)),
    None = maps:remove(<<"messageSignature">>, M),
    ?assertEqual({error, {bundle, missing_content}}, sigstore_bundle:from_map(None)).

%% This suite doubles as a sigstore_json adapter: canned decode.
decode(<<"canned">>, #{value := V}) -> {ok, V};
decode(<<"crash">>, _) -> error(boom);
decode(_, _) -> {error, nope}.

custom_json_adapter(_) ->
    {ok, B} = parse("happy-path-v0.3"),
    Cfg = #{json_adapter => {?MODULE, #{value => sigstore_bundle:to_map(B)}}},
    ?assertEqual({ok, B}, sigstore_bundle:from_json(Cfg, <<"canned">>)),
    ?assertEqual(
        {error, {bundle, {malformed_json, {json, nope}}}},
        sigstore_bundle:from_json(Cfg, <<"other">>)
    ).

adapter_errors_are_wrapped(_) ->
    Cfg = #{json_adapter => {?MODULE, #{}}},
    ?assertMatch(
        {error, {json, {adapter_crashed, ?MODULE, error, boom}}},
        sigstore_json:decode(Cfg, <<"crash">>)
    ),
    ?assertMatch(
        {error, {json, {adapter_crashed, no_such_module, _, _}}},
        sigstore_json:decode(#{json_adapter => {no_such_module, #{}}}, <<"{}">>)
    ).
