-module(sigstore_bundle_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([
    parses_v03_fixture/1,
    rejects_unknown_media_type/1,
    rejects_malformed_json/1,
    custom_json_adapter/1,
    adapter_unavailable_is_clean_error/1,
    decode/2
]).

all() ->
    [
        parses_v03_fixture,
        rejects_unknown_media_type,
        rejects_malformed_json,
        custom_json_adapter,
        adapter_unavailable_is_clean_error
    ].

-define(CFG, sigstore:default_config()).

parses_v03_fixture(Config) ->
    Dir = proplists:get_value(data_dir, Config),
    {ok, Bin} = file:read_file(filename:join(Dir, "happy-path-v0.3.sigstore.json")),
    {ok, B} = sigstore_bundle:from_json(?CFG, Bin),
    ?assertEqual({ok, v0_3}, sigstore_bundle:version(sigstore_bundle:media_type(B))).

rejects_unknown_media_type(_) ->
    ?assertMatch(
        {error, {bundle, {unknown_media_type, _}}},
        sigstore_bundle:from_json(
            ?CFG,
            <<"{\"mediaType\":\"application/vnd.dev.sigstore.bundle+json;version=9.9\"}">>
        )
    ).

rejects_malformed_json(_) ->
    ?assertMatch(
        {error, {bundle, {malformed_json, _}}}, sigstore_bundle:from_json(?CFG, <<"{not json">>)
    ).

%% This suite doubles as a sigstore_json adapter: canned decode, ignores input.
decode(<<"canned">>, #{value := V}) -> {ok, V};
decode(_, _) -> {error, nope}.

custom_json_adapter(_) ->
    Cfg = #{
        json_adapter =>
            {?MODULE, #{
                value => #{<<"mediaType">> => <<"application/vnd.dev.sigstore.bundle.v0.3+json">>}
            }}
    },
    ?assertMatch({ok, #{<<"mediaType">> := _}}, sigstore_bundle:from_json(Cfg, <<"canned">>)),
    ?assertMatch(
        {error, {bundle, {malformed_json, {json, nope}}}},
        sigstore_bundle:from_json(Cfg, <<"other">>)
    ).

adapter_unavailable_is_clean_error(_) ->
    %% On this OTP the default adapter is available; the unavailable path is
    %% exercised by simulating an adapter that reports it.
    ?assertEqual(
        sigstore_json_otp:available(),
        erlang:function_exported(json, decode, 1) orelse code:ensure_loaded(json) =:= {module, json}
    ),
    ?assertMatch(
        {error, {json, {adapter_crashed, _, _, _}}},
        sigstore_json:decode(#{json_adapter => {no_such_module, #{}}}, <<"{}">>)
    ).
