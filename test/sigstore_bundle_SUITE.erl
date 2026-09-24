-module(sigstore_bundle_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("common_test/include/ct.hrl").

-export([all/0]).
-export([parses_v03_fixture/1, rejects_unknown_media_type/1, rejects_malformed_json/1]).

all() -> [parses_v03_fixture, rejects_unknown_media_type, rejects_malformed_json].

parses_v03_fixture(Config) ->
    Dir = proplists:get_value(data_dir, Config),
    {ok, Bin} = file:read_file(filename:join(Dir, "happy-path-v0.3.sigstore.json")),
    {ok, B} = sigstore_bundle:from_json(Bin),
    ?assertEqual({ok, v0_3}, sigstore_bundle:version(sigstore_bundle:media_type(B))).

rejects_unknown_media_type(_) ->
    ?assertMatch(
        {error, {bundle, {unknown_media_type, _}}},
        sigstore_bundle:from_json(
            <<"{\"mediaType\":\"application/vnd.dev.sigstore.bundle+json;version=9.9\"}">>
        )
    ).

rejects_malformed_json(_) ->
    ?assertMatch(
        {error, {bundle, {malformed_json, _}}}, sigstore_bundle:from_json(<<"{not json">>)
    ).
