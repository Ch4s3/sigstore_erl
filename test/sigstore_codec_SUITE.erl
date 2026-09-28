-module(sigstore_codec_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    jcs_rfc8785_key_order/1,
    jcs_escaping/1,
    jcs_rejects/1,
    jcs_set_payload_shape/1,
    b64_variants/1,
    b64_rejects/1,
    hex/1,
    time_ranges/1,
    strip_nulls/1,
    test_json_matches_otp/1,
    keys/1
]).

all() ->
    [
        jcs_rfc8785_key_order,
        jcs_escaping,
        jcs_rejects,
        jcs_set_payload_shape,
        b64_variants,
        b64_rejects,
        hex,
        time_ranges,
        strip_nulls,
        test_json_matches_otp,
        keys
    ].

%% RFC 8785 §3.2.3 example: UTF-16 code-unit order, so U+1F600 (surrogate
%% D83D) sorts before U+FB33 even though its code point is larger.
jcs_rfc8785_key_order(_) ->
    Keys = [
        <<16#20ac/utf8>>,
        <<"\r">>,
        <<16#fb33/utf8>>,
        <<"1">>,
        <<16#1f600/utf8>>,
        <<16#80/utf8>>,
        <<16#f6/utf8>>
    ],
    M = maps:from_list([{K, <<"x">>} || K <- Keys]),
    {ok, J} = sigstore_jcs:encode(M),
    Expected = [
        <<"\r">>,
        <<"1">>,
        <<16#80/utf8>>,
        <<16#f6/utf8>>,
        <<16#20ac/utf8>>,
        <<16#1f600/utf8>>,
        <<16#fb33/utf8>>
    ],
    ExpectedJson = iolist_to_binary([
        ${,
        lists:join($,, [[$", escape(K), $", $:, <<"\"x\"">>] || K <- Expected]),
        $}
    ]),
    ?assertEqual(ExpectedJson, J).

escape(<<"\r">>) -> <<"\\r">>;
escape(K) -> K.

jcs_escaping(_) ->
    {ok, J} = sigstore_jcs:encode([<<"a\"b\\c/\x01\x1f\b\t\n\f\r", 16#2028/utf8, "é"/utf8>>]),
    ?assertEqual(<<"[\"a\\\"b\\\\c/\\u0001\\u001f\\b\\t\\n\\f\\r", 16#2028/utf8, "é\"]"/utf8>>, J),
    ?assertEqual(
        {ok, <<"{\"a\":[1,-2,true,false,null,{}]}">>},
        sigstore_jcs:encode(#{<<"a">> => [1, -2, true, false, null, #{}]})
    ).

jcs_rejects(_) ->
    ?assertMatch({error, {jcs, {float_unsupported, _}}}, sigstore_jcs:encode(#{<<"a">> => 1.5})),
    ?assertMatch({error, {jcs, {non_binary_key, a}}}, sigstore_jcs:encode(#{a => 1})),
    ?assertMatch({error, {jcs, {invalid_utf8, _}}}, sigstore_jcs:encode(<<255>>)).

%% Rekor v1 SET payload: integers as JSON numbers, keys sorted.
jcs_set_payload_shape(_) ->
    {ok, J} = sigstore_jcs:encode(#{
        <<"logIndex">> => 25579,
        <<"logID">> => <<"c0d2">>,
        <<"integratedTime">> => 1624396085,
        <<"body">> => <<"eyJ9">>
    }),
    ?assertEqual(
        <<"{\"body\":\"eyJ9\",\"integratedTime\":1624396085,\"logID\":\"c0d2\",\"logIndex\":25579}">>,
        J
    ).

b64_variants(_) ->
    Raw = <<251, 255, 191, 1, 2>>,
    Std = base64:encode(Raw),
    ?assertEqual({ok, Raw}, sigstore_b64:decode(Std)),
    ?assertEqual({ok, Raw}, sigstore_b64:decode(binary:replace(Std, <<"=">>, <<>>, [global]))),
    Url = binary:replace(binary:replace(Std, <<"+">>, <<"-">>, [global]), <<"/">>, <<"_">>, [global]),
    ?assertEqual({ok, Raw}, sigstore_b64:decode(Url)),
    ?assertEqual(
        {ok, Raw},
        sigstore_b64:decode(<<
            (binary:part(Std, 0, 4))/binary, "\n", (binary:part(Std, 4, 4))/binary, "\r\n"
        >>)
    ),
    ?assertEqual({ok, <<>>}, sigstore_b64:decode(<<>>)).

b64_rejects(_) ->
    [
        ?assertEqual({B, {error, {base64, invalid}}}, {B, sigstore_b64:decode(B)})
     || B <- [
            <<"INVALID!!!BASE64!!!ENCODING====">>,
            <<"ab cd">>,
            <<"abc===">>,
            <<"a">>,
            <<"ab=c">>,
            <<"\tabc">>
        ]
    ],
    ?assertEqual({error, {base64, invalid}}, sigstore_b64:decode(not_a_binary)).

hex(_) ->
    ?assertEqual(<<"00ff0a">>, sigstore_b64:hex_encode(<<0, 255, 10>>)),
    ?assertEqual({ok, <<0, 255, 10>>}, sigstore_b64:hex_decode(<<"00FF0a">>)),
    ?assertEqual({error, {hex, invalid}}, sigstore_b64:hex_decode(<<"0g">>)),
    ?assertEqual({error, {hex, invalid}}, sigstore_b64:hex_decode(<<"abc">>)).

time_ranges(_) ->
    {ok, {S, E}} = sigstore_time:range(#{
        <<"start">> => <<"2022-10-20T00:00:00Z">>, <<"end">> => <<"2022-10-31T23:59:59.999Z">>
    }),
    ?assert(sigstore_time:in_range(S, {S, E})),
    ?assert(sigstore_time:in_range(E, {S, E})),
    ?assertNot(sigstore_time:in_range(E + 1, {S, E})),
    ?assertNot(sigstore_time:in_range(S - 1, {S, E})),
    ?assertEqual(
        {ok, {S, infinity}}, sigstore_time:range(#{<<"start">> => <<"2022-10-20T00:00:00Z">>})
    ),
    ?assertEqual({error, {time, missing_start}}, sigstore_time:range(#{})),
    ?assertEqual(
        {error, {time, end_before_start}},
        sigstore_time:range(#{
            <<"start">> => <<"2023-01-01T00:00:00Z">>, <<"end">> => <<"2022-01-01T00:00:00Z">>
        })
    ),
    ?assertMatch({error, {time, {invalid, _}}}, sigstore_time:parse_rfc3339(<<"yesterday">>)),
    ?assertEqual(sigstore_time:from_unix_seconds(1666224000), S).

strip_nulls(_) ->
    ?assertEqual(
        #{<<"a">> => [#{}], <<"c">> => 1},
        sigstore_json:strip_nulls(#{<<"a">> => [#{<<"b">> => null}], <<"c">> => 1, <<"d">> => null})
    ).

%% The OTP 25/26 test adapter must agree with OTP json where both exist.
test_json_matches_otp(_) ->
    Doc = <<"{\"a\":[1,-2.5e1,true,false,null,\"x\\u00e9\\ud83d\\ude00\\n\"],\"b\":{}}">>,
    {ok, Mine} = sigstore_test_json:decode(Doc, #{}),
    _ =
        case sigstore_json_otp:available() of
            true -> ?assertEqual(sigstore_json_otp:decode(Doc, #{}), {ok, Mine});
            false -> ok
        end,
    ?assertMatch({error, _}, sigstore_test_json:decode(<<"{\"a\":1} x">>, #{})).

keys(_) ->
    Pem = sigstore_test_util:read_vector("bundle-verify/managed-key-happy-path/key.pub"),
    {ok, K} = sigstore_keys:from_pem(Pem),
    ?assertEqual(ecdsa_p256_sha256, sigstore_keys:alg(K)),
    ?assert(sigstore_keys:key_matches_details(K, <<"PKIX_ECDSA_P256_SHA_256">>)),
    ?assertNot(sigstore_keys:key_matches_details(K, <<"PKIX_ED25519">>)),
    ?assertEqual(32, byte_size(sigstore_keys:key_id(K))),
    %% Rekor v2 production log key from the embedded root is Ed25519.
    {ok, Root} = sigstore:trusted_root(#{config => sigstore_test_json:config()}),
    Algs = [sigstore_keys:alg(Key) || #{key := Key} <- maps:get(tlogs, Root), is_map(Key)],
    ?assert(lists:member(ed25519, Algs)),
    ?assert(lists:member(ecdsa_p256_sha256, Algs)),
    ?assertMatch({error, {key, _}}, sigstore_keys:from_pem(<<"nope">>)),
    ?assertMatch({error, {key, _}}, sigstore_keys:from_spki_der(<<1, 2, 3>>)).
