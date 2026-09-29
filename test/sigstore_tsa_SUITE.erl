-module(sigstore_tsa_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    real_token_parses/1,
    imprint_binds_signature/1,
    der_helpers/1,
    token_never_raises/1,
    rekor2_key_validity_at_tsa_time/1
]).

all() ->
    [
        real_token_parses,
        imprint_binds_signature,
        der_helpers,
        token_never_raises,
        rekor2_key_validity_at_tsa_time
    ].

-define(FIX, "rekor2-happy-path").

bundle() ->
    Bin = sigstore_test_util:read_vector("bundle-verify/" ++ ?FIX ++ "/bundle.sigstore.json"),
    {ok, B} = sigstore_bundle:from_json(sigstore_test_json:config(), Bin),
    B.

root() ->
    Path = filename:join([
        sigstore_test_util:root(), "test/vectors/bundle-verify", ?FIX, "trusted_root.json"
    ]),
    {ok, R} = sigstore:trusted_root(#{
        config => sigstore_test_json:config(), trusted_root => {file, Path}
    }),
    R.

token_and_sig() ->
    #{rfc3161_timestamps := [Tok], content := {message_signature, #{signature := Sig}}} = bundle(),
    {Tok, Sig}.

%% Values cross-checked with `openssl ts -reply -text' on the same token.
real_token_parses(_) ->
    {Tok, Sig} = token_and_sig(),
    {ok, P} = sigstore_tsa:parse(Tok),
    ?assertEqual(<<"2025-06-12T12:02:20Z">>, sigstore_time:to_rfc3339(maps:get(gen_time, P))),
    ?assertEqual(sha256, maps:get(imprint_hash, P)),
    ?assertEqual(crypto:hash(sha256, Sig), maps:get(imprint, P)),
    ?assertEqual({ok, maps:get(gen_time, P)}, sigstore_tsa:verify(Tok, Sig, root())).

imprint_binds_signature(_) ->
    {Tok, Sig} = token_and_sig(),
    ?assertEqual(
        {error, {tsa, message_imprint_mismatch}},
        sigstore_tsa:verify(Tok, <<Sig/binary, 0>>, root())
    ),
    %% A root without this TSA: nothing is trusted at genTime.
    ?assertEqual(
        {error, {tsa, no_trusted_tsa_at_time}},
        sigstore_tsa:verify(Tok, Sig, (root())#{timestamp_authorities := []})
    ).

der_helpers(_) ->
    ?assertEqual(
        {ok, {1, 2, 840, 113549, 1, 9, 16, 1, 4}},
        sigstore_der:oid(<<16#2A, 16#86, 16#48, 16#86, 16#F7, 16#0D, 1, 9, 16, 1, 4>>)
    ),
    ?assertEqual(
        {ok, {2, 16, 840, 1, 101, 3, 4, 2, 1}},
        sigstore_der:oid(<<16#60, 16#86, 16#48, 1, 16#65, 3, 4, 2, 1>>)
    ),
    ?assertMatch({error, _}, sigstore_der:oid(<<16#2A, 16#86>>)),
    {ok, T} = sigstore_der:generalized_time(<<"20250612120220Z">>),
    ?assertEqual({ok, T + 123000}, sigstore_der:generalized_time(<<"20250612120220.123Z">>)),
    ?assertMatch({error, _}, sigstore_der:generalized_time(<<"20251312120220Z">>)),
    ?assertMatch({error, _}, sigstore_der:generalized_time(<<"20250612120220">>)),
    ?assertMatch({error, _}, sigstore_der:generalized_time(<<"20250612120220.Z">>)),
    ?assertEqual({ok, 255}, sigstore_der:uint(<<0, 255>>)),
    ?assertMatch({error, _}, sigstore_der:uint(<<255>>)),
    Long = binary:copy(<<"a">>, 300),
    ?assertEqual({ok, 16#31, Long, <<>>}, sigstore_der:tlv(sigstore_der:encode_tlv(16#31, Long))).

%% Every prefix and single-byte flip of a real token yields a tagged error
%% (or, for flips outside signed data, success), never an exception.
token_never_raises(_) ->
    {Tok, Sig} = token_and_sig(),
    Root = root(),
    Variants =
        [binary:part(Tok, 0, N) || N <- lists:seq(0, byte_size(Tok) - 1)] ++
            [flip(Tok, I) || I <- lists:seq(0, byte_size(Tok) - 1)],
    Outcomes = [sigstore_tsa:verify(V, Sig, Root) || V <- Variants],
    ?assert(lists:all(fun(R) -> element(1, R) =:= ok orelse element(1, R) =:= error end, Outcomes)),
    %% No truncation may verify.
    ?assertEqual([], [ok || {ok, _} <- lists:sublist(Outcomes, byte_size(Tok))]).

flip(B, I) ->
    <<Pre:I/binary, C, Post/binary>> = B,
    <<Pre/binary, (C bxor 16#01), Post/binary>>.

%% Rekor v2 entries carry no signed time of their own: the log key must be
%% valid at the verified TSA time (carried over from M3).
rekor2_key_validity_at_tsa_time(_) ->
    Root = root(),
    Bin = sigstore_test_util:read_vector("bundle-verify/" ++ ?FIX ++ "/bundle.sigstore.json"),
    Art = filename:join([sigstore_test_util:root(), "test/vectors/bundle-verify/a.txt"]),
    Opts = fun(R) ->
        #{
            config => sigstore_test_json:config(),
            trusted_root => R,
            policy => sigstore_policy:identity(
                <<"https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main">>,
                <<"https://token.actions.githubusercontent.com">>
            )
        }
    end,
    {ok, #{signed_times := [{tsa, T}]}} = sigstore:verify({file, Art}, Bin, Opts(Root)),
    Expired = Root#{
        tlogs := [
            L#{valid_for := {S, T - 1}}
         || #{valid_for := {S, _}} = L <- maps:get(tlogs, Root)
        ]
    },
    ?assertEqual(
        {error, {tlog, key_not_valid_at_signed_time}},
        sigstore:verify({file, Art}, Bin, Opts(Expired))
    ),
    Inclusive = Root#{
        tlogs := [L#{valid_for := {S, T}} || #{valid_for := {S, _}} = L <- maps:get(tlogs, Root)]
    },
    ?assertMatch({ok, _}, sigstore:verify({file, Art}, Bin, Opts(Inclusive))).
