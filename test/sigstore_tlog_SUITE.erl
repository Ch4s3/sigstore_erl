-module(sigstore_tlog_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    merkle_matches_reference_tree/1,
    merkle_rejects_tampering/1,
    checkpoint_v1_parse_and_verify/1,
    checkpoint_v2_hint_is_name_bound/1,
    checkpoint_ignores_unknown_signers/1,
    checkpoint_parse_errors/1,
    checkpoint_never_raises/1
]).

all() ->
    [
        merkle_matches_reference_tree,
        merkle_rejects_tampering,
        checkpoint_v1_parse_and_verify,
        checkpoint_v2_hint_is_name_bound,
        checkpoint_ignores_unknown_signers,
        checkpoint_parse_errors,
        checkpoint_never_raises
    ].

%%% Reference RFC 6962 tree (§2.1 MTH and §2.1.1 PATH), deliberately naive.

mth([L]) ->
    sigstore_merkle:leaf_hash(L);
mth(Ls) ->
    {A, B} = lists:split(k(length(Ls)), Ls),
    sigstore_merkle:node_hash(mth(A), mth(B)).

path(_M, [_]) ->
    [];
path(M, Ls) ->
    K = k(length(Ls)),
    {A, B} = lists:split(K, Ls),
    case M < K of
        true -> path(M, A) ++ [mth(B)];
        false -> path(M - K, B) ++ [mth(A)]
    end.

%% Largest power of two strictly less than N.
k(N) -> k(N, 1).
k(N, P) when P * 2 < N -> k(N, P * 2);
k(_, P) -> P.

leaves(N) -> [integer_to_binary(I) || I <- lists:seq(1, N)].

merkle_matches_reference_tree(_) ->
    [
        begin
            Ls = leaves(N),
            Root = mth(Ls),
            [
                ?assertEqual(
                    {N, M, ok},
                    {N, M,
                        sigstore_merkle:verify_inclusion(
                            M, N, sigstore_merkle:leaf_hash(lists:nth(M + 1, Ls)), path(M, Ls), Root
                        )}
                )
             || M <- lists:seq(0, N - 1)
            ]
        end
     || N <- lists:seq(1, 33)
    ].

merkle_rejects_tampering(_) ->
    Ls = leaves(13),
    Root = mth(Ls),
    Leaf = sigstore_merkle:leaf_hash(lists:nth(6, Ls)),
    P = path(5, Ls),
    ?assertEqual(ok, sigstore_merkle:verify_inclusion(5, 13, Leaf, P, Root)),
    ?assertMatch(
        {error, {merkle, root_mismatch}}, sigstore_merkle:verify_inclusion(4, 13, Leaf, P, Root)
    ),
    ?assertMatch(
        {error, {merkle, {wrong_proof_size, _, _}}},
        sigstore_merkle:verify_inclusion(5, 13, Leaf, tl(P), Root)
    ),
    ?assertMatch(
        {error, {merkle, {wrong_proof_size, _, _}}},
        sigstore_merkle:verify_inclusion(5, 13, Leaf, P ++ [Root], Root)
    ),
    ?assertMatch(
        {error, {merkle, index_beyond_tree_size}},
        sigstore_merkle:verify_inclusion(13, 13, Leaf, P, Root)
    ),
    [H | T] = P,
    <<B, Rest/binary>> = H,
    ?assertMatch(
        {error, {merkle, root_mismatch}},
        sigstore_merkle:verify_inclusion(5, 13, Leaf, [<<(B bxor 1), Rest/binary>> | T], Root)
    ),
    %% The leaf hash is domain-separated from interior nodes.
    ?assertNotEqual(sigstore_merkle:leaf_hash(<<>>), crypto:hash(sha256, <<>>)).

entry(Fixture) ->
    Bin = sigstore_test_util:read_vector("bundle-verify/" ++ Fixture ++ "/bundle.sigstore.json"),
    {ok, #{tlog_entries := [E]}} = sigstore_bundle:from_json(sigstore_test_json:config(), Bin),
    E.

root(Opts) ->
    {ok, R} = sigstore:trusted_root(Opts#{config => sigstore_test_json:config()}),
    R.

log_key(Root, LogId) ->
    [#{key := K} | _] = sigstore_trust:tlogs_matching(Root, LogId),
    K.

checkpoint_v1_parse_and_verify(_) ->
    #{log_id := Id, inclusion_proof := #{checkpoint := Env, tree_size := Size}} = entry(
        "happy-path-v0.3"
    ),
    {ok, CP} = sigstore_checkpoint:parse(Env),
    ?assertMatch(
        #{
            origin := <<"rekor.sigstore.dev - 2605736670972794746">>,
            size := Size,
            signatures := [_]
        },
        CP
    ),
    ?assertEqual(ok, sigstore_checkpoint:verify(CP, log_key(root(#{}), Id))).

checkpoint_v2_hint_is_name_bound(_) ->
    #{log_id := Id, inclusion_proof := #{checkpoint := Env}} = entry("rekor2-happy-path"),
    Root = root(#{trusted_root => {file, fixture_root("rekor2-happy-path")}}),
    Key = log_key(Root, Id),
    ?assertEqual(ed25519, sigstore_keys:alg(Key)),
    {ok, #{origin := Origin, signatures := [#{name := Origin, hint := Hint}]} = CP} = sigstore_checkpoint:parse(
        Env
    ),
    ?assertEqual({ok, Hint}, sigstore_checkpoint:key_hint(Key, Origin)),
    ?assertNotEqual({ok, Hint}, sigstore_checkpoint:key_hint(Key, <<"github.example">>)),
    ?assertEqual(ok, sigstore_checkpoint:verify(CP, Key)),
    %% The signed text covers the origin: changing it breaks the signature.
    ?assertEqual(
        {error, {checkpoint, invalid_signature}},
        sigstore_checkpoint:verify(CP#{text := <<"x", (maps:get(text, CP))/binary>>}, Key)
    ).

checkpoint_ignores_unknown_signers(_) ->
    #{log_id := Id, inclusion_proof := #{checkpoint := Env}} = entry(
        "rekor2-checkpoint-origin-not-first"
    ),
    Key = log_key(
        root(#{trusted_root => {file, fixture_root("rekor2-checkpoint-origin-not-first")}}), Id
    ),
    {ok, #{signatures := [#{name := <<"witness.example">>}, _]} = CP} = sigstore_checkpoint:parse(
        Env
    ),
    ?assertEqual(ok, sigstore_checkpoint:verify(CP, Key)),
    %% Only unknown signers left: must fail.
    [Witness, _Log] = maps:get(signatures, CP),
    ?assertEqual(
        {error, {checkpoint, no_matching_signature}},
        sigstore_checkpoint:verify(CP#{signatures := [Witness]}, Key)
    ).

checkpoint_parse_errors(_) ->
    Sig = <<226, 128, 148, " log AAAAAAAA\n">>,
    Root = base64:encode(<<0:256>>),
    P = fun(B) -> sigstore_checkpoint:parse(iolist_to_binary(B)) end,
    ?assertMatch(
        {ok, #{size := 7, extensions := [<<"ext">>]}}, P(["o\n7\n", Root, "\next\n\n", Sig])
    ),
    ?assertEqual({error, {checkpoint, no_signature_block}}, P(["o\n7\n", Root, "\n"])),
    ?assertEqual({error, {checkpoint, no_signatures}}, P(["o\n7\n", Root, "\n\n"])),
    ?assertEqual({error, {checkpoint, bad_size}}, P(["o\n07\n", Root, "\n\n", Sig])),
    ?assertEqual({error, {checkpoint, bad_size}}, P(["o\n-1\n", Root, "\n\n", Sig])),
    ?assertEqual({error, {checkpoint, bad_root_hash}}, P(["o\n7\nAAAA\n\n", Sig])),
    ?assertEqual({error, {checkpoint, too_few_lines}}, P(["7\n", Root, "\n\n", Sig])),
    ?assertEqual(
        {error, {checkpoint, bad_signature_line}}, P(["o\n7\n", Root, "\n\n- log AAAAAAAA\n"])
    ),
    ?assertEqual(
        {error, {checkpoint, unterminated_signature_block}},
        P(["o\n7\n", Root, "\n\n", binary:part(Sig, 0, byte_size(Sig) - 1)])
    ).

%% Hostile input must yield tagged errors, never exceptions: every prefix
%% and every single-byte flip of real v1 and v2 checkpoints.
checkpoint_never_raises(_) ->
    Cases = [
        {"happy-path-v0.3", #{}},
        {"rekor2-happy-path", #{trusted_root => {file, fixture_root("rekor2-happy-path")}}}
    ],
    [
        begin
            #{log_id := Id, inclusion_proof := #{checkpoint := Env}} = entry(F),
            Key = log_key(root(Opts), Id),
            Variants =
                [binary:part(Env, 0, N) || N <- lists:seq(0, byte_size(Env) - 1)] ++
                    [flip(Env, I) || I <- lists:seq(0, byte_size(Env) - 1)],
            [
                ?assertMatch(
                    R when R =:= ok orelse element(1, R) =:= error,
                    case sigstore_checkpoint:parse(V) of
                        {ok, CP} -> sigstore_checkpoint:verify(CP, Key);
                        E -> E
                    end
                )
             || V <- Variants
            ]
        end
     || {F, Opts} <- Cases
    ].

flip(B, I) ->
    <<Pre:I/binary, C, Post/binary>> = B,
    <<Pre/binary, (C bxor 16#20), Post/binary>>.

fixture_root(F) ->
    filename:join([sigstore_test_util:root(), "test/vectors/bundle-verify", F, "trusted_root.json"]).
