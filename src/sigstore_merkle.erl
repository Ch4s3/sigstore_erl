%% @doc RFC 6962 Merkle tree hashing and inclusion proofs, following the
%% transparency-dev/merkle reference algorithm (SPEC.md §6.5).
-module(sigstore_merkle).

-export([leaf_hash/1, node_hash/2, verify_inclusion/5, root_from_inclusion/4]).

-spec leaf_hash(binary()) -> binary().
leaf_hash(Leaf) -> crypto:hash(sha256, <<0, Leaf/binary>>).

-spec node_hash(binary(), binary()) -> binary().
node_hash(L, R) -> crypto:hash(sha256, <<1, L/binary, R/binary>>).

-spec verify_inclusion(non_neg_integer(), pos_integer(), binary(), [binary()], binary()) ->
    ok | {error, {merkle, term()}}.
verify_inclusion(Index, Size, LeafHash, Proof, Root) ->
    case root_from_inclusion(Index, Size, LeafHash, Proof) of
        {ok, Root} -> ok;
        {ok, _} -> {error, {merkle, root_mismatch}};
        {error, _} = E -> E
    end.

%% The proof is `inner' hashes combined according to the index bits, then
%% `border' hashes that are always left siblings.
-spec root_from_inclusion(non_neg_integer(), pos_integer(), binary(), [binary()]) ->
    {ok, binary()} | {error, {merkle, term()}}.
root_from_inclusion(Index, Size, _Leaf, _Proof) when Index >= Size ->
    {error, {merkle, index_beyond_tree_size}};
root_from_inclusion(Index, Size, Leaf, Proof) ->
    Inner = bit_length(Index bxor (Size - 1)),
    Border = popcount(Index bsr Inner),
    case length(Proof) =:= Inner + Border of
        false ->
            {error, {merkle, {wrong_proof_size, length(Proof), Inner + Border}}};
        true ->
            case lists:all(fun(H) -> byte_size(H) =:= 32 end, [Leaf | Proof]) of
                false ->
                    {error, {merkle, bad_hash_size}};
                true ->
                    {InnerHashes, BorderHashes} = lists:split(Inner, Proof),
                    Seed = chain_inner(Leaf, InnerHashes, Index, 0),
                    {ok, lists:foldl(fun(H, Acc) -> node_hash(H, Acc) end, Seed, BorderHashes)}
            end
    end.

chain_inner(Seed, [], _Index, _I) ->
    Seed;
chain_inner(Seed, [H | T], Index, I) ->
    Next =
        case (Index bsr I) band 1 of
            0 -> node_hash(Seed, H);
            1 -> node_hash(H, Seed)
        end,
    chain_inner(Next, T, Index, I + 1).

bit_length(0) -> 0;
bit_length(N) -> 1 + bit_length(N bsr 1).

popcount(0) -> 0;
popcount(N) -> (N band 1) + popcount(N bsr 1).
