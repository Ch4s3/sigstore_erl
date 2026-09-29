%% @doc Artifact inputs: file, in-memory binary, or a pre-computed digest.
-module(sigstore_artifact).

-export([digest/2, whole/1]).

-type hash() :: sha256 | sha384 | sha512.

%% @doc Hash the artifact. A pre-hashed input only yields its own algorithm.
-spec digest(sigstore:artifact(), hash()) -> {ok, binary()} | {error, {artifact, term()}}.
digest({digest, H, D}, H) -> {ok, D};
digest({digest, Have, _}, Want) -> {error, {artifact, {digest_algorithm, Have, Want}}};
digest({binary, B}, H) -> {ok, crypto:hash(H, B)};
digest({file, Path}, H) -> hash_file(Path, H).

%% @doc The whole message, for algorithms that cannot sign a prehash (Ed25519).
-spec whole(sigstore:artifact()) -> {ok, binary()} | {error, {artifact, term()}}.
whole({binary, B}) ->
    {ok, B};
whole({file, P}) ->
    case file:read_file(P) of
        {ok, B} -> {ok, B};
        {error, R} -> {error, {artifact, {read, P, R}}}
    end;
whole({digest, _, _}) ->
    {error, {artifact, prehashed_input_needs_prehash_algorithm}}.

hash_file(Path, H) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, F} ->
            try
                loop(F, crypto:hash_init(H))
            after
                ok = file:close(F)
            end;
        {error, R} ->
            {error, {artifact, {read, Path, R}}}
    end.

loop(F, Ctx) ->
    case file:read(F, 1 bsl 16) of
        {ok, Chunk} -> loop(F, crypto:hash_update(Ctx, Chunk));
        eof -> {ok, crypto:hash_final(Ctx)};
        {error, R} -> {error, {artifact, {read, R}}}
    end.
