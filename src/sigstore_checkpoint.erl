%% @doc C2SP signed-note checkpoints (tlog-checkpoint, signed-note) as
%% used by Rekor v1 and v2 (SPEC.md §6.5).
%%
%% Signature lines whose key hint matches no trusted key are ignored
%% (witness cosignatures, rotated keys); at least one line must verify with
%% the log's key. The key hint is computed from the name on *that* line, so
%% renaming a signer invalidates it (rekor2-checkpoint-no-matching-signature).
-module(sigstore_checkpoint).

-include_lib("public_key/include/public_key.hrl").

-export([parse/1, verify/2, key_hint/2]).

-export_type([t/0]).

-type t() :: #{
    text := binary(),
    origin := binary(),
    size := non_neg_integer(),
    root_hash := binary(),
    extensions := [binary()],
    signatures := [#{name := binary(), hint := binary(), sig := binary()}]
}.

-define(EM_DASH, 226, 128, 148).

-spec parse(binary()) -> {ok, t()} | {error, {checkpoint, term()}}.
parse(Envelope) when is_binary(Envelope) ->
    case binary:split(Envelope, <<"\n\n">>) of
        [Body, SigBlock] ->
            Text = <<Body/binary, "\n">>,
            case binary:split(Body, <<"\n">>, [global]) of
                [Origin, SizeB, RootB | Ext] when Origin =/= <<>> ->
                    with_fields(Text, Origin, SizeB, RootB, Ext, SigBlock);
                [<<>> | _] ->
                    {error, {checkpoint, missing_origin}};
                _ ->
                    {error, {checkpoint, too_few_lines}}
            end;
        [_] ->
            {error, {checkpoint, no_signature_block}}
    end.

with_fields(Text, Origin, SizeB, RootB, Ext, SigBlock) ->
    case {tree_size(SizeB), sigstore_b64:decode(RootB)} of
        {error, _} ->
            {error, {checkpoint, bad_size}};
        {_, {ok, Root}} when byte_size(Root) =/= 32 ->
            {error, {checkpoint, bad_root_hash}};
        {_, {error, _}} ->
            {error, {checkpoint, bad_root_hash}};
        {{ok, Size}, {ok, Root}} ->
            case lists:member(<<>>, Ext) of
                true ->
                    {error, {checkpoint, empty_extension_line}};
                false ->
                    case signatures(SigBlock) of
                        {ok, []} ->
                            {error, {checkpoint, no_signatures}};
                        {ok, Sigs} ->
                            {ok, #{
                                text => Text,
                                origin => Origin,
                                size => Size,
                                root_hash => Root,
                                extensions => Ext,
                                signatures => Sigs
                            }};
                        {error, _} = E ->
                            E
                    end
            end
    end.

tree_size(<<>>) ->
    error;
tree_size(<<$0, _, _/binary>>) ->
    error;
tree_size(B) ->
    case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(B)) of
        true -> {ok, binary_to_integer(B)};
        false -> error
    end.

signatures(<<>>) ->
    {ok, []};
signatures(Block) ->
    case binary:last(Block) of
        $\n ->
            Lines = binary:split(binary:part(Block, 0, byte_size(Block) - 1), <<"\n">>, [global]),
            sig_lines(Lines, []);
        _ ->
            {error, {checkpoint, unterminated_signature_block}}
    end.

sig_lines([], Acc) ->
    {ok, lists:reverse(Acc)};
sig_lines([<<?EM_DASH, " ", Rest/binary>> | T], Acc) ->
    case binary:split(Rest, <<" ">>, [global]) of
        [Name, B64] when Name =/= <<>> ->
            case sigstore_b64:decode(B64) of
                {ok, <<Hint:4/binary, Sig/binary>>} when Sig =/= <<>> ->
                    sig_lines(T, [#{name => Name, hint => Hint, sig => Sig} | Acc]);
                _ ->
                    {error, {checkpoint, bad_signature_line}}
            end;
        _ ->
            {error, {checkpoint, bad_signature_line}}
    end;
sig_lines(_, _) ->
    {error, {checkpoint, bad_signature_line}}.

%% @doc Verify with one trusted log key: some line's hint (computed from its
%% own name) must match the key and its signature must verify.
-spec verify(t(), sigstore_keys:key()) -> ok | {error, {checkpoint, term()}}.
verify(#{text := Text, signatures := Sigs}, Key) ->
    Matching = [S || #{name := N, hint := H} = S <- Sigs, key_hint(Key, N) =:= {ok, H}],
    case Matching of
        [] ->
            {error, {checkpoint, no_matching_signature}};
        _ ->
            case lists:any(fun(#{sig := Sig}) -> verify_sig(Text, Sig, Key) end, Matching) of
                true -> ok;
                false -> {error, {checkpoint, invalid_signature}}
            end
    end.

verify_sig(Text, Sig, #{alg := Alg, public_key := K}) ->
    Hash =
        case Alg of
            ed25519 -> none;
            ecdsa_p384_sha384 -> sha384;
            ecdsa_p521_sha512 -> sha512;
            _ -> sha256
        end,
    try
        public_key:verify(Text, Hash, Sig, K)
    catch
        _:_ -> false
    end.

%% @doc The 4-byte C2SP key hint for `Key' signing under name `Name'.
-spec key_hint(sigstore_keys:key(), binary()) -> {ok, <<_:32>>} | {error, {checkpoint, term()}}.
key_hint(#{alg := ed25519, public_key := {#'ECPoint'{point = Pub}, _}}, Name) ->
    {ok, binary:part(crypto:hash(sha256, <<Name/binary, $\n, 1, Pub/binary>>), 0, 4)};
key_hint(#{alg := {rsa, _}, spki := Spki}, Name) ->
    {ok,
        binary:part(
            crypto:hash(sha256, <<Name/binary, $\n, 16#FF, "PKIX-RSA-PKCS#1v1.5", Spki/binary>>),
            0,
            4
        )};
key_hint(#{spki := Spki}, _Name) ->
    %% ECDSA: RFC 6962-style key ID prefix, independent of the name.
    {ok, binary:part(crypto:hash(sha256, Spki), 0, 4)}.
