%% @doc RFC 3161 timestamp verification (SPEC.md §6.1, §6.8).
%%
%% Parsed with `sigstore_der' end to end: OTP names the CMS ASN.1 module
%% differently across the OTP 25..29 range hex supports, so it is not used.
%% Only trust-root TSA certificates are trusted; certificates embedded in a
%% response never become anchors. The TSA chain is validated at the token's
%% own genTime (hybrid model).
-module(sigstore_tsa).

-include("sigstore.hrl").

-export([verify/3, parse/1]).

-define(OID_SIGNED_DATA, {1, 2, 840, 113549, 1, 7, 2}).
-define(OID_TST_INFO, {1, 2, 840, 113549, 1, 9, 16, 1, 4}).
-define(OID_CONTENT_TYPE, {1, 2, 840, 113549, 1, 9, 3}).
-define(OID_MESSAGE_DIGEST, {1, 2, 840, 113549, 1, 9, 4}).

-type token() :: #{
    tst_info := binary(),
    gen_time := sigstore_time:t(),
    imprint_hash := sha256 | sha384 | sha512,
    imprint := binary(),
    digest_hash := sha256 | sha384 | sha512,
    signed_attrs := binary(),
    message_digest := binary(),
    signature := binary()
}.

%% @doc Verify a DER TimeStampResp over `Signed' (the bundle's signature
%% bytes). Returns the verified genTime.
-spec verify(binary(), binary(), sigstore_trust:trusted_root()) ->
    {ok, sigstore_time:t()} | {error, {tsa, term()}}.
verify(Resp, Signed, Root) ->
    case parse(Resp) of
        {ok, #{imprint_hash := IH, imprint := Imprint} = Tok} ->
            case crypto:hash(IH, Signed) =:= Imprint of
                false -> {error, {tsa, message_imprint_mismatch}};
                true -> verify_signer(Tok, Root)
            end;
        {error, _} = E ->
            E
    end.

verify_signer(
    #{gen_time := T, tst_info := TST, digest_hash := DH, message_digest := MD} = Tok, Root
) ->
    case crypto:hash(DH, TST) =:= MD of
        false ->
            {error, {tsa, message_digest_attribute_mismatch}};
        true ->
            case
                [
                    A
                 || #{valid_for := R} = A <- sigstore_trust:tsas(Root), sigstore_time:in_range(T, R)
                ]
            of
                [] ->
                    {error, {tsa, no_trusted_tsa_at_time}};
                TSAs ->
                    Results = [by_authority(Tok, A) || A <- TSAs],
                    case [ok || ok <- Results] of
                        [ok | _] -> {ok, T};
                        [] -> hd(Results)
                    end
            end
    end.

by_authority(#{gen_time := T, signed_attrs := Attrs, signature := Sig, digest_hash := DH}, #{
    cert_chain := Chain
}) ->
    [LeafDer | _] = Chain,
    case sigstore_x509:decode(LeafDer) of
        {ok, Leaf} ->
            checks([
                fun() ->
                    bool(
                        sigstore_x509:has_eku(Leaf, ?OID_KP_TIME_STAMPING), missing_timestamping_eku
                    )
                end,
                fun() ->
                    case sigstore_x509:public_key(Leaf) of
                        {ok, #{public_key := K}} ->
                            bool(safe_verify(Attrs, DH, Sig, K), invalid_signature);
                        {error, R} ->
                            {error, {tsa, R}}
                    end
                end,
                fun() -> chain_at(Leaf, Chain, T) end
            ]);
        {error, R} ->
            {error, {tsa, R}}
    end.

%% The trust-root chain is [leaf, intermediates..., root]; a one-element
%% chain is a self-standing leaf that only needs validity at genTime.
chain_at(Leaf, [_], T) ->
    {NB, NA} = sigstore_x509:validity(Leaf),
    bool(T >= NB andalso T =< NA, leaf_not_valid_at_time);
chain_at(Leaf, [_ | Rest], T) ->
    case sigstore_x509:validate_chain(Leaf, [], [{lists:last(Rest), lists:droplast(Rest)}], T) of
        {ok, _} -> ok;
        {error, {chain, R}} -> {error, {tsa, {chain, R}}}
    end.

safe_verify(Msg, Hash, Sig, K) ->
    try
        public_key:verify(Msg, Hash, Sig, K)
    catch
        _:_ -> false
    end.

%%% Parsing.

-spec parse(binary()) -> {ok, token()} | {error, {tsa, term()}}.
parse(Resp) ->
    try
        {ok, parse_resp(Resp)}
    catch
        throw:{tsa, _} = E -> {error, E};
        %% Any other crash on hostile input is a malformed token.
        error:_ -> {error, {tsa, malformed}}
    end.

parse_resp(Resp) ->
    {ok, 16#30, Body, <<>>} = der(sigstore_der:tlv(Resp)),
    [{16#30, Status}, {16#30, ContentInfo} | _] = der(sigstore_der:children(Body)),
    [{16#02, S} | _] = der(sigstore_der:children(Status)),
    lists:member(der(sigstore_der:uint(S)), [0, 1]) orelse throw({tsa, {not_granted, S}}),
    [{16#06, CT}, {16#A0, Explicit}] = der(sigstore_der:children(ContentInfo)),
    der(sigstore_der:oid(CT)) =:= ?OID_SIGNED_DATA orelse throw({tsa, not_signed_data}),
    {ok, 16#30, SD, <<>>} = der(sigstore_der:tlv(Explicit)),
    signed_data(der(sigstore_der:children(SD))).

signed_data([{16#02, _Version}, {16#31, _DigestAlgs}, {16#30, Encap} | Rest]) ->
    [{16#06, ECT}, {16#A0, EExplicit}] = der(sigstore_der:children(Encap)),
    der(sigstore_der:oid(ECT)) =:= ?OID_TST_INFO orelse throw({tsa, not_tst_info}),
    {ok, 16#04, TST, <<>>} = der(sigstore_der:tlv(EExplicit)),
    %% Skip optional certificates [0] and crls [1]: never trusted.
    [{16#31, SignerInfos}] = [X || {Tag, _} = X <- Rest, Tag =:= 16#31],
    case der(sigstore_der:children(SignerInfos)) of
        [{16#30, SI}] ->
            maps:merge(tst_info(TST), signer_info(der(sigstore_der:children(SI)), TST));
        _ ->
            throw({tsa, signer_count})
    end;
signed_data(_) ->
    throw({tsa, malformed_signed_data}).

tst_info(TST) ->
    {ok, 16#30, Body, <<>>} = der(sigstore_der:tlv(TST)),
    [{16#02, _V}, {16#06, _Policy}, {16#30, MI}, {16#02, _Serial}, {16#18, GT} | _] = der(
        sigstore_der:children(Body)
    ),
    [{16#30, AlgId}, {16#04, Imprint}] = der(sigstore_der:children(MI)),
    #{
        tst_info => TST,
        gen_time => der(sigstore_der:generalized_time(GT)),
        imprint_hash => hash_alg(AlgId),
        imprint => Imprint
    }.

signer_info(
    [
        {16#02, _V},
        {_SidTag, _Sid},
        {16#30, DigestAlg},
        {16#A0, Attrs},
        {16#30, _SigAlg},
        {16#04, Sig}
        | _
    ],
    TST
) ->
    _ = TST,
    AttrList = der(sigstore_der:children(Attrs)),
    Found = [attr(der(sigstore_der:children(A))) || {16#30, A} <- AttrList],
    CT = proplists:get_value(content_type, Found),
    CT =:= ?OID_TST_INFO orelse throw({tsa, bad_content_type_attribute}),
    MD =
        case proplists:get_value(message_digest, Found) of
            undefined -> throw({tsa, missing_message_digest_attribute});
            V -> V
        end,
    #{
        digest_hash => hash_alg(DigestAlg),
        %% The signature covers the attributes DER-encoded as a SET (0x31),
        %% not with the IMPLICIT [0] tag they carry here (RFC 5652 §5.4).
        signed_attrs => sigstore_der:encode_tlv(16#31, Attrs),
        message_digest => MD,
        signature => Sig
    };
signer_info(_, _) ->
    throw({tsa, malformed_signer_info}).

attr([{16#06, Oid}, {16#31, Values}]) ->
    case der(sigstore_der:oid(Oid)) of
        ?OID_CONTENT_TYPE ->
            [{16#06, V}] = der(sigstore_der:children(Values)),
            {content_type, der(sigstore_der:oid(V))};
        ?OID_MESSAGE_DIGEST ->
            [{16#04, V}] = der(sigstore_der:children(Values)),
            {message_digest, V};
        Other ->
            {Other, ignored}
    end;
attr(_) ->
    throw({tsa, malformed_attribute}).

hash_alg(AlgId) ->
    [{16#06, O} | _] = der(sigstore_der:children(AlgId)),
    case der(sigstore_der:oid(O)) of
        {2, 16, 840, 1, 101, 3, 4, 2, 1} -> sha256;
        {2, 16, 840, 1, 101, 3, 4, 2, 2} -> sha384;
        {2, 16, 840, 1, 101, 3, 4, 2, 3} -> sha512;
        Other -> throw({tsa, {unsupported_hash, Other}})
    end.

der({ok, V}) -> V;
der({ok, T, V, R}) -> {ok, T, V, R};
der({error, E}) -> throw({tsa, E}).

bool(true, _) -> ok;
bool(false, Why) -> {error, {tsa, Why}}.

checks([]) ->
    ok;
checks([F | T]) ->
    case F() of
        ok -> checks(T);
        {error, _} = E -> E
    end.
