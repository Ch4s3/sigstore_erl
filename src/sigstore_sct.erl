%% @doc RFC 6962 embedded SCT verification for Fulcio leaves (SPEC.md §6.3).
%%
%% The precertificate TBS is rebuilt by dropping the SCT-list extension and
%% re-encoding through OTP's `plain' records, which was proven byte-faithful
%% against real Fulcio certificates (test/probes/sct_probe.erl, SPEC D7).
-module(sigstore_sct).

-include_lib("public_key/include/public_key.hrl").
-include("sigstore.hrl").

-export([verify_embedded/3, parse_list/1]).

-type sct() :: #{
    log_id := binary(),
    timestamp_ms := non_neg_integer(),
    extensions := binary(),
    hash_alg := byte(),
    sig_alg := byte(),
    signature := binary()
}.

%% @doc Verify the leaf's single embedded SCT. `Path' is the validated chain
%% (leaf first), which supplies the issuer.
-spec verify_embedded(
    sigstore_x509:cert(), [sigstore_x509:cert(), ...], sigstore_trust:trusted_root()
) ->
    ok | {error, {sct, term()}}.
verify_embedded(#{der := LeafDer}, [_Leaf | Issuers], Root) ->
    Plain = public_key:pkix_decode_cert(LeafDer, plain),
    TBS = Plain#'Certificate'.tbsCertificate,
    Exts = TBS#'TBSCertificate'.extensions,
    case lists:partition(fun(#'Extension'{extnID = O}) -> O =:= ?OID_SCT_LIST end, Exts) of
        {[], _} ->
            {error, {sct, missing}};
        {[#'Extension'{extnValue = V}], Rest} ->
            PreTbs = public_key:pkix_encode(
                'TBSCertificate', TBS#'TBSCertificate'{extensions = Rest}, plain
            ),
            case {parse_list(V), issuer_key_hash(Issuers)} of
                {{ok, [Sct]}, {ok, IKH}} -> verify_one(Sct, PreTbs, IKH, Root);
                {{ok, Scts}, _} when length(Scts) =/= 1 -> {error, {sct, {count, length(Scts)}}};
                {{error, _} = E, _} -> E;
                {_, {error, _} = E} -> E
            end;
        {_, _} ->
            {error, {sct, duplicate_extension}}
    end.

%% The issuer is the next cert up, unless that is a CT precert-signing cert
%% (EKU 1.3.6.1.4.1.11129.2.4.4), in which case the one above it.
issuer_key_hash([Issuer | Above]) ->
    Pick =
        case {is_precert_signer(Issuer), Above} of
            {true, [Real | _]} -> {ok, Real};
            {true, []} -> {error, {sct, precert_signer_without_issuer}};
            {false, _} -> {ok, Issuer}
        end,
    case Pick of
        {ok, #{der := D}} ->
            #'Certificate'{tbsCertificate = #'TBSCertificate'{subjectPublicKeyInfo = Spki}} =
                public_key:pkix_decode_cert(D, plain),
            {ok, crypto:hash(sha256, public_key:der_encode('SubjectPublicKeyInfo', Spki))};
        E ->
            E
    end;
issuer_key_hash([]) ->
    {error, {sct, no_issuer}}.

is_precert_signer(#{otp := C}) ->
    Exts =
        case (C#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.extensions of
            asn1_NOVALUE -> [];
            L -> L
        end,
    case lists:keyfind(?'id-ce-extKeyUsage', #'Extension'.extnID, Exts) of
        #'Extension'{extnValue = EKUs} when is_list(EKUs) ->
            lists:member(?OID_CT_PRECERT_SIGNING, EKUs);
        _ ->
            false
    end.

%% @doc Parse the extension value: OCTET STRING (sometimes still wrapped)
%% holding a TLS `SignedCertificateTimestampList'.
-spec parse_list(binary()) -> {ok, [sct()]} | {error, {sct, term()}}.
parse_list(<<4, _/binary>> = Wrapped) ->
    case sigstore_der:tlv(Wrapped) of
        {ok, 4, Inner, <<>>} -> parse_list(Inner);
        _ -> {error, {sct, bad_list}}
    end;
parse_list(<<Len:16, Body:Len/binary>>) ->
    scts(Body, []);
parse_list(_) ->
    {error, {sct, bad_list}}.

scts(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
scts(<<L:16, S:L/binary, Rest/binary>>, Acc) ->
    case sct(S) of
        {ok, Sct} -> scts(Rest, [Sct | Acc]);
        E -> E
    end;
scts(_, _) ->
    {error, {sct, bad_list}}.

sct(
    <<0, LogId:32/binary, Ts:64, ExtLen:16, Ext:ExtLen/binary, H, S, SigLen:16, Sig:SigLen/binary>>
) ->
    {ok, #{
        log_id => LogId,
        timestamp_ms => Ts,
        extensions => Ext,
        hash_alg => H,
        sig_alg => S,
        signature => Sig
    }};
sct(<<V, _/binary>>) when V =/= 0 ->
    {error, {sct, {unsupported_version, V}}};
sct(_) ->
    {error, {sct, malformed}}.

verify_one(
    #{log_id := Id, timestamp_ms := Ts, extensions := Ext, hash_alg := 4, signature := Sig},
    PreTbs,
    IKH,
    Root
) ->
    Signed =
        <<0, 0, Ts:64, 1:16, IKH/binary, (byte_size(PreTbs)):24, PreTbs/binary, (byte_size(Ext)):16,
            Ext/binary>>,
    T = Ts * 1000,
    %% The log ID is an unauthenticated hint: prefer matching logs valid at
    %% the SCT time, then fall back to every CT log valid then.
    Preferred = sigstore_trust:ctlogs_for(Root, Id, T),
    Fallback =
        [L || #{valid_for := R} = L <- maps:get(ctlogs, Root), sigstore_time:in_range(T, R)] --
            Preferred,
    case lists:any(fun(L) -> verify_with(L, Signed, Sig) end, Preferred ++ Fallback) of
        true -> ok;
        false when Preferred =:= [], Fallback =:= [] -> {error, {sct, no_ct_log_at_time}};
        false -> {error, {sct, bad_signature}}
    end;
verify_one(#{hash_alg := H}, _, _, _) ->
    {error, {sct, {unsupported_hash, H}}}.

verify_with(#{key := #{public_key := K}}, Signed, Sig) ->
    try
        public_key:verify(Signed, sha256, Sig, K)
    catch
        _:_ -> false
    end;
verify_with(_, _, _) ->
    false.
