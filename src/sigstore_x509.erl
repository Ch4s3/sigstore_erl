%% @doc X.509 for Sigstore (SPEC.md §6.2, §6.4): decoding, the Fulcio leaf
%% profile, identity extraction, and chain validation at an arbitrary time.
%%
%% OTP's `pkix_path_validation/3' always validates against the wall clock,
%% but Sigstore validates the (short-lived) leaf at the time it was used.
%% So path building and checking are done here, with `public_key' only
%% used for primitives (signature check, issuer-name match).
-module(sigstore_x509).

-include_lib("public_key/include/public_key.hrl").
-include("sigstore.hrl").

-export([
    decode/1,
    public_key/1,
    validity/1,
    leaf_profile/1,
    is_ca/1,
    san/1,
    fulcio_ext/2,
    issuer/1,
    validate_chain/4
]).

-export_type([cert/0]).

%% Decoded certificate plus its DER. Opaque to callers.
-type cert() :: #{der := binary(), otp := #'OTPCertificate'{}}.

-define(MAX_DEPTH, 8).

-spec decode(binary()) -> {ok, cert()} | {error, {cert, term()}}.
decode(Der) when is_binary(Der) ->
    try
        {ok, #{der => Der, otp => public_key:pkix_decode_cert(Der, otp)}}
    catch
        _:_ -> {error, {cert, undecodable}}
    end.

%% @doc The subject public key, via its DER SPKI (stable across OTP versions).
-spec public_key(cert()) -> {ok, sigstore_keys:key()} | {error, {key, term()}}.
public_key(#{der := Der}) ->
    #'Certificate'{tbsCertificate = #'TBSCertificate'{subjectPublicKeyInfo = Spki}} =
        public_key:pkix_decode_cert(Der, plain),
    sigstore_keys:from_spki_der(public_key:der_encode('SubjectPublicKeyInfo', Spki)).

-spec validity(cert()) -> {sigstore_time:t(), sigstore_time:t()}.
validity(#{otp := C}) ->
    #'Validity'{notBefore = NB, notAfter = NA} =
        (C#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.validity,
    {x509_time(NB), x509_time(NA)}.

%% RFC 5280 §4.1.2.5: UTCTime years 50..99 are 19xx.
x509_time({utcTime, [Y1, Y2 | Rest]}) ->
    YY = list_to_integer([Y1, Y2]),
    Century =
        if
            YY >= 50 -> "19";
            true -> "20"
        end,
    x509_time({generalTime, Century ++ [Y1, Y2 | Rest]});
x509_time({generalTime, [Y1, Y2, Y3, Y4, Mo1, Mo2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, $Z]}) ->
    Secs = calendar:datetime_to_gregorian_seconds(
        {
            {
                list_to_integer([Y1, Y2, Y3, Y4]),
                list_to_integer([Mo1, Mo2]),
                list_to_integer([D1, D2])
            },
            {list_to_integer([H1, H2]), list_to_integer([Mi1, Mi2]), list_to_integer([S1, S2])}
        }
    ),
    sigstore_time:from_unix_seconds(Secs - 62167219200).

%% @doc Fulcio leaf profile (client spec §4): not a CA, digitalSignature,
%% codeSigning EKU, exactly one SAN.
-spec leaf_profile(cert()) -> ok | {error, {cert, term()}}.
leaf_profile(C) ->
    checks([
        {not is_ca(C), leaf_is_ca},
        {
            lists:member(digitalSignature, ext_value(C, ?'id-ce-keyUsage', [])),
            missing_digital_signature
        },
        {
            lists:member(?OID_KP_CODE_SIGNING, ext_value(C, ?'id-ce-extKeyUsage', [])),
            missing_code_signing_eku
        },
        {length(ext_value(C, ?'id-ce-subjectAltName', [])) =:= 1, san_count}
    ]).

checks([]) -> ok;
checks([{true, _} | T]) -> checks(T);
checks([{false, Why} | _]) -> {error, {cert, Why}}.

-spec is_ca(cert()) -> boolean().
is_ca(C) ->
    case ext_value(C, ?'id-ce-basicConstraints', undefined) of
        #'BasicConstraints'{cA = true} -> true;
        _ -> false
    end.

%% @doc The single SAN as a binary. otherName is Fulcio's
%% `1.3.6.1.4.1.57264.1.7' (UTF8String username).
-spec san(cert()) -> {ok, {email | uri | other, binary()}} | {error, {cert, term()}}.
san(C) ->
    case ext_value(C, ?'id-ce-subjectAltName', []) of
        [{rfc822Name, V}] -> {ok, {email, to_bin(V)}};
        [{uniformResourceIdentifier, V}] -> {ok, {uri, to_bin(V)}};
        [{otherName, {_Rec, ?OID_FULCIO(7), V}}] -> other_name(V);
        [] -> {error, {cert, no_san}};
        [Other] -> {error, {cert, {unsupported_san, element(1, Other)}}};
        _ -> {error, {cert, san_count}}
    end.

%% otherName decodes to a 3-tuple whose record name differs across OTP
%% versions ('AnotherName' before OTP 27's INSTANCE OF), so match by shape.
%% The value is `[0] EXPLICIT UTF8String' or already unwrapped.
other_name(V) when is_binary(V) ->
    case sigstore_der:tlv(V) of
        {ok, 16#A0, Inner, <<>>} -> tag_other(sigstore_der:utf8_string(Inner));
        {ok, 16#0C, S, <<>>} -> {ok, {other, S}};
        _ -> {error, {cert, bad_other_name}}
    end;
other_name(V) when is_list(V) ->
    {ok, {other, to_bin(V)}};
other_name(_) ->
    {error, {cert, bad_other_name}}.

tag_other({ok, S}) -> {ok, {other, S}};
tag_other(_) -> {error, {cert, bad_other_name}}.

%% @doc A Fulcio extension `1.3.6.1.4.1.57264.1.N' as a string. N = 1..6
%% hold raw bytes (deprecated); N >= 8 hold a DER UTF8String.
-spec fulcio_ext(cert(), pos_integer()) -> {ok, binary()} | undefined | {error, {cert, term()}}.
fulcio_ext(C, N) ->
    case ext_value(C, ?OID_FULCIO(N), undefined) of
        undefined ->
            undefined;
        V when is_binary(V), N =< 6 ->
            {ok, V};
        V when is_binary(V) ->
            case sigstore_der:utf8_string(V) of
                {ok, S} -> {ok, S};
                {error, _} -> {error, {cert, {bad_fulcio_ext, N}}}
            end
    end.

%% @doc The OIDC issuer: `.1.8' preferred, `.1.1' fallback (client spec).
-spec issuer(cert()) -> {ok, binary()} | {error, {cert, term()}}.
issuer(C) ->
    case fulcio_ext(C, 8) of
        {ok, _} = Ok ->
            Ok;
        {error, _} = E ->
            E;
        undefined ->
            case fulcio_ext(C, 1) of
                {ok, _} = Ok -> Ok;
                undefined -> {error, {cert, no_issuer_extension}}
            end
    end.

%% @doc Build and validate a path from `Leaf' to a trust anchor at time `T'.
%%
%% `Anchors' is a list of `{AnchorDer, IntermediateDers}' (the trust-root
%% CA entries valid at T, last cert = anchor). `Extra' are untrusted
%% intermediates from the bundle (v0.1/v0.2 chains); they may help build
%% the path but are never anchors. Returns the path leaf-first, anchor last.
-spec validate_chain(cert(), [binary()], [{binary(), [binary()]}], sigstore_time:t()) ->
    {ok, [cert(), ...]} | {error, {chain, term()}}.
validate_chain(Leaf, Extra, Anchors, T) ->
    Results = [build(Leaf, AnchorDer, Inter ++ Extra, T) || {AnchorDer, Inter} <- Anchors],
    case [P || {ok, P} <- Results] of
        [Path | _] ->
            {ok, Path};
        [] ->
            case [E || {error, E} <- Results] of
                [] -> {error, {chain, no_trusted_ca_at_time}};
                [First | _] -> {error, {chain, First}}
            end
    end.

build(Leaf, AnchorDer, Pool, T) ->
    case decode(AnchorDer) of
        {ok, Anchor} ->
            Candidates = [C || {ok, C} <- [decode(D) || D <- lists:usort(Pool)]],
            walk(Leaf, Anchor, Candidates, T, [Leaf], 0);
        {error, _} ->
            {error, bad_anchor}
    end.

walk(_Cur, _Anchor, _Pool, _T, _Acc, Depth) when Depth > ?MAX_DEPTH ->
    {error, path_too_long};
walk(Cur, Anchor, Pool, T, Acc, Depth) ->
    case in_validity(Cur, T) of
        false ->
            {error, {expired_or_not_yet_valid, Depth}};
        true ->
            case signed_by(Cur, Anchor) of
                true ->
                    case in_validity(Anchor, T) andalso ca_ok(Anchor, Depth) of
                        true -> {ok, lists:reverse([Anchor | Acc])};
                        false -> {error, anchor_invalid_at_time}
                    end;
                false ->
                    Next = [
                        I
                     || I <- Pool,
                        I =/= Cur,
                        not lists:member(I, Acc),
                        signed_by(Cur, I),
                        ca_ok(I, Depth)
                    ],
                    first_ok(
                        [fun() -> walk(I, Anchor, Pool, T, [I | Acc], Depth + 1) end || I <- Next],
                        no_issuer
                    )
            end
    end.

first_ok([], Why) ->
    {error, Why};
first_ok([F | Rest], _Why) ->
    case F() of
        {ok, _} = Ok -> Ok;
        {error, Why} -> first_ok(Rest, Why)
    end.

in_validity(C, T) ->
    {NB, NA} = validity(C),
    T >= NB andalso T =< NA.

%% Issuer must be a CA allowed to sign certs, with path length room for the
%% certs below it (Depth = number of intermediates already below it).
ca_ok(C, Depth) ->
    case ext_value(C, ?'id-ce-basicConstraints', undefined) of
        #'BasicConstraints'{cA = true, pathLenConstraint = Len} ->
            KU = ext_value(C, ?'id-ce-keyUsage', undefined),
            (KU =:= undefined orelse lists:member(keyCertSign, KU)) andalso
                (Len =:= asn1_NOVALUE orelse Depth =< Len);
        _ ->
            false
    end.

signed_by(#{der := Der, otp := Child}, #{otp := Parent} = P) ->
    public_key:pkix_is_issuer(Child, Parent) andalso
        case public_key(P) of
            {ok, #{public_key := Key}} ->
                try
                    public_key:pkix_verify(Der, Key)
                catch
                    _:_ -> false
                end;
            {error, _} ->
                false
        end.

ext_value(#{otp := C}, Oid, Default) ->
    Exts =
        case (C#'OTPCertificate'.tbsCertificate)#'OTPTBSCertificate'.extensions of
            asn1_NOVALUE -> [];
            L -> L
        end,
    case lists:keyfind(Oid, #'Extension'.extnID, Exts) of
        #'Extension'{extnValue = V} -> V;
        false -> Default
    end.

to_bin(V) when is_list(V) -> unicode:characters_to_binary(V);
to_bin(V) when is_binary(V) -> V.
