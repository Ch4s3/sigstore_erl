%% @doc Public keys: protobuf `PublicKeyDetails' names, SPKI/PEM decoding,
%% RFC 6962 key IDs. Single place mapping Sigstore's algorithm registry to
%% OTP `public_key' terms (SPEC.md §5.3).
-module(sigstore_keys).

-include_lib("public_key/include/public_key.hrl").

-export([from_spki_der/1, from_pem/1, key_id/1, details/1, alg/1, key_matches_details/2]).

-export_type([key/0, alg/0, details/0]).

-type alg() ::
    ecdsa_p256_sha256
    | ecdsa_p384_sha384
    | ecdsa_p521_sha512
    | ed25519
    | {rsa, Bits :: pos_integer()}.

-type details() :: binary().
%% Opaque-ish: the OTP public key term plus its algorithm and SPKI bytes.
-type key() :: #{alg := alg(), public_key := term(), spki := binary()}.

-define(P256, {1, 2, 840, 10045, 3, 1, 7}).
-define(P384, {1, 3, 132, 0, 34}).
-define(P521, {1, 3, 132, 0, 35}).
-define(ED25519, {1, 3, 101, 112}).

%% @doc Decode a DER SubjectPublicKeyInfo. Uses `pem_entry_decode', whose
%% output shape is stable across OTP 25..29 (raw `der_decode' is not).
-spec from_spki_der(binary()) -> {ok, key()} | {error, {key, term()}}.
from_spki_der(Der) when is_binary(Der) ->
    try public_key:pem_entry_decode({'SubjectPublicKeyInfo', Der, not_encrypted}) of
        Key ->
            case classify(Key) of
                {ok, Alg} -> {ok, #{alg => Alg, public_key => Key, spki => Der}};
                {error, _} = E -> E
            end
    catch
        _:_ -> {error, {key, invalid_spki}}
    end.

%% @doc Decode the first PUBLIC KEY block of a PEM file (managed keys).
-spec from_pem(binary()) -> {ok, key()} | {error, {key, term()}}.
from_pem(Pem) when is_binary(Pem) ->
    try public_key:pem_decode(Pem) of
        [{'SubjectPublicKeyInfo', Der, not_encrypted} | _] -> from_spki_der(Der);
        [] -> {error, {key, no_pem_entries}};
        [{Type, _, _} | _] -> {error, {key, {unsupported_pem, Type}}}
    catch
        _:_ -> {error, {key, invalid_pem}}
    end.

%% @doc RFC 6962 log/key ID: SHA-256 over the DER SPKI.
-spec key_id(key() | binary()) -> binary().
key_id(#{spki := Der}) -> crypto:hash(sha256, Der);
key_id(Der) when is_binary(Der) -> crypto:hash(sha256, Der).

-spec alg(key()) -> alg().
alg(#{alg := A}) -> A.

%% @doc Map a protobuf `PublicKeyDetails' name to an algorithm.
-spec details(details()) -> {ok, alg()} | {error, {key, {unsupported_details, binary()}}}.
details(<<"PKIX_ECDSA_P256_SHA_256">>) -> {ok, ecdsa_p256_sha256};
details(<<"PKIX_ECDSA_P384_SHA_384">>) -> {ok, ecdsa_p384_sha384};
details(<<"PKIX_ECDSA_P521_SHA_512">>) -> {ok, ecdsa_p521_sha512};
details(<<"PKIX_ED25519">>) -> {ok, ed25519};
details(<<"PKIX_RSA_PKCS1V15_2048_SHA256">>) -> {ok, {rsa, 2048}};
details(<<"PKIX_RSA_PKCS1V15_3072_SHA256">>) -> {ok, {rsa, 3072}};
details(<<"PKIX_RSA_PKCS1V15_4096_SHA256">>) -> {ok, {rsa, 4096}};
details(Other) -> {error, {key, {unsupported_details, Other}}}.

%% @doc Does a decoded key agree with a declared `keyDetails'?
-spec key_matches_details(key(), details()) -> boolean().
key_matches_details(Key, Details) ->
    case details(Details) of
        {ok, A} -> A =:= alg(Key);
        {error, _} -> false
    end.

classify({#'ECPoint'{}, {namedCurve, ?P256}}) -> {ok, ecdsa_p256_sha256};
classify({#'ECPoint'{}, {namedCurve, ?P384}}) -> {ok, ecdsa_p384_sha384};
classify({#'ECPoint'{}, {namedCurve, ?P521}}) -> {ok, ecdsa_p521_sha512};
classify({#'ECPoint'{}, {namedCurve, ?ED25519}}) -> {ok, ed25519};
classify(#'RSAPublicKey'{modulus = N}) -> {ok, {rsa, bit_size(binary:encode_unsigned(N))}};
classify({#'ECPoint'{}, {namedCurve, Curve}}) -> {error, {key, {unsupported_curve, Curve}}};
classify(Other) -> {error, {key, {unsupported_key, element(1, Other)}}}.
