%% @doc Sigstore bundle model (SPEC.md §5.1).
%%
%% `from_json/2' decodes a `.sigstore.json' document into an atom-keyed map
%% with all `bytes' fields base64-decoded and all `int64' fields as
%% integers, then applies every structural check that needs no crypto.
%% `to_json/1' is the inverse and emits canonical (RFC 8785) JSON.
%%
%% Keys are snake_case atoms on purpose: a camelCase binary-keyed map that
%% holds already-decoded bytes looks exactly like raw JSON and invites
%% double-decoding bugs.
-module(sigstore_bundle).

-include("sigstore.hrl").

-export([from_json/2, from_map/1, to_json/1, to_map/1, version/1]).

-export_type([t/0, version/0, tlog_entry/0, material/0, content/0]).

-type version() :: v0_1 | v0_2 | v0_3.

-type material() ::
    {certificate, Der :: binary()}
    | {x509_certificate_chain, [Der :: binary(), ...]}
    | {public_key, Hint :: binary()}.

-type content() ::
    {message_signature, #{
        message_digest := undefined | #{algorithm := binary(), digest := binary()},
        signature := binary()
    }}
    | {dsse_envelope, #{
        payload := binary(),
        payload_type := binary(),
        signatures := [#{sig := binary(), keyid := binary()}]
    }}.

-type tlog_entry() :: #{
    log_index := non_neg_integer(),
    log_id := binary(),
    kind_version := {Kind :: binary(), Version :: binary()},
    integrated_time := non_neg_integer(),
    inclusion_promise := undefined | binary(),
    inclusion_proof :=
        undefined
        | #{
            log_index := non_neg_integer(),
            root_hash := binary(),
            tree_size := non_neg_integer(),
            hashes := [binary()],
            checkpoint := undefined | binary()
        },
    canonicalized_body := binary()
}.

-type t() :: #{
    media_type := binary(),
    version := version(),
    material := material(),
    tlog_entries := [tlog_entry()],
    rfc3161_timestamps := [binary()],
    content := content()
}.

%% Entry kinds we can parse. intoto/0.0.2 is deprecated Rekor v1; parsed so
%% its fixtures fail for the right reason, verification support is M3.
-define(KINDS, [
    {<<"hashedrekord">>, <<"0.0.1">>},
    {<<"hashedrekord">>, <<"0.0.2">>},
    {<<"dsse">>, <<"0.0.1">>},
    {<<"intoto">>, <<"0.0.2">>}
]).

-define(MAX_TIMESTAMPS, 32).

%%% ---------------------------------------------------------------- parse

-spec from_json(sigstore:config(), binary()) -> {ok, t()} | {error, {bundle, term()}}.
from_json(Config, Bin) ->
    case sigstore_json:decode(Config, Bin) of
        {ok, Map} when is_map(Map) -> from_map(Map);
        {ok, _} -> {error, {bundle, not_an_object}};
        {error, Reason} -> {error, {bundle, {malformed_json, Reason}}}
    end.

%% @doc Parse an already-decoded JSON object.
-spec from_map(map()) -> {ok, t()} | {error, {bundle, term()}}.
from_map(M) ->
    try
        {ok, parse(M)}
    catch
        throw:{bundle, _} = E -> {error, E}
    end.

parse(M) ->
    MT = req(<<"mediaType">>, M, fun is_binary/1),
    Version =
        case version(MT) of
            {ok, V} -> V;
            {error, E} -> throw(E)
        end,
    VM = req(<<"verificationMaterial">>, M, fun is_map/1),
    Material = material(VM, Version),
    Entries = [tlog_entry(E, Version) || E <- req(<<"tlogEntries">>, VM, fun is_list/1)],
    Timestamps = timestamps(maps:get(<<"timestampVerificationData">>, VM, #{})),
    Content = content(M),
    Bundle = #{
        media_type => MT,
        version => Version,
        material => Material,
        tlog_entries => Entries,
        rfc3161_timestamps => Timestamps,
        content => Content
    },
    check_profile(Bundle),
    Bundle.

-spec version(binary()) -> {ok, version()} | {error, {bundle, {unknown_media_type, binary()}}}.
version(?BUNDLE_V01) -> {ok, v0_1};
version(?BUNDLE_V02) -> {ok, v0_2};
version(?BUNDLE_V03) -> {ok, v0_3};
version(?BUNDLE_V03_LEGACY) -> {ok, v0_3};
version(Other) -> {error, {bundle, {unknown_media_type, Other}}}.

material(VM, Version) ->
    Present = [
        K
     || K <- [<<"certificate">>, <<"x509CertificateChain">>, <<"publicKey">>], maps:is_key(K, VM)
    ],
    case {Present, Version} of
        {[<<"certificate">>], _} ->
            {certificate, bytes(<<"rawBytes">>, req(<<"certificate">>, VM, fun is_map/1))};
        {[<<"x509CertificateChain">>], v0_3} ->
            %% v0.3 producers MUST use `certificate'; verifiers still accept a chain.
            chain(VM);
        {[<<"x509CertificateChain">>], _} ->
            chain(VM);
        {[<<"publicKey">>], _} ->
            PK = req(<<"publicKey">>, VM, fun is_map/1),
            {public_key, maps:get(<<"hint">>, PK, <<>>)};
        {[], _} ->
            throw({bundle, missing_verification_material});
        {Many, _} ->
            throw({bundle, {conflicting_verification_material, Many}})
    end.

chain(VM) ->
    Chain = req(<<"x509CertificateChain">>, VM, fun is_map/1),
    case maps:get(<<"certificates">>, Chain, []) of
        [] ->
            throw({bundle, empty_certificate_chain});
        Certs when is_list(Certs) ->
            Ders = [bytes(<<"rawBytes">>, C) || C <- Certs],
            [_Leaf | Rest] = Ders,
            %% Signers MUST NOT include the root; the conformance suite requires
            %% rejecting it (bundle-with-root-cert_fail), stricter than the spec's
            %% "ignore with a warning" (SPEC D5).
            lists:foreach(
                fun(D) ->
                    case self_signed(D) of
                        true -> throw({bundle, root_certificate_in_chain});
                        false -> ok
                    end
                end,
                Rest
            ),
            {x509_certificate_chain, Ders};
        _ ->
            throw({bundle, {invalid, <<"x509CertificateChain.certificates">>}})
    end.

self_signed(Der) ->
    try
        public_key:pkix_is_self_signed(Der)
    catch
        _:_ -> throw({bundle, {invalid_certificate, der}})
    end.

tlog_entry(E, _Version) when is_map(E) ->
    KV = req(<<"kindVersion">>, E, fun is_map/1),
    Kind = {req(<<"kind">>, KV, fun is_binary/1), req(<<"version">>, KV, fun is_binary/1)},
    lists:member(Kind, ?KINDS) orelse throw({bundle, {unsupported_entry, Kind}}),
    #{
        log_index => non_neg(<<"logIndex">>, E),
        log_id => bytes(<<"keyId">>, req(<<"logId">>, E, fun is_map/1)),
        kind_version => Kind,
        integrated_time => non_neg(<<"integratedTime">>, E, 0),
        inclusion_promise =>
            case maps:get(<<"inclusionPromise">>, E, null) of
                null -> undefined;
                P when is_map(P) -> bytes(<<"signedEntryTimestamp">>, P);
                _ -> throw({bundle, {invalid, <<"inclusionPromise">>}})
            end,
        inclusion_proof =>
            case maps:get(<<"inclusionProof">>, E, null) of
                null -> undefined;
                P when is_map(P) -> inclusion_proof(P);
                _ -> throw({bundle, {invalid, <<"inclusionProof">>}})
            end,
        canonicalized_body => bytes(<<"canonicalizedBody">>, E)
    };
tlog_entry(_, _) ->
    throw({bundle, {invalid, <<"tlogEntries">>}}).

inclusion_proof(P) ->
    #{
        log_index => non_neg(<<"logIndex">>, P),
        root_hash => bytes(<<"rootHash">>, P),
        tree_size => non_neg(<<"treeSize">>, P),
        hashes => [b64(H, <<"hashes">>) || H <- maps:get(<<"hashes">>, P, [])],
        checkpoint =>
            case maps:get(<<"checkpoint">>, P, null) of
                #{<<"envelope">> := Env} when is_binary(Env) -> Env;
                null -> undefined;
                _ -> throw({bundle, {invalid, <<"checkpoint">>}})
            end
    }.

timestamps(TVD) when is_map(TVD) ->
    TS = [bytes(<<"signedTimestamp">>, T) || T <- maps:get(<<"rfc3161Timestamps">>, TVD, [])],
    length(TS) =< ?MAX_TIMESTAMPS orelse throw({bundle, too_many_timestamps}),
    length(lists:usort(TS)) =:= length(TS) orelse throw({bundle, duplicate_timestamps}),
    TS;
timestamps(_) ->
    throw({bundle, {invalid, <<"timestampVerificationData">>}}).

content(M) ->
    case
        {maps:get(<<"messageSignature">>, M, undefined), maps:get(<<"dsseEnvelope">>, M, undefined)}
    of
        {MS, undefined} when is_map(MS) ->
            {message_signature, #{
                message_digest =>
                    case maps:get(<<"messageDigest">>, MS, undefined) of
                        undefined ->
                            undefined;
                        D when is_map(D) ->
                            #{
                                algorithm => req(<<"algorithm">>, D, fun is_binary/1),
                                digest => bytes(<<"digest">>, D)
                            }
                    end,
                signature => bytes(<<"signature">>, MS)
            }};
        {undefined, Env} when is_map(Env) ->
            Sigs = req(<<"signatures">>, Env, fun is_list/1),
            length(Sigs) =:= 1 orelse throw({bundle, {dsse_signature_count, length(Sigs)}}),
            {dsse_envelope, #{
                payload => bytes(<<"payload">>, Env),
                payload_type => req(<<"payloadType">>, Env, fun is_binary/1),
                signatures => [
                    #{sig => bytes(<<"sig">>, S), keyid => maps:get(<<"keyid">>, S, <<>>)}
                 || S <- Sigs
                ]
            }};
        {undefined, undefined} ->
            throw({bundle, missing_content});
        _ ->
            throw({bundle, conflicting_content})
    end.

%% Version-dependent requirements (client spec §4, SPEC §5.1).
check_profile(#{tlog_entries := Entries, version := V, rfc3161_timestamps := TS}) ->
    length(Entries) =:= 1 orelse throw({bundle, {tlog_entry_count, length(Entries)}}),
    lists:foreach(
        fun(E) ->
            #{inclusion_promise := Promise, inclusion_proof := Proof} = E,
            case V of
                v0_1 ->
                    Promise =/= undefined orelse throw({bundle, missing_inclusion_promise});
                _ ->
                    case Proof of
                        #{checkpoint := CP} when CP =/= undefined -> ok;
                        #{} -> throw({bundle, missing_checkpoint});
                        undefined -> throw({bundle, missing_inclusion_proof})
                    end,
                    %% Without a SET the only signed time can come from a TSA.
                    (Promise =/= undefined orelse TS =/= []) orelse
                        throw({bundle, no_signed_time_source})
            end
        end,
        Entries
    ).

%%% ------------------------------------------------------------- helpers

req(K, M, Guard) ->
    case M of
        #{K := V} ->
            case Guard(V) of
                true -> V;
                false -> throw({bundle, {invalid, K}})
            end;
        _ ->
            throw({bundle, {missing, K}})
    end.

bytes(K, M) -> b64(req(K, M, fun is_binary/1), K).

b64(V, K) ->
    case sigstore_b64:decode(V) of
        {ok, B} -> B;
        {error, _} -> throw({bundle, {invalid_base64, K}})
    end.

%% int64 fields arrive as JSON strings (canonical proto3 JSON) or numbers.
non_neg(K, M) -> non_neg(K, M, missing).
non_neg(K, M, Default) ->
    V =
        case {maps:get(K, M, undefined), Default} of
            {undefined, missing} -> throw({bundle, {missing, K}});
            {undefined, D} -> D;
            {X, _} -> X
        end,
    case int64(V) of
        {ok, I} when I >= 0 -> I;
        {ok, _} -> throw({bundle, {negative, K}});
        error -> throw({bundle, {invalid, K}})
    end.

int64(I) when is_integer(I) -> {ok, I};
int64(B) when is_binary(B) ->
    try
        {ok, binary_to_integer(B)}
    catch
        error:badarg -> error
    end;
int64(_) ->
    error.

%%% ----------------------------------------------------------------- emit

%% @doc Canonical JSON for a bundle. int64 as strings, bytes as padded
%% standard base64, unset optional fields omitted.
-spec to_json(t()) -> {ok, binary()} | {error, {jcs, term()}}.
to_json(B) -> sigstore_jcs:encode(to_map(B)).

-spec to_map(t()) -> map().
to_map(#{
    media_type := MT, material := Mat, tlog_entries := Es, rfc3161_timestamps := TS, content := C
}) ->
    VM0 = #{<<"tlogEntries">> => [entry_map(E) || E <- Es]},
    VM1 = maps:merge(VM0, material_map(Mat)),
    VM =
        case TS of
            [] ->
                VM1;
            _ ->
                VM1#{
                    <<"timestampVerificationData">> => #{
                        <<"rfc3161Timestamps">> => [#{<<"signedTimestamp">> => e(T)} || T <- TS]
                    }
                }
        end,
    maps:merge(#{<<"mediaType">> => MT, <<"verificationMaterial">> => VM}, content_map(C)).

material_map({certificate, D}) ->
    #{<<"certificate">> => #{<<"rawBytes">> => e(D)}};
material_map({x509_certificate_chain, Ds}) ->
    #{
        <<"x509CertificateChain">> => #{
            <<"certificates">> => [#{<<"rawBytes">> => e(D)} || D <- Ds]
        }
    };
material_map({public_key, Hint}) ->
    #{<<"publicKey">> => #{<<"hint">> => Hint}}.

entry_map(E) ->
    #{
        log_index := LI,
        log_id := Id,
        kind_version := {K, V},
        integrated_time := IT,
        canonicalized_body := Body
    } = E,
    M0 = #{
        <<"logIndex">> => integer_to_binary(LI),
        <<"logId">> => #{<<"keyId">> => e(Id)},
        <<"kindVersion">> => #{<<"kind">> => K, <<"version">> => V},
        <<"integratedTime">> => integer_to_binary(IT),
        <<"canonicalizedBody">> => e(Body)
    },
    M1 =
        case maps:get(inclusion_promise, E) of
            undefined -> M0;
            SET -> M0#{<<"inclusionPromise">> => #{<<"signedEntryTimestamp">> => e(SET)}}
        end,
    case maps:get(inclusion_proof, E) of
        undefined -> M1;
        P -> M1#{<<"inclusionProof">> => proof_map(P)}
    end.

proof_map(#{log_index := LI, root_hash := R, tree_size := S, hashes := Hs, checkpoint := CP}) ->
    M = #{
        <<"logIndex">> => integer_to_binary(LI),
        <<"rootHash">> => e(R),
        <<"treeSize">> => integer_to_binary(S),
        <<"hashes">> => [e(H) || H <- Hs]
    },
    case CP of
        undefined -> M;
        _ -> M#{<<"checkpoint">> => #{<<"envelope">> => CP}}
    end.

content_map({message_signature, #{message_digest := MD, signature := Sig}}) ->
    MS0 = #{<<"signature">> => e(Sig)},
    MS =
        case MD of
            undefined ->
                MS0;
            #{algorithm := A, digest := D} ->
                MS0#{<<"messageDigest">> => #{<<"algorithm">> => A, <<"digest">> => e(D)}}
        end,
    #{<<"messageSignature">> => MS};
content_map({dsse_envelope, #{payload := P, payload_type := PT, signatures := Sigs}}) ->
    #{
        <<"dsseEnvelope">> => #{
            <<"payload">> => e(P),
            <<"payloadType">> => PT,
            <<"signatures">> => [sig_map(S) || S <- Sigs]
        }
    }.

sig_map(#{sig := S, keyid := <<>>}) -> #{<<"sig">> => e(S)};
sig_map(#{sig := S, keyid := K}) -> #{<<"sig">> => e(S), <<"keyid">> => K}.

e(B) -> sigstore_b64:encode(B).
