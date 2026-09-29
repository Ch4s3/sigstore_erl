%% @doc Transparency-log entry verification (SPEC.md §6.5): log selection,
%% checkpoint + inclusion proof, SET, and cross-checking the logged body
%% against the bundle (anti CVE-2022-36056: the log must describe *this*
%% signature, key and artifact).
-module(sigstore_tlog).

-export([verify_entry/2]).

-type ctx() :: #{
    root := sigstore_trust:trusted_root(),
    key := sigstore_keys:key(),
    leaf := sigstore_x509:cert() | undefined,
    content := sigstore_bundle:content(),
    artifact := sigstore:artifact(),
    config := sigstore:config(),
    version := sigstore_bundle:version()
}.

%% @doc Returns the verified integrated time (Rekor v1 with a valid SET),
%% or `undefined' when the entry provides no signed time.
-spec verify_entry(sigstore_bundle:tlog_entry(), ctx()) ->
    {ok, sigstore_time:t() | undefined} | {error, {tlog, term()}}.
verify_entry(#{kind_version := {<<"intoto">>, _}}, _Ctx) ->
    %% Deprecated Rekor v1 type; not verified (SPEC Q7, as sigstore-python).
    {error, {tlog, {unsupported_entry, intoto}}};
verify_entry(Entry, #{root := Root} = Ctx) ->
    #{log_id := LogId, integrated_time := IT, inclusion_promise := SET, kind_version := {_, KV}} =
        Entry,
    %% Rekor v1 key validity is checked at the (claimed, then SET-verified)
    %% integrated time. v2 entries only have TSA time, checked in M4.
    Logs =
        case {SET, KV} of
            {undefined, _} -> sigstore_trust:tlogs_matching(Root, LogId);
            {_, <<"0.0.2">>} -> sigstore_trust:tlogs_matching(Root, LogId);
            _ -> sigstore_trust:tlogs_for(Root, LogId, sigstore_time:from_unix_seconds(IT))
        end,
    case [L || #{key := #{alg := _}} = L <- Logs] of
        [] -> {error, {tlog, unknown_log}};
        Usable -> first_ok([fun() -> with_log(Entry, L, Ctx) end || L <- Usable])
    end.

first_ok([F]) ->
    F();
first_ok([F | Rest]) ->
    case F() of
        {ok, _} = Ok -> Ok;
        {error, _} -> first_ok(Rest)
    end.

with_log(Entry, #{key := Key}, Ctx) ->
    bind(proof(Entry, Key, Ctx), fun(_) ->
        bind(set(Entry, Key), fun(Time) ->
            bind(body(Entry, Ctx), fun(_) -> {ok, Time} end)
        end)
    end).

%%% Checkpoint + inclusion proof.

proof(#{inclusion_proof := undefined}, _Key, #{version := v0_1}) ->
    {ok, skipped};
proof(#{inclusion_proof := #{checkpoint := undefined}}, _Key, #{version := v0_1}) ->
    %% v0.1 may carry a checkpoint-less proof: ignore it (client spec).
    {ok, skipped};
proof(#{inclusion_proof := P, canonicalized_body := Body} = Entry, Key, _Ctx) ->
    #{
        checkpoint := Envelope,
        root_hash := RootHash,
        tree_size := Size,
        hashes := Hashes,
        log_index := Index
    } = P,
    bind(wrap(sigstore_checkpoint:parse(Envelope)), fun(CP) ->
        bind(wrap(sigstore_checkpoint:verify(CP, Key)), fun(_) ->
            case CP of
                #{size := Size, root_hash := RootHash} ->
                    case v2_index_consistent(Entry) of
                        true ->
                            wrap(
                                sigstore_merkle:verify_inclusion(
                                    Index, Size, sigstore_merkle:leaf_hash(Body), Hashes, RootHash
                                )
                            );
                        false ->
                            {error, {tlog, inconsistent_log_index}}
                    end;
                #{} ->
                    {error, {tlog, checkpoint_does_not_match_proof}}
            end
        end)
    end).

%% Rekor v2 has a single per-shard index: both copies must agree.
v2_index_consistent(#{
    kind_version := {_, <<"0.0.2">>}, log_index := I, inclusion_proof := #{log_index := PI}
}) ->
    I =:= PI;
v2_index_consistent(_) ->
    true.

%%% Signed entry timestamp (Rekor v1).

set(#{inclusion_promise := undefined}, _Key) ->
    {ok, undefined};
set(#{inclusion_promise := SET} = E, Key) ->
    #{canonicalized_body := Body, integrated_time := IT, log_id := LogId, log_index := LI} = E,
    {ok, Payload} = sigstore_jcs:encode(#{
        <<"body">> => sigstore_b64:encode(Body),
        <<"integratedTime">> => IT,
        <<"logID">> => sigstore_b64:hex_encode(LogId),
        <<"logIndex">> => LI
    }),
    case verify_sig(Payload, SET, Key) of
        true -> {ok, sigstore_time:from_unix_seconds(IT)};
        false -> {error, {tlog, invalid_set}}
    end.

%%% Body cross-check.

body(#{kind_version := KV, canonicalized_body := Raw}, #{config := Config} = Ctx) ->
    case sigstore_json:decode(Config, Raw) of
        {ok, #{<<"kind">> := K, <<"apiVersion">> := V} = B} when {K, V} =:= KV ->
            body_spec(KV, maps:get(<<"spec">>, B, #{}), Ctx);
        {ok, _} ->
            {error, {tlog, {body, kind_version_mismatch}}};
        {error, R} ->
            {error, {tlog, {body, R}}}
    end.

body_spec(
    {<<"hashedrekord">>, <<"0.0.1">>},
    Spec,
    #{content := {message_signature, #{signature := Sig}}} = Ctx
) ->
    #{artifact := A} = Ctx,
    checks([
        fun() -> eq_b64(get([<<"signature">>, <<"content">>], Spec), Sig, signature) end,
        fun() -> eq_pem(get([<<"signature">>, <<"publicKey">>, <<"content">>], Spec), Ctx) end,
        fun() ->
            Alg = get([<<"data">>, <<"hash">>, <<"algorithm">>], Spec),
            Hex = get([<<"data">>, <<"hash">>, <<"value">>], Spec),
            case v1_hash(Alg) of
                undefined ->
                    {error, {tlog, {body, {unsupported_hash, Alg}}}};
                H ->
                    bind(sigstore_artifact:digest(A, H), fun(D) ->
                        eq(
                            is_binary(Hex) andalso
                                string:lowercase(Hex) =:= sigstore_b64:hex_encode(D),
                            artifact_digest
                        )
                    end)
            end
        end
    ]);
body_spec({<<"dsse">>, <<"0.0.1">>}, Spec, #{content := {dsse_envelope, Env}} = Ctx) ->
    #{payload := Payload, signatures := [#{sig := Sig}]} = Env,
    checks([
        fun() ->
            eq(
                get([<<"payloadHash">>, <<"algorithm">>], Spec) =:= <<"sha256">> andalso
                    get([<<"payloadHash">>, <<"value">>], Spec) =:=
                        sigstore_b64:hex_encode(crypto:hash(sha256, Payload)),
                payload_hash
            )
        end,
        fun() ->
            case get([<<"signatures">>], Spec) of
                [#{<<"signature">> := S, <<"verifier">> := V}] ->
                    bind(eq_b64(S, Sig, signature), fun(_) -> eq_pem(V, Ctx) end);
                _ ->
                    {error, {tlog, {body, signature_count}}}
            end
        end
    ]);
body_spec({<<"hashedrekord">>, <<"0.0.2">>}, Spec0, #{content := Content, key := Key} = Ctx) ->
    Spec = get([<<"hashedRekordV002">>], Spec0),
    {Signed, Sig} =
        case Content of
            {message_signature, #{signature := S}} ->
                {Ctx, S};
            {dsse_envelope, #{payload := P, payload_type := T, signatures := [#{sig := S}]}} ->
                %% Rekor v2 logs DSSE as a hashedrekord over the PAE.
                {Ctx#{artifact => {binary, sigstore_dsse:pae(T, P)}}, S}
        end,
    checks([
        fun() -> eq_b64(get([<<"signature">>, <<"content">>], Spec), Sig, signature) end,
        fun() -> verifier_v2(get([<<"signature">>, <<"verifier">>], Spec), Ctx) end,
        fun() ->
            Details = get([<<"signature">>, <<"verifier">>, <<"keyDetails">>], Spec),
            eq(
                is_binary(Details) andalso sigstore_keys:key_matches_details(Key, Details),
                key_details
            )
        end,
        fun() ->
            case v2_hash(get([<<"data">>, <<"algorithm">>], Spec)) of
                undefined ->
                    {error, {tlog, {body, unsupported_hash}}};
                H ->
                    bind(sigstore_artifact:digest(maps:get(artifact, Signed), H), fun(D) ->
                        eq_b64(get([<<"data">>, <<"digest">>], Spec), D, artifact_digest)
                    end)
            end
        end
    ]);
body_spec(KV, _Spec, _Ctx) ->
    {error, {tlog, {body, {content_does_not_match_entry_kind, KV}}}}.

verifier_v2(#{<<"x509Certificate">> := #{<<"rawBytes">> := B}}, #{leaf := #{der := Der}}) ->
    eq_b64(B, Der, verifier);
verifier_v2(#{<<"publicKey">> := #{<<"rawBytes">> := B}}, #{
    leaf := undefined, key := #{spki := Spki}
}) ->
    eq_b64(B, Spki, verifier);
verifier_v2(_, _) ->
    {error, {tlog, {body, verifier_mismatch}}}.

%% The logged verifier is base64(PEM of cert or public key).
eq_pem(B64, #{leaf := Leaf, key := #{spki := Spki}}) ->
    Want =
        case Leaf of
            #{der := Der} -> {'Certificate', Der};
            undefined -> {'SubjectPublicKeyInfo', Spki}
        end,
    Got =
        case is_binary(B64) andalso sigstore_b64:decode(B64) of
            {ok, Pem} ->
                try public_key:pem_decode(Pem) of
                    [{Type, Der2, not_encrypted}] -> {Type, Der2};
                    _ -> bad
                catch
                    _:_ -> bad
                end;
            _ ->
                bad
        end,
    eq(Got =:= Want, verifier).

v1_hash(<<"sha256">>) -> sha256;
v1_hash(<<"sha384">>) -> sha384;
v1_hash(<<"sha512">>) -> sha512;
v1_hash(_) -> undefined.

v2_hash(<<"SHA2_256">>) -> sha256;
v2_hash(<<"SHA2_384">>) -> sha384;
v2_hash(<<"SHA2_512">>) -> sha512;
v2_hash(_) -> undefined.

eq_b64(B64, Want, What) when is_binary(B64) ->
    eq(sigstore_b64:decode(B64) =:= {ok, Want}, What);
eq_b64(_, _, What) ->
    {error, {tlog, {body, {missing, What}}}}.

eq(true, _What) -> {ok, match};
eq(false, What) -> {error, {tlog, {body, {mismatch, What}}}}.

get([], V) -> V;
get([K | T], M) when is_map(M) -> get(T, maps:get(K, M, undefined));
get(_, _) -> undefined.

checks([]) ->
    {ok, match};
checks([F | T]) ->
    case F() of
        {ok, _} -> checks(T);
        {error, _} = E -> E
    end.

verify_sig(Msg, Sig, #{alg := Alg, public_key := K}) ->
    Hash =
        case Alg of
            ed25519 -> none;
            ecdsa_p384_sha384 -> sha384;
            ecdsa_p521_sha512 -> sha512;
            _ -> sha256
        end,
    try
        public_key:verify(Msg, Hash, Sig, K)
    catch
        _:_ -> false
    end.

wrap({ok, _} = Ok) -> Ok;
wrap(ok) -> {ok, ok};
wrap({error, E}) -> {error, {tlog, E}}.

bind({ok, V}, F) -> F(V);
bind({error, _} = E, _F) -> E.
