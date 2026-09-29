%% @doc The verification procedure (SPEC.md §6), in client-spec order.
%%
%% Milestone status: transparency-log (M3) and RFC 3161 (M4) checks are not
%% implemented, so the pipeline currently ends with
%% `{error, {verify, {incomplete, Pending}}}' after every implemented step
%% has passed. It never returns `{ok, _}' until nothing is pending. Times
%% used for chain validation are the entries' CLAIMED integrated times until
%% M3 verifies them.
-module(sigstore_verify).

-export([verify/5]).

-spec verify(
    sigstore:artifact(),
    binary() | sigstore_bundle:t(),
    sigstore_trust:trusted_root(),
    sigstore_policy:t(),
    sigstore:verify_opts()
) -> {ok, sigstore:verified()} | sigstore:error().
verify(Artifact, Bundle, Root, Policy, Opts) when is_binary(Bundle) ->
    Config = maps:get(config, Opts, sigstore:default_config()),
    case sigstore_bundle:from_json(Config, Bundle) of
        {ok, Parsed} -> verify(Artifact, Parsed, Root, Policy, Opts);
        {error, _} = E -> E
    end;
verify(Artifact, Bundle, Root, Policy, Opts) ->
    Ctx = #{
        artifact => Artifact,
        bundle => Bundle,
        root => Root,
        policy => Policy,
        config => maps:get(config, Opts, sigstore:default_config()),
        now => maps:get(now, Opts, sigstore_time:now())
    },
    run(
        [
            fun material/1,
            fun signed_times/1,
            fun chain/1,
            fun sct/1,
            fun policy/1,
            fun signature/1,
            fun finish/1
        ],
        Ctx
    ).

run([], Ctx) ->
    {ok, Ctx};
run([Step | Rest], Ctx) ->
    case Step(Ctx) of
        {ok, Ctx2} -> run(Rest, Ctx2);
        {error, _} = E -> E
    end.

%%% Step 0: signing material vs policy.

material(#{bundle := #{material := {public_key, _}}, policy := {key, Key}} = Ctx) ->
    {ok, Ctx#{key => Key, leaf => undefined}};
material(#{bundle := #{material := {public_key, _}}}) ->
    {error, {policy, bundle_has_no_certificate}};
material(#{policy := {key, _}}) ->
    {error, {policy, bundle_has_certificate_not_key}};
material(#{bundle := #{material := Mat}} = Ctx) ->
    [LeafDer | Extra] =
        case Mat of
            {certificate, D} -> [D];
            {x509_certificate_chain, Ds} -> Ds
        end,
    bind(sigstore_x509:decode(LeafDer), fun(Leaf) ->
        bind(sigstore_x509:leaf_profile(Leaf), fun(_) ->
            bind(sigstore_x509:public_key(Leaf), fun(Key) ->
                {ok, Ctx#{leaf => Leaf, extra => Extra, key => Key}}
            end)
        end)
    end).

%%% Step 1: signed times. M2: claimed integrated times of Rekor v1 entries
%%% carrying a SET (verified in M3); TSA times arrive in M4.

signed_times(#{bundle := #{tlog_entries := Es, rfc3161_timestamps := TS}, now := Now} = Ctx) ->
    %% Only Rekor v1 entries carry a SET; v2 integratedTime is always 0 and
    %% MUST be ignored (client spec §4).
    Claimed = [IT || #{integrated_time := IT, inclusion_promise := P} <- Es, P =/= undefined],
    case [T || T <- Claimed, sigstore_time:from_unix_seconds(T) > Now] of
        [_ | _] ->
            {error, {time, integrated_time_in_future}};
        [] ->
            Pending = [tlog] ++ [tsa || TS =/= []],
            {ok, Ctx#{
                times => [sigstore_time:from_unix_seconds(T) || T <- Claimed], pending => Pending
            }}
    end.

%%% Step 2: chain to a trust-root CA at every signed time.

chain(#{leaf := undefined} = Ctx) ->
    {ok, Ctx};
chain(#{times := []} = Ctx) ->
    %% Only TSA times (M4) exist: nothing to validate against yet.
    {ok, Ctx#{path => undefined}};
chain(#{leaf := Leaf, extra := Extra, root := Root, times := Times} = Ctx) ->
    Paths = [
        begin
            Anchors = [anchors(A) || A <- sigstore_trust:cas_at(Root, T)],
            sigstore_x509:validate_chain(Leaf, Extra, Anchors, T)
        end
     || T <- Times
    ],
    case [E || {error, E} <- Paths] of
        [] -> {ok, Ctx#{path => element(2, hd(Paths))}};
        [E | _] -> {error, E}
    end.

anchors(#{cert_chain := Chain}) ->
    {lists:last(Chain), lists:droplast(Chain)}.

%%% Step 3: embedded SCT.

sct(#{leaf := undefined} = Ctx) ->
    {ok, Ctx};
sct(#{path := undefined} = Ctx) ->
    {ok, Ctx};
sct(#{leaf := Leaf, path := Path, root := Root} = Ctx) ->
    ok_ctx(sigstore_sct:verify_embedded(Leaf, Path, Root), Ctx).

%%% Step 4: identity policy.

policy(#{leaf := undefined} = Ctx) -> {ok, Ctx};
policy(#{leaf := Leaf, policy := P} = Ctx) -> ok_ctx(sigstore_policy:check(P, Leaf), Ctx).

%%% Step 7 (run early while 5 and 6 are pending): the signature itself.

signature(#{bundle := #{content := {message_signature, MS}}, key := Key, artifact := A} = Ctx) ->
    #{signature := Sig, message_digest := MD} = MS,
    bind(check_message_digest(MD, A), fun(_) ->
        Hash = hash_for(Key),
        case Hash of
            none ->
                bind(whole_message(A), fun(Msg) ->
                    verified(safe_verify(Msg, none, Sig, Key), Ctx)
                end);
            _ ->
                bind(digest(A, Hash), fun(D) ->
                    verified(safe_verify({digest, D}, Hash, Sig, Key), Ctx)
                end)
        end
    end);
signature(
    #{bundle := #{content := {dsse_envelope, Env}}, key := Key, artifact := A, config := Config} =
        Ctx
) ->
    #{payload := Payload, payload_type := Type, signatures := [#{sig := Sig}]} = Env,
    PAE = sigstore_dsse:pae(Type, Payload),
    case safe_verify(PAE, hash_for(Key), Sig, Key) of
        false ->
            {error, {signature, dsse_invalid}};
        true when Type =/= <<"application/vnd.in-toto+json">> ->
            {error, {signature, {unsupported_payload_type, Type}}};
        true ->
            bind(sigstore_intoto:parse(Config, Payload), fun(Statement) ->
                bind(digest(A, sha256), fun(D) ->
                    case sigstore_intoto:subject_matches(Statement, D) of
                        true -> {ok, Ctx#{statement => Statement}};
                        false -> {error, {signature, artifact_not_in_subjects}}
                    end
                end)
            end)
    end.

verified(true, Ctx) -> {ok, Ctx};
verified(false, _) -> {error, {signature, invalid}}.

%% `messageDigest' must agree with the artifact but is never what we verify.
check_message_digest(undefined, _A) ->
    {ok, skip};
check_message_digest(#{algorithm := Alg, digest := Want}, A) ->
    case hash_name(Alg) of
        undefined ->
            {error, {signature, {unsupported_digest_algorithm, Alg}}};
        H ->
            %% A fun head would shadow Want, not match it: compare explicitly.
            bind(digest(A, H), fun
                (Got) when Got =:= Want -> {ok, match};
                (_) -> {error, {signature, message_digest_mismatch}}
            end)
    end.

hash_name(<<"SHA2_256">>) -> sha256;
hash_name(<<"SHA2_384">>) -> sha384;
hash_name(<<"SHA2_512">>) -> sha512;
hash_name(_) -> undefined.

hash_for(Key) ->
    case sigstore_keys:alg(Key) of
        ecdsa_p256_sha256 -> sha256;
        ecdsa_p384_sha384 -> sha384;
        ecdsa_p521_sha512 -> sha512;
        {rsa, _} -> sha256;
        ed25519 -> none
    end.

safe_verify(Msg, Hash, Sig, #{public_key := K}) ->
    try
        public_key:verify(Msg, Hash, Sig, K)
    catch
        _:_ -> false
    end.

%%% Terminal step: report what is still unimplemented.

finish(#{pending := Pending}) -> {error, {verify, {incomplete, Pending}}}.

%%% Artifact digests.

-spec digest(sigstore:artifact(), sha256 | sha384 | sha512) ->
    {ok, binary()} | {error, {artifact, term()}}.
digest({digest, H, D}, H) -> {ok, D};
digest({digest, Have, _}, Want) -> {error, {artifact, {digest_algorithm, Have, Want}}};
digest({binary, B}, H) -> {ok, crypto:hash(H, B)};
digest({file, Path}, H) -> hash_file(Path, H).

whole_message({binary, B}) ->
    {ok, B};
whole_message({file, P}) ->
    case file:read_file(P) of
        {ok, B} -> {ok, B};
        {error, R} -> {error, {artifact, {read, P, R}}}
    end;
whole_message({digest, _, _}) ->
    {error, {artifact, prehashed_input_needs_prehash_algorithm}}.

hash_file(Path, H) ->
    case file:open(Path, [read, binary, raw]) of
        {ok, F} ->
            try
                hash_loop(F, crypto:hash_init(H))
            after
                ok = file:close(F)
            end;
        {error, R} ->
            {error, {artifact, {read, Path, R}}}
    end.

hash_loop(F, Ctx) ->
    case file:read(F, 1 bsl 16) of
        {ok, Chunk} -> hash_loop(F, crypto:hash_update(Ctx, Chunk));
        eof -> {ok, crypto:hash_final(Ctx)};
        {error, R} -> {error, {artifact, {read, R}}}
    end.

%%% Helpers.

bind(ok, F) -> F(ok);
bind({ok, V}, F) -> F(V);
bind({error, _} = E, _F) -> E.

ok_ctx(ok, Ctx) -> {ok, Ctx};
ok_ctx({error, _} = E, _Ctx) -> E.
