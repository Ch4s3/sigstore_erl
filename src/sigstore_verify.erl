%% @doc The verification procedure (SPEC.md §6), in client-spec order.
%%
%% Milestone status: RFC 3161 (M4) is not implemented, so a bundle carrying
%% timestamps ends with `{error, {verify, {incomplete, [tsa]}}}' after every
%% other step has passed; it never returns `{ok, _}' while anything is
%% pending. Signed times come only from verified SETs until M4.
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
            fun tlog/1,
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

%%% Tlog entries (client spec step 5, run first: a SET must verify before
%%% its integrated time counts as a signed time).

tlog(#{bundle := #{tlog_entries := Es, content := C, version := V}} = Ctx) ->
    TCtx = maps:with([root, key, leaf, artifact, config], Ctx),
    Results = [sigstore_tlog:verify_entry(E, TCtx#{content => C, version => V}) || E <- Es],
    case [E || {error, E} <- Results] of
        [] -> {ok, Ctx#{tlog_times => [T || {ok, T} <- Results, T =/= undefined]}};
        [E | _] -> {error, E}
    end.

%%% Signed times: integrated times from verified SETs; TSA times in M4.

signed_times(#{bundle := #{rfc3161_timestamps := TS}, tlog_times := Times, now := Now} = Ctx) ->
    case [T || T <- Times, T > Now] of
        [_ | _] ->
            {error, {time, integrated_time_in_future}};
        [] ->
            Pending = [tsa || TS =/= []],
            case {Times, Pending} of
                {[], []} -> {error, {time, no_verified_time}};
                _ -> {ok, Ctx#{times => Times, pending => Pending}}
            end
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
        %% ECDSA/RSA do not tie the hash to the key: a P-384 key may sign a
        %% SHA-256 prehash (CPython releases do). Use the declared digest
        %% algorithm, falling back to the key's default.
        Hash = prehash_for(MD, Key),
        case Hash of
            none ->
                bind(sigstore_artifact:whole(A), fun(Msg) ->
                    verified(safe_verify(Msg, none, Sig, Key), Ctx)
                end);
            _ ->
                bind(sigstore_artifact:digest(A, Hash), fun(D) ->
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
                bind(sigstore_artifact:digest(A, sha256), fun(D) ->
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
            bind(sigstore_artifact:digest(A, H), fun
                (Got) when Got =:= Want -> {ok, match};
                (_) -> {error, {signature, message_digest_mismatch}}
            end)
    end.

hash_name(<<"SHA2_256">>) -> sha256;
hash_name(<<"SHA2_384">>) -> sha384;
hash_name(<<"SHA2_512">>) -> sha512;
hash_name(_) -> undefined.

prehash_for(#{algorithm := Alg}, Key) ->
    case {hash_for(Key), hash_name(Alg)} of
        {none, _} -> none;
        {Default, undefined} -> Default;
        {_, H} -> H
    end;
prehash_for(undefined, Key) ->
    hash_for(Key).

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

%%% Terminal step: success only when nothing is pending.

finish(#{pending := [_ | _] = Pending}) ->
    {error, {verify, {incomplete, Pending}}};
finish(#{pending := [], leaf := Leaf, times := Times} = Ctx) ->
    {Identity, Issuer} =
        case Leaf of
            undefined ->
                {undefined, undefined};
            _ ->
                {ok, {_, Id}} = sigstore_x509:san(Leaf),
                {ok, Iss} = sigstore_x509:issuer(Leaf),
                {Id, Iss}
        end,
    {ok, #{
        certificate =>
            case Leaf of
                undefined -> undefined;
                #{der := D} -> D
            end,
        identity => Identity,
        issuer => Issuer,
        signed_times => [{tlog, T} || T <- Times],
        statement => maps:get(statement, Ctx, undefined)
    }}.

%%% Helpers.

bind(ok, F) -> F(ok);
bind({ok, V}, F) -> F(V);
bind({error, _} = E, _F) -> E.

ok_ctx(ok, Ctx) -> {ok, Ctx};
ok_ctx({error, _} = E, _Ctx) -> E.
