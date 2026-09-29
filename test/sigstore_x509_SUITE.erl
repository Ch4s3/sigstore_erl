-module(sigstore_x509_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0]).
-export([
    fulcio_leaf_identity/1,
    fulcio_leaf_profile/1,
    real_chain_at_time/1,
    generated_chain_ok/1,
    expired_intermediate/1,
    non_ca_intermediate/1,
    untrusted_extra_is_not_anchor/1,
    utc_century/1
]).

all() ->
    [
        fulcio_leaf_identity,
        fulcio_leaf_profile,
        real_chain_at_time,
        generated_chain_ok,
        expired_intermediate,
        non_ca_intermediate,
        untrusted_extra_is_not_anchor,
        utc_century
    ].

-define(BEACON,
    <<"https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main">>
).

leaf() ->
    Bin = sigstore_test_util:read_vector("bundle-verify/happy-path-v0.3/bundle.sigstore.json"),
    {ok, #{material := {certificate, Der}, tlog_entries := [#{integrated_time := IT}]}} =
        sigstore_bundle:from_json(sigstore_test_json:config(), Bin),
    {ok, C} = sigstore_x509:decode(Der),
    {C, sigstore_time:from_unix_seconds(IT)}.

fulcio_leaf_identity(_) ->
    {C, _} = leaf(),
    ?assertEqual({ok, {uri, ?BEACON}}, sigstore_x509:san(C)),
    ?assertEqual({ok, <<"https://token.actions.githubusercontent.com">>}, sigstore_x509:issuer(C)),
    %% .1.1 is raw bytes, .1.8+ DER UTF8String: both decode to the same text.
    ?assertEqual(sigstore_x509:fulcio_ext(C, 1), sigstore_x509:fulcio_ext(C, 8)),
    ?assertEqual({ok, <<"github-hosted">>}, sigstore_x509:fulcio_ext(C, 11)),
    ?assertEqual(undefined, sigstore_x509:fulcio_ext(C, 99)),
    ?assertEqual(
        ok,
        sigstore_policy:check(
            sigstore_policy:identity(?BEACON, <<"https://token.actions.githubusercontent.com">>), C
        )
    ),
    ?assertMatch(
        {error, {policy, {identity_mismatch, _, _}}},
        sigstore_policy:check(
            sigstore_policy:identity(<<"x">>, <<"https://token.actions.githubusercontent.com">>), C
        )
    ),
    ?assertMatch(
        {error, {policy, {issuer_mismatch, _, _}}},
        sigstore_policy:check(
            sigstore_policy:identity(?BEACON, <<"https://accounts.google.com">>), C
        )
    ),
    ?assertEqual(
        ok,
        sigstore_policy:check(
            sigstore_policy:all_of([
                sigstore_policy:extension(11, <<"github-hosted">>),
                sigstore_policy:extension(22, <<"public">>)
            ]),
            C
        )
    ),
    ?assertMatch(
        {error, {policy, {extension_mismatch, 22, _, _}}},
        sigstore_policy:check(sigstore_policy:extension(22, <<"private">>), C)
    ),
    ?assertEqual(
        ok,
        sigstore_policy:check(
            sigstore_policy:any_of([
                sigstore_policy:extension(22, <<"private">>),
                sigstore_policy:extension(22, <<"public">>)
            ]),
            C
        )
    ),
    ?assertEqual(
        {error, {policy, none_matched}},
        sigstore_policy:check(
            sigstore_policy:any_of([sigstore_policy:extension(22, <<"private">>)]), C
        )
    ).

fulcio_leaf_profile(_) ->
    {C, _} = leaf(),
    ?assertEqual(ok, sigstore_x509:leaf_profile(C)),
    ?assertNot(sigstore_x509:is_ca(C)),
    {ok, K} = sigstore_x509:public_key(C),
    ?assertEqual(ecdsa_p256_sha256, sigstore_keys:alg(K)).

real_chain_at_time(_) ->
    {C, T} = leaf(),
    {ok, Root} = sigstore:trusted_root(#{config => sigstore_test_json:config()}),
    Anchors = fun(At) ->
        [
            {lists:last(Ch), lists:droplast(Ch)}
         || #{cert_chain := Ch} <- sigstore_trust:cas_at(Root, At)
        ]
    end,
    {ok, Path} = sigstore_x509:validate_chain(C, [], Anchors(T), T),
    ?assertEqual(3, length(Path)),
    {_, NotAfter} = sigstore_x509:validity(C),
    ?assertMatch(
        {error, {chain, {expired_or_not_yet_valid, 0}}},
        sigstore_x509:validate_chain(C, [], Anchors(NotAfter + 1), NotAfter + 1)
    ),
    %% Staging roots must not validate a production leaf.
    {ok, Staging} = sigstore:trusted_root(#{
        config => sigstore_test_json:config(), instance => staging
    }),
    StagingAnchors = [
        {lists:last(Ch), lists:droplast(Ch)}
     || #{cert_chain := Ch} <- sigstore_trust:cas_at(Staging, T)
    ],
    ?assertMatch({error, {chain, _}}, sigstore_x509:validate_chain(C, [], StagingAnchors, T)),
    ?assertEqual(
        {error, {chain, no_trusted_ca_at_time}}, sigstore_x509:validate_chain(C, [], [], T)
    ).

%% Minted chains: root -> intermediate -> leaf, via OTP's pkix_test_data.
mint(IntOpts) ->
    Now = calendar:universal_time(),
    Validity = {shift(Now, -1), shift(Now, 30)},
    Data = public_key:pkix_test_data(#{
        root => [{key, {namedCurve, secp256r1}}, {validity, Validity}],
        %% Overrides first: proplists take the first match.
        intermediates => [IntOpts ++ [{key, {namedCurve, secp256r1}}, {validity, Validity}]],
        peer => [{key, {namedCurve, secp256r1}}, {validity, Validity}]
    }),
    %% Returns a proplist; identify the root by self-signature, not order.
    Leaf = proplists:get_value(cert, Data),
    %% cacerts lists the root twice.
    CAs = lists:usort(proplists:get_value(cacerts, Data)),
    [RootCert] = [C || C <- CAs, public_key:pkix_is_self_signed(C)],
    [Int] = CAs -- [RootCert],
    {ok, L} = sigstore_x509:decode(Leaf),
    {L, Int, RootCert}.

%% pkix_test_data takes dates (it fixes the time at 13:00:00Z).
shift(DT, Days) ->
    {Date, _} = calendar:gregorian_seconds_to_datetime(
        calendar:datetime_to_gregorian_seconds(DT) + Days * 86400
    ),
    Date.

generated_chain_ok(_) ->
    {L, Int, Root} = mint([]),
    Now = sigstore_time:now(),
    ?assertMatch({ok, [_, _, _]}, sigstore_x509:validate_chain(L, [], [{Root, [Int]}], Now)),
    %% The intermediate may also come from the bundle, untrusted.
    ?assertMatch({ok, [_, _, _]}, sigstore_x509:validate_chain(L, [Int], [{Root, []}], Now)),
    ?assertMatch(
        {error, {chain, no_issuer}}, sigstore_x509:validate_chain(L, [], [{Root, []}], Now)
    ).

expired_intermediate(_) ->
    Now = calendar:universal_time(),
    {L, Int, Root} = mint([{validity, {shift(Now, -10), shift(Now, -5)}}]),
    {ok, IntCert} = sigstore_x509:decode(Int),
    ?assert(element(2, sigstore_x509:validity(IntCert)) < sigstore_time:now()),
    ?assertMatch(
        {error, {chain, _}},
        sigstore_x509:validate_chain(L, [], [{Root, [Int]}], sigstore_time:now())
    ).

non_ca_intermediate(_) ->
    NotCA = #'Extension'{
        extnID = ?'id-ce-basicConstraints',
        critical = true,
        extnValue = #'BasicConstraints'{cA = false}
    },
    {L, Int, Root} = mint([{extensions, [NotCA]}]),
    %% Guard against a vacuous pass: the override must have taken effect.
    {ok, IntCert} = sigstore_x509:decode(Int),
    ?assertNot(sigstore_x509:is_ca(IntCert)),
    ?assertMatch(
        {error, {chain, no_issuer}},
        sigstore_x509:validate_chain(L, [], [{Root, [Int]}], sigstore_time:now())
    ).

%% A self-issued cert smuggled in as an "extra" must not act as an anchor.
untrusted_extra_is_not_anchor(_) ->
    {L, Int, Root} = mint([]),
    {_, _, OtherRoot} = mint([]),
    ?assertMatch(
        {error, {chain, _}},
        sigstore_x509:validate_chain(L, [Int, Root], [{OtherRoot, []}], sigstore_time:now())
    ).

utc_century(_) ->
    {C, _} = leaf(),
    {NB, _} = sigstore_x509:validity(C),
    %% "240319172626Z" is 2024, not 1924.
    ?assertEqual(<<"2024-03-19T17:26:26Z">>, sigstore_time:to_rfc3339(NB)).
