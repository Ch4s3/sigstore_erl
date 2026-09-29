-module(sigstore_signature_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0]).
-export([
    dsse_pae_vector/1,
    intoto_subjects/1,
    digest_inputs_agree/1,
    ed25519_needs_whole_message/1,
    sct_list_parse/1
]).

all() ->
    [
        dsse_pae_vector,
        intoto_subjects,
        digest_inputs_agree,
        ed25519_needs_whole_message,
        sct_list_parse
    ].

%% Test vector from the DSSE v1 protocol spec.
dsse_pae_vector(_) ->
    ?assertEqual(
        <<"DSSEv1 29 http://example.com/HelloWorld 11 hello world">>,
        sigstore_dsse:pae(<<"http://example.com/HelloWorld">>, <<"hello world">>)
    ).

intoto_subjects(_) ->
    D = crypto:hash(sha256, <<"a">>),
    Stmt = iolist_to_binary([
        <<"{\"_type\":\"https://in-toto.io/Statement/v1\",\"subject\":[{\"name\":\"a\",\"digest\":{\"sha256\":\"">>,
        string:uppercase(sigstore_b64:hex_encode(D)),
        <<"\"}}],\"predicateType\":\"x\",\"predicate\":{}}">>
    ]),
    {ok, S} = sigstore_intoto:parse(sigstore_test_json:config(), Stmt),
    ?assert(sigstore_intoto:subject_matches(S, D)),
    ?assertNot(sigstore_intoto:subject_matches(S, crypto:hash(sha256, <<"b">>))),
    ?assertMatch(
        {error, {intoto, {unknown_statement_type, _}}},
        sigstore_intoto:parse(sigstore_test_json:config(), <<"{\"_type\":\"x\",\"subject\":[{}]}">>)
    ),
    ?assertMatch(
        {error, {intoto, not_a_statement}},
        sigstore_intoto:parse(sigstore_test_json:config(), <<"{\"_type\":\"x\"}">>)
    ).

%% File, binary and pre-hashed inputs must all verify the same bundle.
digest_inputs_agree(_) ->
    Root0 = sigstore_test_util:root(),
    Art = filename:join(Root0, "test/vectors/bundle-verify/a.txt"),
    {ok, Bytes} = file:read_file(Art),
    Bundle = sigstore_test_util:read_vector("bundle-verify/happy-path-v0.3/bundle.sigstore.json"),
    {ok, Root} = sigstore:trusted_root(#{config => sigstore_test_json:config()}),
    Opts = #{
        config => sigstore_test_json:config(),
        trusted_root => Root,
        policy => sigstore_policy:identity(
            <<"https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main">>,
            <<"https://token.actions.githubusercontent.com">>
        )
    },
    Expected = {error, {verify, {incomplete, [tlog]}}},
    ?assertEqual(Expected, sigstore:verify({file, Art}, Bundle, Opts)),
    ?assertEqual(Expected, sigstore:verify({binary, Bytes}, Bundle, Opts)),
    ?assertEqual(
        Expected, sigstore:verify({digest, sha256, crypto:hash(sha256, Bytes)}, Bundle, Opts)
    ),
    ?assertEqual(
        {error, {signature, message_digest_mismatch}},
        sigstore:verify({binary, <<Bytes/binary, "x">>}, Bundle, Opts)
    ),
    ?assertMatch(
        {error, {artifact, {read, _, enoent}}},
        sigstore:verify({file, "/nonexistent"}, Bundle, Opts)
    ).

%% Managed-key bundles signed with freshly generated keys: the verifier
%% must pick the hash by key algorithm (Ed25519 signs the whole message,
%% P-384 needs SHA-384, so a SHA-256 prehash input cannot work for either).
ed25519_needs_whole_message(_) ->
    Msg = <<"hello sigstore">>,
    [
        begin
            Priv = public_key:generate_key({namedCurve, Curve}),
            Pub = {#'ECPoint'{point = Priv#'ECPrivateKey'.publicKey}, {namedCurve, CurveOid}},
            Key = #{alg => Alg, public_key => Pub, spki => <<>>},
            Sig = public_key:sign(Msg, SignHash, Priv),
            Check = fun(Artifact, S) -> managed(Key, S, Artifact) end,
            ?assertEqual(
                {Alg, {error, {verify, {incomplete, [tlog]}}}}, {Alg, Check({binary, Msg}, Sig)}
            ),
            ?assertEqual(
                {Alg, {error, {signature, invalid}}},
                {Alg, Check({binary, <<Msg/binary, "!">>}, Sig)}
            ),
            ?assertMatch(
                {Alg, {error, {artifact, _}}},
                {Alg, Check({digest, sha256, crypto:hash(sha256, Msg)}, Sig)}
            )
        end
     || {Alg, Curve, CurveOid, SignHash} <- [
            {ed25519, ed25519, ?'id-Ed25519', none},
            {ecdsa_p384_sha384, secp384r1, ?'secp384r1', sha384}
        ]
    ].

managed(Key, Sig, Artifact) ->
    Bundle = #{
        media_type => <<"application/vnd.dev.sigstore.bundle.v0.3+json">>,
        version => v0_3,
        material => {public_key, <<>>},
        tlog_entries => [],
        rfc3161_timestamps => [],
        content => {message_signature, #{signature => Sig, message_digest => undefined}}
    },
    sigstore:verify(Artifact, Bundle, #{
        config => sigstore_test_json:config(),
        trusted_root => #{},
        policy => sigstore_policy:key(Key)
    }).

sct_list_parse(_) ->
    ?assertMatch({error, {sct, bad_list}}, sigstore_sct:parse_list(<<0, 5, 1>>)),
    Sct = <<0, 0:256, 1:64, 0:16, 4, 3, 2:16, 1, 2>>,
    List = <<(byte_size(Sct) + 2):16, (byte_size(Sct)):16, Sct/binary>>,
    ?assertMatch(
        {ok, [#{timestamp_ms := 1, hash_alg := 4, signature := <<1, 2>>}]},
        sigstore_sct:parse_list(List)
    ),
    ?assertMatch({ok, [_]}, sigstore_sct:parse_list(<<4, (byte_size(List)), List/binary>>)),
    ?assertMatch(
        {error, {sct, {unsupported_version, 1}}},
        sigstore_sct:parse_list(<<
            (byte_size(Sct) + 2):16,
            (byte_size(Sct)):16,
            1,
            (binary:part(Sct, 1, byte_size(Sct) - 1))/binary
        >>)
    ).
