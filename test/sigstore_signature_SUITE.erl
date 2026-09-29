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
-export([p384_key_sha256_prehash/1, cpython_release_bundle/1]).

all() ->
    [
        dsse_pae_vector,
        intoto_subjects,
        digest_inputs_agree,
        ed25519_needs_whole_message,
        sct_list_parse,
        p384_key_sha256_prehash,
        cpython_release_bundle
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
    {ok, Verified} = sigstore:verify({file, Art}, Bundle, Opts),
    ?assertMatch(
        #{
            identity := <<"https://github.com/sigstore-conformance/", _/binary>>,
            issuer := <<"https://token.actions.githubusercontent.com">>,
            signed_times := [{tlog, _}],
            certificate := <<16#30, _/binary>>
        },
        Verified
    ),
    ?assertEqual({ok, Verified}, sigstore:verify({binary, Bytes}, Bundle, Opts)),
    ?assertEqual(
        {ok, Verified},
        sigstore:verify({digest, sha256, crypto:hash(sha256, Bytes)}, Bundle, Opts)
    ),
    %% A different artifact is caught by the logged body before the signature.
    ?assertEqual(
        {error, {tlog, {body, {mismatch, artifact_digest}}}},
        sigstore:verify({binary, <<Bytes/binary, "x">>}, Bundle, Opts)
    ),
    ?assertMatch(
        {error, {artifact, {read, _, enoent}}},
        sigstore:verify({file, "/nonexistent"}, Bundle, Opts)
    ).

%% Managed-key bundles signed with freshly generated keys (no tlog entry;
%% a placeholder TSA token keeps the pipeline at `incomplete [tsa]' so the
%% signature step runs): the verifier
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
                {Alg, {error, {verify, {incomplete, [tsa]}}}}, {Alg, Check({binary, Msg}, Sig)}
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
        rfc3161_timestamps => [<<"placeholder">>],
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

%% ECDSA does not bind hash to curve: a P-384 key signing a SHA-256
%% prehash is valid when the bundle declares SHA2_256 (CPython releases).
p384_key_sha256_prehash(_) ->
    Msg = <<"release tarball">>,
    D = crypto:hash(sha256, Msg),
    Priv = public_key:generate_key({namedCurve, secp384r1}),
    Pub = {#'ECPoint'{point = Priv#'ECPrivateKey'.publicKey}, {namedCurve, ?'secp384r1'}},
    Key = #{alg => ecdsa_p384_sha384, public_key => Pub, spki => <<>>},
    Sig = public_key:sign({digest, D}, sha256, Priv),
    Bundle = fun(MD) ->
        #{
            media_type => <<"application/vnd.dev.sigstore.bundle.v0.3+json">>,
            version => v0_3,
            material => {public_key, <<>>},
            tlog_entries => [],
            rfc3161_timestamps => [<<"placeholder">>],
            content => {message_signature, #{signature => Sig, message_digest => MD}}
        }
    end,
    Opts = #{
        config => sigstore_test_json:config(),
        trusted_root => #{},
        policy => sigstore_policy:key(Key)
    },
    Declared = #{algorithm => <<"SHA2_256">>, digest => D},
    ?assertEqual(
        {error, {verify, {incomplete, [tsa]}}},
        sigstore:verify({digest, sha256, D}, Bundle(Declared), Opts)
    ),
    ?assertEqual(
        {error, {verify, {incomplete, [tsa]}}},
        sigstore:verify({binary, Msg}, Bundle(Declared), Opts)
    ),
    %% Without a declared digest the key default (SHA-384) applies.
    ?assertEqual(
        {error, {signature, invalid}}, sigstore:verify({binary, Msg}, Bundle(undefined), Opts)
    ).

%% A real CPython 3.11.6 release bundle (P-384 key, SHA-256 digest,
%% bundle v0.1, Google-issued identity) verifies end to end.
cpython_release_bundle(_) ->
    Bundle = sigstore_test_util:read_vector("cpython/3.11.6.sigstore.json"),
    {ok, #{<<"sha256">> := Hex, <<"identity">> := Id, <<"issuer">> := Iss}} =
        sigstore_json:decode(
            sigstore_test_json:config(),
            sigstore_test_util:read_vector("cpython/3.11.6.expect.json")
        ),
    {ok, Root} = sigstore:trusted_root(#{config => sigstore_test_json:config()}),
    Opts = #{
        config => sigstore_test_json:config(),
        trusted_root => Root,
        policy => sigstore_policy:identity(Id, Iss)
    },
    {ok, D} = sigstore_b64:hex_decode(Hex),
    ?assertMatch(
        {ok, #{identity := Id, issuer := Iss}}, sigstore:verify({digest, sha256, D}, Bundle, Opts)
    ),
    <<B, Rest/binary>> = D,
    ?assertMatch(
        {error, _}, sigstore:verify({digest, sha256, <<(B bxor 1), Rest/binary>>}, Bundle, Opts)
    ).
