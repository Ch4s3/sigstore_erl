-module(sigstore_conformance_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([
    parses_sign_bundle/1,
    parses_verify_identity/1,
    parses_verify_key/1,
    digest_vs_path/1,
    rejects_conflicting_policy/1
]).

all() ->
    [
        parses_sign_bundle,
        parses_verify_identity,
        parses_verify_key,
        digest_vs_path,
        rejects_conflicting_policy
    ].

%% Exact order emitted by sigstore-conformance test/client.py.
parses_sign_bundle(_) ->
    Args = [
        "sign-bundle",
        "--staging",
        "--in-toto",
        "--identity-token",
        "tok",
        "--bundle",
        "out.json",
        "--trusted-root",
        "tr.json",
        "--signing-config",
        "sc.json",
        "statement.json"
    ],
    ?assertEqual(
        {ok,
            {sign_bundle, #{
                staging => true,
                in_toto => true,
                identity_token => <<"tok">>,
                bundle => "out.json",
                trusted_root => "tr.json",
                signing_config => "sc.json",
                file => "statement.json"
            }}},
        sigstore_conformance:parse_args(Args)
    ).

parses_verify_identity(_) ->
    Args = [
        "verify-bundle",
        "--bundle",
        "b.json",
        "--certificate-identity",
        "me@x",
        "--certificate-oidc-issuer",
        "https://iss",
        "--trusted-root",
        "tr.json",
        "a.txt"
    ],
    ?assertEqual(
        {ok,
            {verify_bundle, #{
                staging => false,
                bundle => "b.json",
                policy => {identity, <<"me@x">>, <<"https://iss">>},
                trusted_root => "tr.json",
                input => {file, "a.txt"}
            }}},
        sigstore_conformance:parse_args(Args)
    ).

parses_verify_key(_) ->
    Args = ["verify-bundle", "--staging", "--bundle", "b.json", "--key", "key.pub", "a.txt"],
    ?assertMatch(
        {ok, {verify_bundle, #{staging := true, policy := {key, "key.pub"}}}},
        sigstore_conformance:parse_args(Args)
    ).

digest_vs_path(_) ->
    Hex = binary_to_list(binary:encode_hex(crypto:hash(sha256, <<"a">>))),
    {ok, {verify_bundle, #{input := {digest, sha256, D}}}} =
        sigstore_conformance:parse_args([
            "verify-bundle", "--bundle", "b", "--key", "k", "sha256:" ++ Hex
        ]),
    ?assertEqual(crypto:hash(sha256, <<"a">>), D),
    {ok, {verify_bundle, #{input := {file, "sha256:short"}}}} =
        sigstore_conformance:parse_args([
            "verify-bundle", "--bundle", "b", "--key", "k", "sha256:short"
        ]).

rejects_conflicting_policy(_) ->
    ?assertMatch(
        {error, {conflicting_policy, _}},
        sigstore_conformance:parse_args([
            "verify-bundle",
            "--bundle",
            "b",
            "--key",
            "k",
            "--certificate-identity",
            "i",
            "--certificate-oidc-issuer",
            "u",
            "a"
        ])
    ).
