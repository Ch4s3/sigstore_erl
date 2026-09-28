%% @doc The verification procedure (SPEC.md §6). Skeleton.
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
verify(_Artifact, #{material := Material}, _Root, Policy, _Opts) ->
    case check_material_policy(Material, Policy) of
        ok -> {error, {verify, not_implemented}};
        {error, _} = E -> E
    end.

%% Keyless policies need a certificate; managed-key policies need a
%% public-key bundle (conformance managed-key-no-key_fail and friends).
check_material_policy({public_key, _}, {key, _}) -> ok;
check_material_policy({public_key, _}, _) -> {error, {policy, bundle_has_no_certificate}};
check_material_policy(_, {key, _}) -> {error, {policy, bundle_has_certificate_not_key}};
check_material_policy(_, _) -> ok.
