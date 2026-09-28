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
verify(_Artifact, Bundle, _Root, _Policy, _Opts) when is_binary(Bundle) ->
    Config = maps:get(config, _Opts, sigstore:default_config()),
    case sigstore_bundle:from_json(Config, Bundle) of
        {ok, Parsed} -> verify(_Artifact, Parsed, _Root, _Policy, _Opts);
        {error, _} = E -> E
    end;
verify(_Artifact, _Bundle, _Root, _Policy, _Opts) ->
    {error, {verify, not_implemented}}.
