%% @doc The signing procedure (SPEC.md §7). Skeleton.
-module(sigstore_sign).

-export([sign/1]).

-spec sign(sigstore:sign_opts()) -> {ok, sigstore_bundle:t()} | sigstore:error().
sign(_Opts) ->
    {error, {sign, not_implemented}}.
