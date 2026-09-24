%% @doc TrustedRoot and SigningConfig models (SPEC.md §5.2). Skeleton.
-module(sigstore_trust).

-export([load_trusted_root/1, load_signing_config/1]).

-export_type([trusted_root/0, signing_config/0]).

-type trusted_root() :: #{binary() => term()}.
-type signing_config() :: #{binary() => term()}.

-spec load_trusted_root(sigstore:trust_opts()) -> {ok, trusted_root()} | sigstore:error().
load_trusted_root(_Opts) ->
    {error, {trust, not_implemented}}.

-spec load_signing_config(sigstore:trust_opts()) -> {ok, signing_config()} | sigstore:error().
load_signing_config(_Opts) ->
    {error, {trust, not_implemented}}.
