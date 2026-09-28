%% @doc Verification policies (SPEC.md §6.4). Skeleton.
-module(sigstore_policy).

-export([identity/2, key/1, all_of/1, any_of/1]).

-export_type([t/0]).

-type t() ::
    {identity, Identity :: binary(), Issuer :: binary()}
    | {key, sigstore_keys:key()}
    | {all_of, [t()]}
    | {any_of, [t()]}.

-spec identity(binary(), binary()) -> t().
identity(Identity, Issuer) -> {identity, Identity, Issuer}.

%% @doc Managed-key verification: no certificate, signature checked with `Key'.
-spec key(sigstore_keys:key()) -> t().
key(Key) -> {key, Key}.

-spec all_of([t()]) -> t().
all_of(Ps) -> {all_of, Ps}.

-spec any_of([t()]) -> t().
any_of(Ps) -> {any_of, Ps}.
