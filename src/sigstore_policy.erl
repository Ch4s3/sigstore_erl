%% @doc Verification policies (SPEC.md §6.4): who must have signed.
-module(sigstore_policy).

-export([identity/2, key/1, extension/2, all_of/1, any_of/1, check/2]).

-export_type([t/0]).

-type t() ::
    {identity, Identity :: binary(), Issuer :: binary()}
    | {key, sigstore_keys:key()}
    | {extension, FulcioOidArc :: pos_integer(), Expected :: binary()}
    | {all_of, [t()]}
    | {any_of, [t()]}.

%% @doc The certificate's SAN must equal `Identity' and its OIDC issuer
%% extension must equal `Issuer'. Both are exact comparisons.
-spec identity(binary(), binary()) -> t().
identity(Identity, Issuer) when is_binary(Identity), is_binary(Issuer) ->
    {identity, Identity, Issuer}.

%% @doc Managed-key verification: no certificate, signature checked with `Key'.
-spec key(sigstore_keys:key()) -> t().
key(Key) -> {key, Key}.

%% @doc Fulcio extension `1.3.6.1.4.1.57264.1.N' must equal `Expected',
%% e.g. `extension(12, <<"https://github.com/org/repo">>)' for the source
%% repository URI.
-spec extension(pos_integer(), binary()) -> t().
extension(N, Expected) when is_integer(N), N > 0, is_binary(Expected) -> {extension, N, Expected}.

-spec all_of([t(), ...]) -> t().
all_of([_ | _] = Ps) -> {all_of, Ps}.

-spec any_of([t(), ...]) -> t().
any_of([_ | _] = Ps) -> {any_of, Ps}.

%% @doc Evaluate a certificate policy. `{key, _}' is not a certificate
%% policy and is handled by the verifier before this is called.
-spec check(t(), sigstore_x509:cert()) -> ok | {error, {policy, term()}}.
check({identity, Want, WantIss}, Cert) ->
    case {sigstore_x509:san(Cert), sigstore_x509:issuer(Cert)} of
        {{ok, {_, Want}}, {ok, WantIss}} -> ok;
        {{ok, {_, Got}}, {ok, WantIss}} -> {error, {policy, {identity_mismatch, Want, Got}}};
        {{ok, _}, {ok, GotIss}} -> {error, {policy, {issuer_mismatch, WantIss, GotIss}}};
        {{error, E}, _} -> {error, {policy, E}};
        {_, {error, E}} -> {error, {policy, E}}
    end;
check({extension, N, Want}, Cert) ->
    case sigstore_x509:fulcio_ext(Cert, N) of
        {ok, Want} -> ok;
        {ok, Got} -> {error, {policy, {extension_mismatch, N, Want, Got}}};
        undefined -> {error, {policy, {extension_missing, N}}};
        {error, E} -> {error, {policy, E}}
    end;
check({all_of, Ps}, Cert) ->
    case [E || P <- Ps, {error, E} <- [check(P, Cert)]] of
        [] -> ok;
        [First | _] -> {error, First}
    end;
check({any_of, Ps}, Cert) ->
    case lists:any(fun(P) -> check(P, Cert) =:= ok end, Ps) of
        true -> ok;
        false -> {error, {policy, none_matched}}
    end;
check({key, _}, _Cert) ->
    {error, {policy, key_policy_on_certificate}}.
