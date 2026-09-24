%% @doc Public façade for sigstore_erl. See SPEC.md §4.
%%
%% All functions return `{ok, Result} | {error, Reason}' with a tagged-tuple
%% `Reason'. Nothing here raises across the API boundary.
-module(sigstore).

-export([verify/3, sign/1, trusted_root/1, signing_config/1]).

-export_type([artifact/0, trust_opts/0, verify_opts/0, sign_opts/0, verified/0, error/0]).

-type artifact() ::
    {file, file:name_all()}
    | {binary, binary()}
    | {digest, sha256, <<_:256>>}.

-type trust_opts() :: #{
    instance => production | staging,
    trusted_root => sigstore_trust:trusted_root() | file:name_all() | binary(),
    signing_config => sigstore_trust:signing_config() | file:name_all() | binary(),
    tuf => embedded | refresh | {cache_dir, file:name_all()}
}.

-type verify_opts() :: #{
    trusted_root := sigstore_trust:trusted_root(),
    policy := sigstore_policy:t(),
    now => calendar:datetime()
}.

-type sign_opts() :: #{
    identity_token := binary(),
    signing_config := sigstore_trust:signing_config(),
    trusted_root := sigstore_trust:trusted_root(),
    payload := artifact() | {dsse, PayloadType :: binary(), Payload :: binary()},
    key => ephemeral_p256,
    tsa => required | optional | none,
    self_verify => boolean()
}.

-type verified() :: #{
    certificate := public_key:der_encoded() | undefined,
    identity := binary() | undefined,
    issuer := binary() | undefined,
    signed_times := [{tsa | tlog, calendar:datetime()}],
    statement := map() | undefined
}.

-type error() :: {error, {Stage :: atom(), Reason :: term()}}.

%% @doc Verify `Bundle' (JSON binary or parsed map) over `Artifact' offline.
-spec verify(artifact(), binary() | map(), verify_opts()) -> {ok, verified()} | error().
verify(Artifact, Bundle, #{trusted_root := Root, policy := Policy} = Opts) ->
    sigstore_verify:verify(Artifact, Bundle, Root, Policy, Opts).

%% @doc Keyless signing: identity token in, v0.3 bundle (map) out.
-spec sign(sign_opts()) -> {ok, map()} | error().
sign(Opts) ->
    sigstore_sign:sign(Opts).

%% @doc Load a trusted root: explicit file/binary/map, or the embedded snapshot.
-spec trusted_root(trust_opts()) -> {ok, sigstore_trust:trusted_root()} | error().
trusted_root(Opts) ->
    sigstore_trust:load_trusted_root(Opts).

%% @doc Load a signing config: explicit file/binary/map, or the embedded snapshot.
-spec signing_config(trust_opts()) -> {ok, sigstore_trust:signing_config()} | error().
signing_config(Opts) ->
    sigstore_trust:load_signing_config(Opts).
