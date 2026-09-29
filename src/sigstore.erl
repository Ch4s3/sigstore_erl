%% @doc Public façade for sigstore_erl. See SPEC.md §4.
%%
%% All functions return `{ok, Result} | {error, Reason}' with a tagged-tuple
%% `Reason'. Nothing here raises across the API boundary.
-module(sigstore).

-export([default_config/0, verify/3, sign/1, trusted_root/1, signing_config/1]).

-export_type([config/0, artifact/0, trust_opts/0, verify_opts/0, sign_opts/0, verified/0, error/0]).

%% Config map threaded through every function, like `hex_core:config()'.
-type config() :: #{
    json_adapter => sigstore_json:adapter(),
    http_adapter => {module(), map()},
    %% Extra attempts for retryable failures (see sigstore_http:retry()).
    http_retries => non_neg_integer()
}.

-type artifact() ::
    {file, file:name_all()}
    | {binary, binary()}
    | {digest, sha256, <<_:256>>}.

-type trust_opts() :: #{
    config => config(),
    instance => production | staging,
    trusted_root => sigstore_trust:source(),
    signing_config => sigstore_trust:source()
}.

-type verify_opts() :: #{
    config => config(),
    trusted_root := sigstore_trust:trusted_root(),
    policy := sigstore_policy:t(),
    now => sigstore_time:t()
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
    certificate := binary() | undefined,
    identity := binary() | undefined,
    issuer := binary() | undefined,
    signed_times := [{tsa | tlog, sigstore_time:t()}],
    statement := map() | undefined
}.

-type error() :: {error, {Stage :: atom(), Reason :: term()}}.

%% @doc Default configuration: OTP `json' adapter (OTP 27+).
-spec default_config() -> config().
default_config() ->
    #{
        json_adapter => sigstore_json:default_adapter(),
        http_adapter => sigstore_http:default_adapter()
    }.

%% @doc Verify `Bundle' (JSON binary or parsed bundle) over `Artifact' offline.
-spec verify(artifact(), binary() | sigstore_bundle:t(), verify_opts()) ->
    {ok, verified()} | error().
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
