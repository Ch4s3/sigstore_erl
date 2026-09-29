%% @doc TrustedRoot and SigningConfig models and selectors (SPEC.md §5.2).
%%
%% Validity ranges are inclusive (conformance trust-root-*-validity-end-
%% inclusive) and `start' is mandatory (trust-root-tlog-missing-validity-
%% start_fail). Selectors never consult the wall clock: the caller passes
%% the instant being checked, which is how expired keys still verify old
%% entries.
-module(sigstore_trust).

-include("sigstore.hrl").

-export([
    load_trusted_root/1,
    load_signing_config/1,
    trusted_root_from_map/1,
    signing_config_from_map/1,
    tlogs_for/3,
    tlogs_matching/2,
    ctlogs_for/3,
    cas_at/2,
    tsas/1,
    select_services/4
]).

-export_type([trusted_root/0, signing_config/0, log/0, authority/0, service/0, source/0]).

-type source() :: {file, file:name_all()} | {json, binary()} | map().

-type log() :: #{
    base_url := binary(),
    hash_algorithm := binary(),
    key := sigstore_keys:key() | {unsupported, term()},
    key_details := binary(),
    valid_for := sigstore_time:range(),
    log_id := binary(),
    checkpoint_key_id := binary() | undefined,
    operator := binary() | undefined
}.

-type authority() :: #{
    uri := binary(),
    cert_chain := [binary(), ...],
    valid_for := sigstore_time:range(),
    operator := binary() | undefined
}.

-type trusted_root() :: #{
    media_type := binary(),
    tlogs := [log()],
    ctlogs := [log()],
    certificate_authorities := [authority()],
    timestamp_authorities := [authority()]
}.

-type service() :: #{
    url := binary(),
    major_api_version := non_neg_integer(),
    valid_for := sigstore_time:range(),
    operator := binary() | undefined
}.

-type selector() :: all | any | {exact, pos_integer()}.

-type signing_config() :: #{
    media_type := binary(),
    ca_urls := [service()],
    oidc_urls := [service()],
    rekor_tlog_urls := [service()],
    tsa_urls := [service()],
    rekor_tlog_config := selector(),
    tsa_config := selector()
}.

%%% ------------------------------------------------------------- loading

%% @doc `#{trusted_root => source()}' wins; otherwise the embedded snapshot
%% for `instance' (default production). A ClientTrustConfig is unwrapped.
-spec load_trusted_root(sigstore:trust_opts()) -> {ok, trusted_root()} | {error, {trust, term()}}.
load_trusted_root(Opts) ->
    Config = maps:get(config, Opts, sigstore:default_config()),
    case maps:find(trusted_root, Opts) of
        {ok, Src} ->
            with_map(Config, Src, <<"trustedRoot">>, fun trusted_root_from_map/1);
        error ->
            Inst = maps:get(instance, Opts, production),
            with_map(
                Config,
                {json, sigstore_trust_embedded:trusted_root(Inst)},
                <<"trustedRoot">>,
                fun trusted_root_from_map/1
            )
    end.

-spec load_signing_config(sigstore:trust_opts()) ->
    {ok, signing_config()} | {error, {trust, term()}}.
load_signing_config(Opts) ->
    Config = maps:get(config, Opts, sigstore:default_config()),
    case maps:find(signing_config, Opts) of
        {ok, Src} ->
            with_map(Config, Src, <<"signingConfig">>, fun signing_config_from_map/1);
        error ->
            Inst = maps:get(instance, Opts, production),
            with_map(
                Config,
                {json, sigstore_trust_embedded:signing_config(Inst)},
                <<"signingConfig">>,
                fun signing_config_from_map/1
            )
    end.

%% `Key' names the member to unwrap from a ClientTrustConfig.
with_map(Config, {file, Path}, Key, F) ->
    case file:read_file(Path) of
        {ok, Bin} -> with_map(Config, {json, Bin}, Key, F);
        {error, R} -> {error, {trust, {read, Path, R}}}
    end;
with_map(Config, {json, Bin}, Key, F) ->
    case sigstore_json:decode(Config, Bin) of
        {ok, M} when is_map(M) -> with_map(Config, M, Key, F);
        {ok, _} -> {error, {trust, not_an_object}};
        {error, R} -> {error, {trust, R}}
    end;
with_map(_Config, #{<<"mediaType">> := ?CLIENT_TRUST_CONFIG_V01} = M, Key, F) ->
    case M of
        #{Key := Inner} when is_map(Inner) -> F(Inner);
        _ -> {error, {trust, {missing, Key}}}
    end;
with_map(_Config, M, _Key, F) when is_map(M) ->
    F(M);
with_map(_Config, Other, _Key, _F) ->
    {error, {trust, {invalid_source, Other}}}.

%%% ------------------------------------------------------- trusted root

-spec trusted_root_from_map(map()) -> {ok, trusted_root()} | {error, {trust, term()}}.
trusted_root_from_map(M) ->
    try
        MT = req(<<"mediaType">>, M),
        lists:member(MT, [?TRUSTED_ROOT_V01_LEGACY, ?TRUSTED_ROOT_V01, ?TRUSTED_ROOT_V02]) orelse
            throw({trust, {unknown_media_type, MT}}),
        {ok, #{
            media_type => MT,
            tlogs => [log(L) || L <- maps:get(<<"tlogs">>, M, [])],
            ctlogs => [log(L) || L <- maps:get(<<"ctlogs">>, M, [])],
            certificate_authorities => [
                authority(A)
             || A <- maps:get(<<"certificateAuthorities">>, M, [])
            ],
            timestamp_authorities => [
                authority(A)
             || A <- maps:get(<<"timestampAuthorities">>, M, [])
            ]
        }}
    catch
        throw:{trust, _} = E -> {error, E}
    end.

log(L) ->
    PK = req(<<"publicKey">>, L),
    Raw = bytes(<<"rawBytes">>, PK),
    Details = maps:get(<<"keyDetails">>, PK, <<"PUBLIC_KEY_DETAILS_UNSPECIFIED">>),
    %% An unparseable key in an entry we never select must not poison the
    %% whole root; it can only fail when that log is actually used.
    Key =
        case sigstore_keys:from_spki_der(Raw) of
            {ok, K} -> K;
            {error, R} -> {unsupported, R}
        end,
    #{
        base_url => maps:get(<<"baseUrl">>, L, <<>>),
        hash_algorithm => maps:get(<<"hashAlgorithm">>, L, <<"SHA2_256">>),
        key => Key,
        key_details => Details,
        valid_for => range(maps:get(<<"validFor">>, PK, #{})),
        log_id => bytes(<<"keyId">>, req(<<"logId">>, L)),
        checkpoint_key_id =>
            case maps:get(<<"checkpointKeyId">>, L, undefined) of
                undefined -> undefined;
                C -> bytes(<<"keyId">>, C)
            end,
        operator => maps:get(<<"operator">>, L, undefined)
    }.

authority(A) ->
    Chain = [
        bytes(<<"rawBytes">>, C)
     || C <- maps:get(<<"certificates">>, req(<<"certChain">>, A), [])
    ],
    Chain =/= [] orelse throw({trust, {empty_cert_chain, maps:get(<<"uri">>, A, <<>>)}}),
    #{
        uri => maps:get(<<"uri">>, A, <<>>),
        cert_chain => Chain,
        valid_for => range(maps:get(<<"validFor">>, A, #{})),
        operator => maps:get(<<"operator">>, A, undefined)
    }.

%%% ------------------------------------------------------ signing config

-spec signing_config_from_map(map()) -> {ok, signing_config()} | {error, {trust, term()}}.
signing_config_from_map(M) ->
    try
        MT = req(<<"mediaType">>, M),
        MT =:= ?SIGNING_CONFIG_V02 orelse throw({trust, {unknown_media_type, MT}}),
        {ok, #{
            media_type => MT,
            ca_urls => [service(S) || S <- maps:get(<<"caUrls">>, M, [])],
            oidc_urls => [service(S) || S <- maps:get(<<"oidcUrls">>, M, [])],
            rekor_tlog_urls => [service(S) || S <- maps:get(<<"rekorTlogUrls">>, M, [])],
            tsa_urls => [service(S) || S <- maps:get(<<"tsaUrls">>, M, [])],
            rekor_tlog_config => selector(maps:get(<<"rekorTlogConfig">>, M, #{})),
            tsa_config => selector(maps:get(<<"tsaConfig">>, M, #{}))
        }}
    catch
        throw:{trust, _} = E -> {error, E}
    end.

service(S) ->
    #{
        url => req(<<"url">>, S),
        major_api_version => maps:get(<<"majorApiVersion">>, S, 0),
        valid_for => range(maps:get(<<"validFor">>, S, #{})),
        operator => maps:get(<<"operator">>, S, undefined)
    }.

selector(#{<<"selector">> := <<"ALL">>}) ->
    all;
selector(#{<<"selector">> := <<"ANY">>}) ->
    any;
selector(#{<<"selector">> := <<"EXACT">>, <<"count">> := N}) when is_integer(N), N > 0 ->
    {exact, N};
selector(#{} = M) when map_size(M) =:= 0 -> any;
selector(Other) ->
    throw({trust, {invalid_selector, Other}}).

%%% ----------------------------------------------------------- selectors

%% @doc Tlogs whose `logId' or `checkpointKeyId' equals `KeyId' and whose
%% validity covers `T'.
-spec tlogs_for(trusted_root(), binary(), sigstore_time:t()) -> [log()].
tlogs_for(#{tlogs := Logs}, KeyId, T) -> logs_for(Logs, KeyId, T).

%% @doc Tlogs matching `KeyId' regardless of validity. Only for entries
%% whose signed time is not yet known (Rekor v2 before its TSA time is
%% verified); callers must check validity once the time is known.
-spec tlogs_matching(trusted_root(), binary()) -> [log()].
tlogs_matching(#{tlogs := Logs}, KeyId) ->
    [L || #{log_id := Id, checkpoint_key_id := CK} = L <- Logs, Id =:= KeyId orelse CK =:= KeyId].

-spec ctlogs_for(trusted_root(), binary(), sigstore_time:t()) -> [log()].
ctlogs_for(#{ctlogs := Logs}, KeyId, T) -> logs_for(Logs, KeyId, T).

logs_for(Logs, KeyId, T) ->
    [
        L
     || #{log_id := Id, checkpoint_key_id := CK, valid_for := R} = L <- Logs,
        Id =:= KeyId orelse CK =:= KeyId,
        sigstore_time:in_range(T, R)
    ].

%% @doc Certificate authorities valid at `T'.
-spec cas_at(trusted_root(), sigstore_time:t()) -> [authority()].
cas_at(#{certificate_authorities := CAs}, T) ->
    [A || #{valid_for := R} = A <- CAs, sigstore_time:in_range(T, R)].

%% @doc All TSAs; validity is checked against the timestamp's genTime.
-spec tsas(trusted_root()) -> [authority()].
tsas(#{timestamp_authorities := TSAs}) -> TSAs.

%% @doc Client spec §2: services valid at `Now' with a supported major
%% version. `ca'/`oidc': the single best one. `rekor'/`tsa': the highest
%% supported version per operator, then the configured selector.
-spec select_services(signing_config(), ca | oidc | rekor | tsa, sigstore_time:t(), [pos_integer()]) ->
    {ok, [service()]} | {error, {trust, term()}}.
select_services(SC, Kind, Now, Supported) ->
    {Key, Sel} =
        case Kind of
            ca -> {ca_urls, one};
            oidc -> {oidc_urls, one};
            rekor -> {rekor_tlog_urls, maps:get(rekor_tlog_config, SC)};
            tsa -> {tsa_urls, maps:get(tsa_config, SC)}
        end,
    Valid = [
        S
     || #{valid_for := R, major_api_version := V} = S <- maps:get(Key, SC),
        sigstore_time:in_range(Now, R),
        lists:member(V, Supported)
    ],
    %% Newest first by validity start, then highest version first.
    Sorted = lists:sort(
        fun(
            #{valid_for := {A, _}, major_api_version := VA},
            #{valid_for := {B, _}, major_api_version := VB}
        ) ->
            {VA, A} >= {VB, B}
        end,
        Valid
    ),
    apply_selector(Sel, per_operator(Sorted), Kind).

per_operator(Services) ->
    {_, Out} = lists:foldl(
        fun(#{operator := Op} = S, {Seen, Acc}) ->
            case Op =/= undefined andalso lists:member(Op, Seen) of
                true -> {Seen, Acc};
                false -> {[Op | Seen], [S | Acc]}
            end
        end,
        {[], []},
        Services
    ),
    lists:reverse(Out).

apply_selector(_, [], Kind) ->
    {error, {trust, {no_service, Kind}}};
apply_selector(one, [S | _], _) ->
    {ok, [S]};
apply_selector(any, [S | _], _) ->
    {ok, [S]};
apply_selector(all, Ss, _) ->
    {ok, Ss};
apply_selector({exact, N}, Ss, _) when length(Ss) >= N -> {ok, lists:sublist(Ss, N)};
apply_selector({exact, N}, Ss, Kind) ->
    {error, {trust, {not_enough_services, Kind, N, length(Ss)}}}.

%%% ------------------------------------------------------------- helpers

req(K, M) when is_map(M) ->
    case M of
        #{K := V} -> V;
        _ -> throw({trust, {missing, K}})
    end;
req(K, _) ->
    throw({trust, {invalid, K}}).

bytes(K, M) ->
    case sigstore_b64:decode(req(K, M)) of
        {ok, B} -> B;
        {error, _} -> throw({trust, {invalid_base64, K}})
    end.

range(R) ->
    case sigstore_time:range(R) of
        {ok, Range} -> Range;
        {error, {time, E}} -> throw({trust, {valid_for, E}})
    end.
