%% @doc HTTP contract and shared request layer (SPEC.md §8.2).
%%
%% The adapter callback is identical to hex_core's `hex_http:request/5', so
%% a host such as hex can pass its own configured adapter through:
%% `#{http_adapter => {Module, AdapterConfig}}'. Behaviours are checked at
%% compile time only, so an adapter need not name this module.
%%
%% This module adds what every adapter would otherwise repeat: a User-Agent
%% (unless the caller set one), JSON encoding (RFC 8785 via `sigstore_jcs')
%% and decoding (via the configured `json_adapter'), and retries under an
%% explicit per-call policy.
-module(sigstore_http).

-include("sigstore.hrl").

-export([request/6, json/6, default_adapter/0, user_agent/0]).

-export_type([method/0, headers/0, body/0, response/0, retry/0]).

-type method() :: get | post | put | patch | delete.
-type status() :: non_neg_integer().
-type headers() :: #{binary() => binary()}.
-type body() :: {ContentType :: binary(), Body :: binary()} | undefined.
-type response() :: {status(), headers(), binary()}.

%% `idempotent': safe to resend (Fulcio, TSA, GETs); retried on 5xx and on
%% connection failures. `connect_only': not idempotent (Rekor uploads);
%% retried only when the request provably never reached the server.
%% `none': never retried.
-type retry() :: idempotent | connect_only | none.

-callback request(method(), URI :: binary(), headers(), body(), AdapterConfig :: map()) ->
    {ok, response()} | {error, term()}.

-define(DEFAULT_RETRIES, 2).
-define(BACKOFF_MS, 250).

-spec default_adapter() -> {module(), map()}.
default_adapter() -> {sigstore_http_httpc, #{}}.

-spec user_agent() -> binary().
user_agent() ->
    iolist_to_binary([
        "sigstore_erl/", ?SIGSTORE_ERL_VERSION, " (OTP/", erlang:system_info(otp_release), ")"
    ]).

%% @doc Raw request through the configured adapter.
-spec request(sigstore:config(), method(), binary(), headers(), body(), retry()) ->
    {ok, response()} | {error, {http, term()}}.
request(Config, Method, URI, Headers, Body, Retry) when is_binary(URI), is_map(Headers) ->
    {Mod, Cfg} = maps:get(http_adapter, Config, default_adapter()),
    Hs = put_new(<<"user-agent">>, user_agent(), lower_keys(Headers)),
    Attempts = 1 + maps:get(http_retries, Config, ?DEFAULT_RETRIES),
    attempt(fun() -> call(Mod, Method, URI, Hs, Body, Cfg) end, Retry, Attempts, 0).

%% @doc JSON request: `Term' (or `undefined') is encoded with JCS; a JSON
%% response body is decoded with the configured JSON adapter. Non-JSON
%% responses (e.g. error pages) come back as `{raw, Binary}'.
-spec json(sigstore:config(), method(), binary(), headers(), term() | undefined, retry()) ->
    {ok, {status(), headers(), sigstore_json:value() | {raw, binary()}}} | {error, {http, term()}}.
json(Config, Method, URI, Headers, Term, Retry) ->
    Body =
        case Term of
            undefined ->
                {ok, undefined};
            _ ->
                case sigstore_jcs:encode(Term) of
                    {ok, Bin} -> {ok, {<<"application/json">>, Bin}};
                    {error, R} -> {error, {http, {encode, R}}}
                end
        end,
    case Body of
        {ok, B} ->
            Hs = put_new(<<"accept">>, <<"application/json">>, lower_keys(Headers)),
            case request(Config, Method, URI, Hs, B, Retry) of
                {ok, {Status, RespHs, RespBody}} ->
                    {ok, {Status, RespHs, decode_body(Config, RespHs, RespBody)}};
                {error, _} = E ->
                    E
            end;
        {error, _} = E ->
            E
    end.

decode_body(_Config, _Hs, <<>>) ->
    {raw, <<>>};
decode_body(Config, Hs, Bin) ->
    case binary:match(maps:get(<<"content-type">>, Hs, <<>>), <<"json">>) of
        nomatch ->
            {raw, Bin};
        _ ->
            case sigstore_json:decode(Config, Bin) of
                {ok, V} -> V;
                {error, _} -> {raw, Bin}
            end
    end.

%%% Retries.

attempt(F, Retry, Left, N) ->
    Result = F(),
    case Left > 1 andalso retryable(Retry, Result) of
        true ->
            timer:sleep(?BACKOFF_MS bsl N),
            attempt(F, Retry, Left - 1, N + 1);
        false ->
            Result
    end.

retryable(idempotent, {ok, {Status, _, _}}) -> Status >= 500;
retryable(idempotent, {error, _}) -> true;
retryable(connect_only, {error, {http, {adapter, Reason}}}) -> never_sent(Reason);
retryable(_, _) -> false.

%% Failures that happen before any request byte reaches the server. The
%% shapes are httpc's; errors from other adapters are not retried under
%% `connect_only', which is the safe direction.
never_sent({failed_connect, _}) -> true;
never_sent(econnrefused) -> true;
never_sent(nxdomain) -> true;
never_sent(_) -> false.

call(Mod, Method, URI, Hs, Body, Cfg) ->
    try Mod:request(Method, URI, Hs, Body, Cfg) of
        {ok, {S, RHs, RB}} when is_integer(S), is_map(RHs), is_binary(RB) ->
            {ok, {S, lower_keys(RHs), RB}};
        {error, R} ->
            {error, {http, {adapter, R}}};
        Other ->
            {error, {http, {bad_adapter_return, Mod, Other}}}
    catch
        C:R -> {error, {http, {adapter_crashed, Mod, C, R}}}
    end.

lower_keys(M) -> maps:fold(fun(K, V, Acc) -> Acc#{string:lowercase(K) => V} end, #{}, M).

put_new(K, V, M) ->
    case maps:is_key(K, M) of
        true -> M;
        false -> M#{K => V}
    end.
