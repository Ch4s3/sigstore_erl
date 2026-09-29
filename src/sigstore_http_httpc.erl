%% @doc Default HTTP adapter over OTP's `httpc' (SPEC.md §8.2).
%%
%% TLS verification is mandatory: peer verification against the OS CA
%% store (or `cacerts' given in the adapter config), and HTTPS hostname
%% checking. Options that disable it are refused rather than warned about.
%% Plain `http' URIs are refused unless `allow_http' is set (local test
%% instances only).
%%
%% Adapter config keys: `profile' (httpc profile, default `default'),
%% `timeout' and `connect_timeout' (ms), `cacerts' (list of DER, replaces
%% the OS store), `allow_http' (boolean). The `inets' and `ssl'
%% applications must already be running: a library does not start them.
-module(sigstore_http_httpc).

-behaviour(sigstore_http).

-export([request/5]).

-define(TIMEOUT, 30000).
-define(CONNECT_TIMEOUT, 10000).

-spec request(
    sigstore_http:method(), binary(), sigstore_http:headers(), sigstore_http:body(), map()
) ->
    {ok, sigstore_http:response()} | {error, term()}.
request(Method, URI, Headers, Body, Cfg) ->
    case {running(), scheme(URI, Cfg)} of
        {{error, _} = E, _} ->
            E;
        {_, {error, _} = E} ->
            E;
        {ok, {ok, Scheme}} ->
            HTTPOpts = [
                {timeout, maps:get(timeout, Cfg, ?TIMEOUT)},
                {connect_timeout, maps:get(connect_timeout, Cfg, ?CONNECT_TIMEOUT)},
                {autoredirect, false}
                | [{ssl, ssl_opts(Cfg)} || Scheme =:= https]
            ],
            Req = req(Method, binary_to_list(URI), Headers, Body),
            Profile = maps:get(profile, Cfg, default),
            case httpc:request(Method, Req, HTTPOpts, [{body_format, binary}], Profile) of
                {ok, {{_, Status, _}, RespHeaders, RespBody}} ->
                    {ok, {Status, headers_out(RespHeaders), RespBody}};
                {error, _} = E ->
                    E
            end
    end.

running() ->
    Apps = [A || {A, _, _} <- application:which_applications()],
    case [A || A <- [inets, ssl], not lists:member(A, Apps)] of
        [] -> ok;
        [A | _] -> {error, {not_started, A}}
    end.

scheme(<<"https://", _/binary>>, _Cfg) -> {ok, https};
scheme(<<"http://", _/binary>>, #{allow_http := true}) -> {ok, http};
scheme(<<"http://", _/binary>>, _Cfg) -> {error, plain_http_refused};
scheme(_, _) -> {error, unsupported_scheme}.

ssl_opts(Cfg) ->
    [
        {verify, verify_peer},
        {cacerts, maps:get(cacerts, Cfg, public_key:cacerts_get())},
        {depth, 10},
        {customize_hostname_check, [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}
    ].

req(Method, URI, Headers, undefined) when Method =:= get; Method =:= delete ->
    {URI, headers_in(Headers)};
req(_Method, URI, Headers, undefined) ->
    {URI, headers_in(Headers), "application/octet-stream", <<>>};
req(_Method, URI, Headers, {ContentType, Body}) ->
    {URI, headers_in(maps:remove(<<"content-type">>, Headers)), binary_to_list(ContentType), Body}.

headers_in(M) -> [{binary_to_list(K), binary_to_list(V)} || {K, V} <- maps:to_list(M)].

headers_out(L) ->
    maps:from_list([{string:lowercase(list_to_binary(K)), list_to_binary(V)} || {K, V} <- L]).
