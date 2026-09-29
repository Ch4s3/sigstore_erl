-module(sigstore_http_SUITE).

-include_lib("stdlib/include/assert.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([
    user_agent/1,
    json_round_trip/1,
    retry_idempotent/1,
    retry_connect_only/1,
    adapter_failures_wrapped/1,
    tls_trusted_localhost/1,
    tls_rejects_untrusted_chain/1,
    tls_rejects_wrong_hostname/1,
    plain_http_refused/1
]).

all() ->
    [
        user_agent,
        json_round_trip,
        retry_idempotent,
        retry_connect_only,
        adapter_failures_wrapped,
        tls_trusted_localhost,
        tls_rejects_untrusted_chain,
        tls_rejects_wrong_hostname,
        plain_http_refused
    ].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    Config.

end_per_suite(Config) -> Config.

%%% Shared layer, via the stub adapter.

cfg(Handler) ->
    (sigstore_test_json:config())#{
        http_adapter => {sigstore_test_http, #{handler => Handler}}, http_retries => 2
    }.

echo(Method, URI, Headers, Body) ->
    self() ! {req, Method, URI, Headers, Body},
    {ok, {200, #{<<"Content-Type">> => <<"application/json">>}, <<"{\"ok\":true}">>}}.

user_agent(_) ->
    {ok, _} = sigstore_http:request(cfg(fun echo/4), get, <<"https://x">>, #{}, undefined, none),
    receive
        {req, get, <<"https://x">>, #{<<"user-agent">> := <<"sigstore_erl/", _/binary>>},
            undefined} ->
            ok
    after 0 -> ct:fail(no_user_agent)
    end,
    {ok, _} = sigstore_http:request(
        cfg(fun echo/4), get, <<"https://x">>, #{<<"User-Agent">> => <<"hex/2">>}, undefined, none
    ),
    receive
        {req, _, _, Hs, _} -> ?assertEqual(<<"hex/2">>, maps:get(<<"user-agent">>, Hs))
    after 0 -> ct:fail(no_request)
    end.

json_round_trip(_) ->
    {ok, {200, Hs, Decoded}} =
        sigstore_http:json(
            cfg(fun echo/4), post, <<"https://x">>, #{}, #{<<"b">> => 1, <<"a">> => [true]}, none
        ),
    ?assertEqual(#{<<"ok">> => true}, Decoded),
    %% Response header keys are normalised to lowercase.
    ?assertEqual(<<"application/json">>, maps:get(<<"content-type">>, Hs)),
    receive
        {req, post, _, ReqHs, {<<"application/json">>, Body}} ->
            ?assertEqual(<<"{\"a\":[true],\"b\":1}">>, Body),
            ?assertEqual(<<"application/json">>, maps:get(<<"accept">>, ReqHs))
    after 0 -> ct:fail(no_request)
    end,
    Html = fun(_, _, _, _) ->
        {ok, {502, #{<<"content-type">> => <<"text/html">>}, <<"<h1>bad gateway</h1>">>}}
    end,
    ?assertMatch(
        {ok, {502, _, {raw, <<"<h1>", _/binary>>}}},
        sigstore_http:json(cfg(Html), get, <<"https://x">>, #{}, undefined, none)
    ).

%% Fails with Script (one element per attempt), recording the attempt count.
scripted(Script) ->
    Ref = counters:new(1, []),
    F = fun(_, _, _, _) ->
        counters:add(Ref, 1, 1),
        N = counters:get(Ref, 1),
        lists:nth(min(N, length(Script)), Script)
    end,
    {F, fun() -> counters:get(Ref, 1) end}.

ok200() -> {ok, {200, #{}, <<>>}}.
s503() -> {ok, {503, #{}, <<>>}}.

retry_idempotent(_) ->
    {F, Count} = scripted([s503(), {error, timeout}, ok200()]),
    ?assertMatch(
        {ok, {200, _, _}},
        sigstore_http:request(cfg(F), post, <<"https://x">>, #{}, undefined, idempotent)
    ),
    ?assertEqual(3, Count()),
    %% Retries are bounded by http_retries: the last 503 is returned.
    {G, Count2} = scripted([s503()]),
    ?assertMatch(
        {ok, {503, _, _}},
        sigstore_http:request(cfg(G), post, <<"https://x">>, #{}, undefined, idempotent)
    ),
    ?assertEqual(3, Count2()).

%% Rekor uploads: a 5xx or timeout may mean the entry was logged, so only
%% failures that never reached the server are retried.
retry_connect_only(_) ->
    {F, C1} = scripted([s503(), ok200()]),
    ?assertMatch(
        {ok, {503, _, _}},
        sigstore_http:request(cfg(F), post, <<"https://x">>, #{}, undefined, connect_only)
    ),
    ?assertEqual(1, C1()),
    {G, C2} = scripted([{error, timeout}, ok200()]),
    ?assertMatch(
        {error, {http, {adapter, timeout}}},
        sigstore_http:request(cfg(G), post, <<"https://x">>, #{}, undefined, connect_only)
    ),
    ?assertEqual(1, C2()),
    {H, C3} = scripted([{error, {failed_connect, [econnrefused]}}, ok200()]),
    ?assertMatch(
        {ok, {200, _, _}},
        sigstore_http:request(cfg(H), post, <<"https://x">>, #{}, undefined, connect_only)
    ),
    ?assertEqual(2, C3()),
    {I, C4} = scripted([s503(), ok200()]),
    ?assertMatch(
        {ok, {503, _, _}}, sigstore_http:request(cfg(I), get, <<"https://x">>, #{}, undefined, none)
    ),
    ?assertEqual(1, C4()).

adapter_failures_wrapped(_) ->
    Crash = fun(_, _, _, _) -> error(boom) end,
    ?assertMatch(
        {error, {http, {adapter_crashed, sigstore_test_http, error, boom}}},
        sigstore_http:request(cfg(Crash), get, <<"https://x">>, #{}, undefined, none)
    ),
    Junk = fun(_, _, _, _) -> {ok, weird} end,
    ?assertMatch(
        {error, {http, {bad_adapter_return, _, _}}},
        sigstore_http:request(cfg(Junk), get, <<"https://x">>, #{}, undefined, none)
    ).

%%% Default httpc adapter against a local TLS server.

tls_trusted_localhost(Config) ->
    {Port, Root, Stop} = tls_server(Config),
    try
        Cfg = #{profile => profile(), cacerts => [Root], timeout => 5000},
        Res = sigstore_http_httpc:request(
            post, url("localhost", Port), #{}, {<<"application/json">>, <<"{}">>}, Cfg
        ),
        ?assertMatch(
            {ok,
                {200, #{<<"content-type">> := <<"application/json">>},
                    <<"{\"method\":\"POST\",\"len\":2}">>}},
            Res
        )
    after
        Stop()
    end.

tls_rejects_untrusted_chain(Config) ->
    {Port, _Root, Stop} = tls_server(Config),
    try
        %% The OS store does not contain the minted test root. Assert the
        %% client's own verdict, so a broken server cannot make this pass.
        Cfg = #{profile => profile(), timeout => 5000},
        {error, R} = sigstore_http_httpc:request(get, url("localhost", Port), #{}, undefined, Cfg),
        ?assertEqual(unknown_ca, client_alert(R))
    after
        Stop()
    end.

tls_rejects_wrong_hostname(Config) ->
    {Port, Root, Stop} = tls_server(Config),
    try
        %% Trusted chain, but the certificate names only "localhost".
        Cfg = #{profile => profile(), cacerts => [Root], timeout => 5000},
        {error, R} = sigstore_http_httpc:request(get, url("127.0.0.1", Port), #{}, undefined, Cfg),
        ?assertEqual(hostname_check_failed, client_alert(R))
    after
        Stop()
    end.

plain_http_refused(_) ->
    ?assertEqual(
        {error, plain_http_refused},
        sigstore_http_httpc:request(get, <<"http://localhost:1/">>, #{}, undefined, #{})
    ),
    ?assertEqual(
        {error, unsupported_scheme},
        sigstore_http_httpc:request(get, <<"ftp://x/">>, #{}, undefined, #{})
    ).

%% The rejection reason raised by *our* TLS client (not a server alert).
client_alert({failed_connect, Info}) ->
    [{tls_alert, {_, Msg}}] = [A || {inet, _, A} <- Info],
    ?assertMatch({match, _}, re:run(Msg, "TLS client: .* generated CLIENT ALERT")),
    case re:run(Msg, "hostname", [caseless]) of
        {match, _} ->
            hostname_check_failed;
        nomatch ->
            case re:run(Msg, "unknown.ca", [caseless]) of
                {match, _} -> unknown_ca;
                nomatch -> {unexpected, Msg}
            end
    end.

url(Host, Port) -> iolist_to_binary(["https://", Host, ":", integer_to_list(Port), "/api"]).

%% A fresh httpc profile per case so no pooled connection is reused.
profile() ->
    P = list_to_atom("sigstore_http_test_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, _} = inets:start(httpc, [{profile, P}]),
    P.

%% Minimal HTTPS/1.1 server: one response per connection, echoing the
%% method and body length as JSON.
tls_server(_Config) ->
    SAN = #'Extension'{
        extnID = ?'id-ce-subjectAltName', critical = false, extnValue = [{dNSName, "localhost"}]
    },
    Data = public_key:pkix_test_data(#{
        %% SHA-256 signatures: the default (SHA-1) is refused by TLS 1.3.
        root => [{key, {namedCurve, secp256r1}}, {digest, sha256}],
        peer => [{key, {namedCurve, secp256r1}}, {digest, sha256}, {extensions, [SAN]}]
    }),
    Cert = proplists:get_value(cert, Data),
    Key = proplists:get_value(key, Data),
    [Root | _] = [
        C
     || C <- lists:usort(proplists:get_value(cacerts, Data)), public_key:pkix_is_self_signed(C)
    ],
    {ok, L} = ssl:listen(0, [binary, {active, false}, {reuseaddr, true}, {cert, Cert}, {key, Key}]),
    {ok, {_, Port}} = ssl:sockname(L),
    Acceptor = spawn(fun() -> accept_loop(L) end),
    ok = ssl:controlling_process(L, Acceptor),
    {Port, Root, fun() ->
        exit(Acceptor, kill),
        _ = ssl:close(L)
    end}.

accept_loop(L) ->
    case ssl:transport_accept(L) of
        {ok, S0} ->
            _ = spawn(fun() -> serve(S0) end),
            accept_loop(L);
        _ ->
            ok
    end.

serve(S0) ->
    case ssl:handshake(S0, 5000) of
        {ok, S} ->
            {Method, Len} = read_request(S, <<>>),
            Body = iolist_to_binary([
                "{\"method\":\"", Method, "\",\"len\":", integer_to_list(Len), "}"
            ]),
            ok = ssl:send(S, [
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: ",
                integer_to_list(byte_size(Body)),
                "\r\n\r\n",
                Body
            ]),
            ssl:close(S);
        _ ->
            ok
    end.

read_request(S, Acc) ->
    case binary:split(Acc, <<"\r\n\r\n">>) of
        [Head, Rest] ->
            [ReqLine | Lines] = binary:split(Head, <<"\r\n">>, [global]),
            [Method | _] = binary:split(ReqLine, <<" ">>),
            Len = lists:foldl(
                fun(L, N) ->
                    case binary:split(L, <<":">>) of
                        [K, V] ->
                            case string:lowercase(K) of
                                <<"content-length">> -> binary_to_integer(string:trim(V));
                                _ -> N
                            end;
                        _ ->
                            N
                    end
                end,
                0,
                Lines
            ),
            _ = read_body(S, Rest, Len),
            {Method, Len};
        [_] ->
            {ok, More} = ssl:recv(S, 0, 5000),
            read_request(S, <<Acc/binary, More/binary>>)
    end.

read_body(_S, Got, Len) when byte_size(Got) >= Len -> Got;
read_body(S, Got, Len) ->
    {ok, More} = ssl:recv(S, 0, 5000),
    read_body(S, <<Got/binary, More/binary>>, Len).
