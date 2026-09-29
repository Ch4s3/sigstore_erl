%% Test-only `sigstore_http' adapter: delegates to `handler' in its config.
-module(sigstore_test_http).

-behaviour(sigstore_http).

-export([request/5]).

request(Method, URI, Headers, Body, #{handler := F}) -> F(Method, URI, Headers, Body).
