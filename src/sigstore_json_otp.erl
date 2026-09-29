%% @doc Default `sigstore_json' adapter: OTP 27+'s `json' module, when present.
%%
%% The codec module is read from the adapter config (default `json') rather
%% than called statically, so the library compiles, loads, and passes xref
%% and dialyzer on OTP 25/26 where `json' does not exist.
-module(sigstore_json_otp).

-behaviour(sigstore_json).

-export([decode/2, available/0]).

-define(DEFAULT, json).

-spec available() -> boolean().
available() -> available(?DEFAULT).

available(Mod) ->
    case code:ensure_loaded(Mod) of
        {module, Mod} -> erlang:function_exported(Mod, decode, 1);
        _ -> false
    end.

-spec decode(binary(), map()) -> {ok, sigstore_json:value()} | {error, term()}.
decode(Bin, Cfg) ->
    Mod = maps:get(module, Cfg, ?DEFAULT),
    case available(Mod) of
        true ->
            try
                {ok, Mod:decode(Bin)}
            catch
                error:Reason -> {error, {invalid, Reason}}
            end;
        false ->
            {error,
                {unavailable,
                    <<"OTP 27+ json module not present; set #{json_adapter => {Mod, Cfg}}">>}}
    end.
