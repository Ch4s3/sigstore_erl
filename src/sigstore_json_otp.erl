%% @doc Default `sigstore_json' adapter: OTP 27+'s `json' module, when present.
-module(sigstore_json_otp).

-behaviour(sigstore_json).

-export([decode/2, available/0]).

%% Referenced dynamically so this module compiles and loads on OTP 25/26,
%% where `json' does not exist (xref: the call is guarded by available/0).
-define(JSON, json).

-spec available() -> boolean().
available() ->
    case code:ensure_loaded(?JSON) of
        {module, ?JSON} -> erlang:function_exported(?JSON, decode, 1);
        _ -> false
    end.

-spec decode(binary(), map()) -> {ok, sigstore_json:value()} | {error, term()}.
decode(Bin, _Cfg) ->
    case available() of
        true ->
            try
                {ok, ?JSON:decode(Bin)}
            catch
                error:Reason -> {error, {invalid, Reason}}
            end;
        false ->
            {error,
                {unavailable,
                    <<"OTP 27+ json module not present; set #{json_adapter => {Mod, Cfg}}">>}}
    end.
