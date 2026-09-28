%% @doc JSON codec. OTP floor is 25 (hex_core vendoring, SPEC.md §2a), so the
%% OTP 27 `json' module cannot be used. M0 stub delegates to it; M1 replaces
%% the body with a self-contained codec keeping this exact interface.
%% TODO(M1): own decoder/encoder; remove the `json' dependency.
-module(sigstore_json).

-export([decode/1, encode/1]).

-spec decode(binary()) -> {ok, term()} | {error, {json, term()}}.
decode(Bin) when is_binary(Bin) ->
    try
        {ok, json:decode(Bin)}
    catch
        error:Reason -> {error, {json, Reason}}
    end.

-spec encode(term()) -> iodata().
encode(Term) ->
    json:encode(Term).
