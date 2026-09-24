%% @doc Thin wrapper over OTP's `json'. Single swap point if an older OTP
%% floor ever requires a vendored codec (SPEC.md §2, Q1).
-module(sigstore_json).

-export([decode/1, encode/1]).

-spec decode(binary()) -> {ok, json:decode_value()} | {error, {json, term()}}.
decode(Bin) when is_binary(Bin) ->
    try
        {ok, json:decode(Bin)}
    catch
        error:Reason -> {error, {json, Reason}}
    end.

-spec encode(json:encode_value()) -> iodata().
encode(Term) ->
    json:encode(Term).
