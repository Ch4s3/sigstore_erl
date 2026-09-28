%% @doc Time handling. All instants are integer microseconds since the Unix
%% epoch (`sigstore_time:t()'); ranges are inclusive on both ends, matching
%% the protobuf-specs `TimeRange' semantics.
-module(sigstore_time).

-export([parse_rfc3339/1, from_unix_seconds/1, now/0, range/1, in_range/2, to_rfc3339/1]).

-export_type([t/0, range/0]).

-type t() :: integer().
-type range() :: {Start :: t(), End :: t() | infinity}.

-spec parse_rfc3339(binary()) -> {ok, t()} | {error, {time, {invalid, binary()}}}.
parse_rfc3339(Bin) when is_binary(Bin) ->
    try
        {ok, calendar:rfc3339_to_system_time(binary_to_list(Bin), [{unit, microsecond}])}
    catch
        _:_ -> {error, {time, {invalid, Bin}}}
    end;
parse_rfc3339(Other) ->
    {error, {time, {invalid, Other}}}.

-spec to_rfc3339(t()) -> binary().
to_rfc3339(T) ->
    list_to_binary(calendar:system_time_to_rfc3339(T, [{unit, microsecond}, {offset, "Z"}])).

-spec from_unix_seconds(integer()) -> t().
from_unix_seconds(S) -> S * 1000000.

-spec now() -> t().
now() -> os:system_time(microsecond).

%% @doc Parse a protobuf `TimeRange' JSON object. `start' is REQUIRED: a
%% missing start must not be read as "unbounded" (conformance
%% trust-root-tlog-missing-validity-start_fail).
-spec range(term()) -> {ok, range()} | {error, {time, term()}}.
range(#{<<"start">> := S} = M) ->
    maybe_end(parse_rfc3339(S), maps:get(<<"end">>, M, undefined));
range(#{}) ->
    {error, {time, missing_start}};
range(Other) ->
    {error, {time, {invalid_range, Other}}}.

maybe_end({ok, S}, undefined) ->
    {ok, {S, infinity}};
maybe_end({ok, S}, E) ->
    case parse_rfc3339(E) of
        {ok, EndT} when EndT >= S -> {ok, {S, EndT}};
        {ok, _} -> {error, {time, end_before_start}};
        {error, _} = Err -> Err
    end;
maybe_end({error, _} = Err, _) ->
    Err.

-spec in_range(t(), range()) -> boolean().
in_range(T, {S, infinity}) -> T >= S;
in_range(T, {S, E}) -> T >= S andalso T =< E.
