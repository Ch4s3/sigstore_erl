%% @doc Minimal DER reader: enough for Fulcio extension values, SCT lists
%% and (M4) RFC 3161 TSTInfo, without build-time ASN.1 code (SPEC §2a V3).
%% Never raises.
-module(sigstore_der).

-export([tlv/1, utf8_string/1, children/1]).

-type tag() :: byte().

%% @doc Split one TLV off the front: `{ok, Tag, Value, Rest}'.
-spec tlv(binary()) -> {ok, tag(), binary(), binary()} | {error, {der, term()}}.
tlv(<<Tag, 0:1, Len:7, Rest/binary>>) ->
    take(Tag, Len, Rest);
tlv(<<Tag, 1:1, N:7, Rest/binary>>) when N >= 1, N =< 4 ->
    case Rest of
        <<Len:(N * 8), Rest2/binary>> when Len >= 128 -> take(Tag, Len, Rest2);
        <<_:(N * 8), _/binary>> -> {error, {der, non_minimal_length}};
        _ -> {error, {der, truncated}}
    end;
tlv(<<_, _/binary>>) ->
    {error, {der, bad_length}};
tlv(_) ->
    {error, {der, truncated}}.

take(Tag, Len, Bin) ->
    case Bin of
        <<V:Len/binary, Rest/binary>> -> {ok, Tag, V, Rest};
        _ -> {error, {der, truncated}}
    end.

%% @doc Decode exactly one UTF8String (tag 0x0C) with nothing trailing.
-spec utf8_string(binary()) -> {ok, binary()} | {error, {der, term()}}.
utf8_string(Bin) ->
    case tlv(Bin) of
        {ok, 16#0C, V, <<>>} -> {ok, V};
        {ok, 16#0C, _, _} -> {error, {der, trailing_data}};
        {ok, T, _, _} -> {error, {der, {unexpected_tag, T}}};
        {error, _} = E -> E
    end.

%% @doc All TLVs of a constructed value's contents.
-spec children(binary()) -> {ok, [{tag(), binary()}]} | {error, {der, term()}}.
children(Bin) -> children(Bin, []).

children(<<>>, Acc) ->
    {ok, lists:reverse(Acc)};
children(Bin, Acc) ->
    case tlv(Bin) of
        {ok, T, V, Rest} -> children(Rest, [{T, V} | Acc]);
        {error, _} = E -> E
    end.
