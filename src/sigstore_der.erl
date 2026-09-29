%% @doc Minimal DER reader: enough for Fulcio extension values, SCT lists
%% and (M4) RFC 3161 TSTInfo, without build-time ASN.1 code (SPEC §2a V3).
%% Never raises.
-module(sigstore_der).

-export([tlv/1, utf8_string/1, children/1, oid/1, uint/1, generalized_time/1, encode_tlv/2]).

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

%% @doc Decode OBJECT IDENTIFIER contents (without tag/length) to a tuple.
-spec oid(binary()) -> {ok, tuple()} | {error, {der, term()}}.
oid(<<First, Rest/binary>>) ->
    {A, B} =
        if
            First < 40 -> {0, First};
            First < 80 -> {1, First - 40};
            true -> {2, First - 80}
        end,
    case arcs(Rest, 0, []) of
        {ok, Arcs} -> {ok, list_to_tuple([A, B | Arcs])};
        E -> E
    end;
oid(_) ->
    {error, {der, bad_oid}}.

arcs(<<>>, 0, Acc) -> {ok, lists:reverse(Acc)};
arcs(<<>>, _, _) -> {error, {der, bad_oid}};
arcs(<<1:1, V:7, Rest/binary>>, N, Acc) -> arcs(Rest, (N bsl 7) bor V, Acc);
arcs(<<0:1, V:7, Rest/binary>>, N, Acc) -> arcs(Rest, 0, [(N bsl 7) bor V | Acc]).

%% @doc Non-negative INTEGER contents.
-spec uint(binary()) -> {ok, non_neg_integer()} | {error, {der, term()}}.
uint(<<0:1, _:7, _/binary>> = B) -> {ok, binary:decode_unsigned(B)};
uint(_) -> {error, {der, bad_integer}}.

%% @doc GeneralizedTime `YYYYMMDDHHMMSS[.f+]Z' to `sigstore_time:t()'.
-spec generalized_time(binary()) -> {ok, sigstore_time:t()} | {error, {der, term()}}.
generalized_time(
    <<Y:4/binary, Mo:2/binary, D:2/binary, H:2/binary, Mi:2/binary, S:2/binary, Rest/binary>>
) ->
    try
        Frac =
            case Rest of
                <<"Z">> ->
                    0;
                <<$., F/binary>> ->
                    [Digits, <<>>] = binary:split(F, <<"Z">>),
                    true = Digits =/= <<>> andalso byte_size(Digits) =< 6,
                    binary_to_integer(Digits) * pow10(6 - byte_size(Digits))
            end,
        DT = {{i(Y), i(Mo), i(D)}, {i(H), i(Mi), i(S)}},
        true = calendar:valid_date(element(1, DT)),
        Secs = calendar:datetime_to_gregorian_seconds(DT) - 62167219200,
        {ok, sigstore_time:from_unix_seconds(Secs) + Frac}
    catch
        _:_ -> {error, {der, bad_time}}
    end;
generalized_time(_) ->
    {error, {der, bad_time}}.

i(B) -> binary_to_integer(B).
pow10(0) -> 1;
pow10(N) -> 10 * pow10(N - 1).

%% @doc Encode one TLV (definite, minimal length).
-spec encode_tlv(byte(), binary()) -> binary().
encode_tlv(Tag, V) ->
    L = byte_size(V),
    Len =
        if
            L < 128 ->
                <<L>>;
            true ->
                LB = binary:encode_unsigned(L),
                <<(16#80 bor byte_size(LB)), LB/binary>>
        end,
    <<Tag, Len/binary, V/binary>>.
