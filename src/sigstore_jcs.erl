%% @doc RFC 8785 JSON Canonicalization Scheme, restricted to the values
%% Sigstore produces: objects with binary keys, arrays, UTF-8 binaries,
%% integers, booleans, `null'. Floats are rejected. Every JSON byte this
%% library emits goes through here (SPEC.md §8.3, §8.5).
-module(sigstore_jcs).

-export([encode/1]).

-spec encode(term()) -> {ok, binary()} | {error, {jcs, term()}}.
encode(Term) ->
    try
        {ok, iolist_to_binary(value(Term))}
    catch
        throw:{jcs, _} = R -> {error, R}
    end.

value(M) when is_map(M) ->
    Keys = lists:sort(fun key_le/2, [key(K) || K <- maps:keys(M)]),
    Members = [[string(K), $:, value(maps:get(K, M))] || K <- Keys],
    [${, lists:join($,, Members), $}];
value(L) when is_list(L) -> [$[, lists:join($,, [value(V) || V <- L]), $]];
value(B) when is_binary(B) -> string(B);
value(I) when is_integer(I) -> integer_to_binary(I);
value(true) ->
    <<"true">>;
value(false) ->
    <<"false">>;
value(null) ->
    <<"null">>;
value(F) when is_float(F) -> throw({jcs, {float_unsupported, F}});
value(Other) ->
    throw({jcs, {unsupported, Other}}).

key(K) when is_binary(K) -> K;
key(K) -> throw({jcs, {non_binary_key, K}}).

%% RFC 8785 §3.2.3: sort by UTF-16 code units. Big-endian UTF-16 bytes
%% compare exactly like their code units.
key_le(A, B) -> utf16(A) =< utf16(B).

utf16(B) ->
    case unicode:characters_to_binary(B, utf8, {utf16, big}) of
        U when is_binary(U) -> U;
        _ -> throw({jcs, {invalid_utf8, B}})
    end.

%% RFC 8785 §3.2.2.2: escape only '"', '\\' and C0 controls; short forms
%% for \b \t \n \f \r, lowercase \u00xx otherwise; everything else literal.
string(B) ->
    _ = utf16(B),
    [$", [esc(C) || <<C>> <= B], $"].

esc($") -> <<"\\\"">>;
esc($\\) -> <<"\\\\">>;
esc($\b) -> <<"\\b">>;
esc($\t) -> <<"\\t">>;
esc($\n) -> <<"\\n">>;
esc($\f) -> <<"\\f">>;
esc($\r) -> <<"\\r">>;
esc(C) when C < 16#20 -> io_lib:format("\\u~4.16.0b", [C]);
esc(C) -> C.
