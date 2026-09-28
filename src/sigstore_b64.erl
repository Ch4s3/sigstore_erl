%% @doc Strict base64 and hex helpers. Never raise.
%%
%% Protobuf JSON accepts standard or URL-safe alphabets, with or without
%% padding, for `bytes' fields. Line breaks (`\r', `\n') are skipped, as
%% Go's and Python's decoders and sigstore-rs do: real fixtures carry
%% line-wrapped output of the `base64' CLI. Anything else is rejected.
-module(sigstore_b64).

-export([decode/1, encode/1, hex_decode/1, hex_encode/1]).

-spec decode(binary()) -> {ok, binary()} | {error, {base64, invalid}}.
decode(Bin) when is_binary(Bin) ->
    Std = <<<<(to_std(C))>> || <<C>> <= Bin, C =/= $\r, C =/= $\n>>,
    case valid(Std) of
        {true, Unpadded} ->
            Padded = pad(Unpadded),
            try
                {ok, base64:decode(Padded)}
            catch
                error:_ -> {error, {base64, invalid}}
            end;
        false ->
            {error, {base64, invalid}}
    end;
decode(_) ->
    {error, {base64, invalid}}.

-spec encode(binary()) -> binary().
encode(Bin) -> base64:encode(Bin).

-spec hex_decode(binary()) -> {ok, binary()} | {error, {hex, invalid}}.
hex_decode(Hex) when is_binary(Hex), byte_size(Hex) rem 2 =:= 0 ->
    try
        {ok, binary:decode_hex(Hex)}
    catch
        error:_ -> {error, {hex, invalid}}
    end;
hex_decode(_) ->
    {error, {hex, invalid}}.

%% Lowercase, as Rekor and the SET payload use.
-spec hex_encode(binary()) -> binary().
hex_encode(Bin) -> string:lowercase(binary:encode_hex(Bin)).

to_std($-) -> $+;
to_std($_) -> $/;
to_std(C) -> C.

%% Strip at most two trailing '=', then every remaining char must be in the
%% alphabet and the unpadded length must not be 1 mod 4.
valid(Bin) ->
    Unpadded = strip_pad(Bin, 0),
    case Unpadded of
        error ->
            false;
        U ->
            Alpha = lists:all(fun alpha/1, binary_to_list(U)),
            PadOk =
                byte_size(U) rem 4 =/= 1 andalso
                    (byte_size(Bin) =:= byte_size(U) orelse byte_size(Bin) rem 4 =:= 0),
            case Alpha andalso PadOk of
                true -> {true, U};
                false -> false
            end
    end.

strip_pad(_, N) when N > 2 -> error;
strip_pad(<<>>, _) ->
    <<>>;
strip_pad(Bin, N) ->
    case binary:last(Bin) of
        $= -> strip_pad(binary:part(Bin, 0, byte_size(Bin) - 1), N + 1);
        _ -> Bin
    end.

alpha(C) when C >= $A, C =< $Z -> true;
alpha(C) when C >= $a, C =< $z -> true;
alpha(C) when C >= $0, C =< $9 -> true;
alpha($+) -> true;
alpha($/) -> true;
alpha(_) -> false.

pad(B) ->
    case byte_size(B) rem 4 of
        0 -> B;
        2 -> <<B/binary, "==">>;
        3 -> <<B/binary, "=">>
    end.
