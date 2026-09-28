%% Test-only JSON decoder implementing the `sigstore_json' behaviour, so the
%% OTP 25/26 CI jobs (no `json' module) can run every suite. Not shipped.
-module(sigstore_test_json).

-behaviour(sigstore_json).

-export([decode/2, config/0]).

%% Config for tests: OTP `json' when present, this module otherwise.
config() ->
    case sigstore_json_otp:available() of
        true -> sigstore:default_config();
        false -> (sigstore:default_config())#{json_adapter => {?MODULE, #{}}}
    end.

decode(Bin, _Cfg) ->
    try value(ws(Bin)) of
        {V, Rest} ->
            case ws(Rest) of
                <<>> -> {ok, V};
                _ -> {error, trailing_data}
            end
    catch
        throw:R -> {error, R};
        error:R -> {error, R}
    end.

ws(<<C, R/binary>>) when C =:= $\s; C =:= $\t; C =:= $\n; C =:= $\r -> ws(R);
ws(B) -> B.

value(<<${, R/binary>>) -> object(ws(R), #{});
value(<<$[, R/binary>>) -> array(ws(R), []);
value(<<$", R/binary>>) -> string(R, []);
value(<<"true", R/binary>>) -> {true, R};
value(<<"false", R/binary>>) -> {false, R};
value(<<"null", R/binary>>) -> {null, R};
value(<<C, _/binary>> = B) when C =:= $-; C >= $0, C =< $9 -> number(B);
value(_) -> throw(unexpected_token).

object(<<$}, R/binary>>, Acc) ->
    {Acc, R};
object(<<$", R/binary>>, Acc) ->
    {K, R1} = string(R, []),
    <<$:, R2/binary>> = ws(R1),
    {V, R3} = value(ws(R2)),
    case ws(R3) of
        <<$,, R4/binary>> -> object(ws(R4), Acc#{K => V});
        <<$}, R4/binary>> -> {Acc#{K => V}, R4};
        _ -> throw(bad_object)
    end;
object(_, _) ->
    throw(bad_object).

array(<<$], R/binary>>, []) ->
    {[], R};
array(B, Acc) ->
    {V, R1} = value(B),
    case ws(R1) of
        <<$,, R2/binary>> -> array(ws(R2), [V | Acc]);
        <<$], R2/binary>> -> {lists:reverse([V | Acc]), R2};
        _ -> throw(bad_array)
    end.

string(<<$", R/binary>>, Acc) ->
    {unicode:characters_to_binary(lists:reverse(Acc)), R};
string(<<$\\, $u, H:4/binary, R/binary>>, Acc) ->
    Hi = binary_to_integer(H, 16),
    case {Hi >= 16#D800 andalso Hi =< 16#DBFF, R} of
        {true, <<$\\, $u, L:4/binary, R2/binary>>} ->
            Lo = binary_to_integer(L, 16),
            string(R2, [16#10000 + ((Hi - 16#D800) bsl 10) + (Lo - 16#DC00) | Acc]);
        _ ->
            string(R, [Hi | Acc])
    end;
string(<<$\\, C, R/binary>>, Acc) ->
    E =
        case C of
            $" -> $";
            $\\ -> 92;
            $/ -> $/;
            $b -> $\b;
            $f -> $\f;
            $n -> $\n;
            $r -> $\r;
            $t -> $\t;
            _ -> throw(bad_escape)
        end,
    string(R, [E | Acc]);
string(<<C/utf8, R/binary>>, Acc) when C >= 16#20 ->
    string(R, [C | Acc]);
string(_, _) ->
    throw(bad_string).

number(B) ->
    {Tok, R} = take_num(B, []),
    V =
        case lists:any(fun(C) -> lists:member(C, ".eE") end, Tok) of
            true -> list_to_float(fix_float(Tok));
            false -> list_to_integer(Tok)
        end,
    {V, R}.

take_num(<<C, R/binary>>, Acc) when
    C >= $0, C =< $9; C =:= $-; C =:= $+; C =:= $.; C =:= $e; C =:= $E
->
    take_num(R, [C | Acc]);
take_num(R, Acc) ->
    {lists:reverse(Acc), R}.

%% list_to_float/1 needs a fraction part: "1e5" -> "1.0e5".
fix_float(Tok) ->
    case lists:member($., Tok) of
        true ->
            Tok;
        false ->
            {M, E} = lists:splitwith(fun(C) -> C =/= $e andalso C =/= $E end, Tok),
            M ++ ".0" ++ E
    end.
