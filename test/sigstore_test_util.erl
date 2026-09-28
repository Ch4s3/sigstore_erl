-module(sigstore_test_util).

-export([root/0, read_vector/1]).

%% Project root: rebar3 symlinks _build/<profile>/lib/sigstore_erl/src back
%% to the checkout, so four levels up from the lib dir.
root() ->
    Root = filename:absname(filename:join([code:lib_dir(sigstore_erl), "..", "..", "..", ".."])),
    Norm = normalize(filename:split(Root), []),
    true = filelib:is_file(filename:join(Norm, "SPEC.md")),
    Norm.

normalize([], Acc) -> filename:join(lists:reverse(Acc));
normalize([".." | T], [_ | Acc]) -> normalize(T, Acc);
normalize(["." | T], Acc) -> normalize(T, Acc);
normalize([H | T], Acc) -> normalize(T, [H | Acc]).

read_vector(Rel) ->
    {ok, B} = file:read_file(filename:join([root(), "test/vectors", Rel])),
    B.
