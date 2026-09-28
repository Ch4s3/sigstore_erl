%% SPEC.md §2a V7/V9: the library must survive hex_core-style vendoring,
%% twice (hex_core vendors us, then hex/rebar3 re-vendor hex_core).
-module(sigstore_vendor_SUITE).

-include_lib("stdlib/include/assert.hrl").

-export([all/0]).
-export([double_vendor_compiles_and_runs/1]).

all() -> [double_vendor_compiles_and_runs].

double_vendor_compiles_and_runs(Config) ->
    Root = sigstore_test_util:root(),
    {Files, Tokens} = vendor_list(filename:join(Root, "scripts/vendor_list.txt")),
    ?assertEqual(lists:sort(Files), lists:sort(src_files(Root))),
    Priv = proplists:get_value(priv_dir, Config),
    Hop1 = filename:join(Priv, "hop1"),
    Hop2 = filename:join(Priv, "hop2"),
    vendor(filename:join(Root, "src"), Files, Tokens, "a_", Hop1),
    vendor(Hop1, ["a_" ++ F || F <- Files], ["a_" ++ T || T <- Tokens], "b_", Hop2),
    Beams = [compile_one(Hop2, F) || F <- filelib:wildcard(filename:join(Hop2, "*.erl"))],
    %% No compiled module may still reference an unprefixed or singly
    %% prefixed module name, including atoms used for dynamic dispatch.
    lists:foreach(
        fun({Mod, Bin}) ->
            {ok, {_, [{atoms, Atoms}]}} = beam_lib:chunks(Bin, [atoms]),
            Leaks = [A || {_, A} <- Atoms, leaked(atom_to_list(A))],
            ?assertEqual({Mod, []}, {Mod, Leaks})
        end,
        Beams
    ),
    %% Load the vendored copy next to the original and actually run it,
    %% which exercises dynamic dispatch through the default JSON adapter.
    [{module, M} = code:load_binary(M, atom_to_list(M) ++ ".beam", B) || {M, B} <- Beams],
    Fixture = sigstore_test_util:read_vector("bundle-verify/happy-path-v0.3/bundle.sigstore.json"),
    VCfg0 = b_a_sigstore:default_config(),
    VCfg =
        case b_a_sigstore_json_otp:available() of
            true -> VCfg0;
            false -> VCfg0#{json_adapter => {sigstore_test_json, #{}}}
        end,
    ?assertMatch({ok, #{version := v0_3}}, b_a_sigstore_bundle:from_json(VCfg, Fixture)),
    ?assertMatch({ok, #{tlogs := [_ | _]}}, b_a_sigstore:trusted_root(#{config => VCfg})).

leaked("sigstore" ++ _) -> true;
leaked("a_sigstore" ++ _) -> true;
leaked(_) -> false.

src_files(Root) ->
    All = [
        filename:basename(F)
     || F <- filelib:wildcard(filename:join([Root, "src", "*.{erl,hrl}"]))
    ],
    %% V8: the conformance escript is not vendored.
    All -- ["sigstore_conformance.erl"].

vendor_list(Path) ->
    {ok, Bin} = file:read_file(Path),
    Lines = [string:trim(L) || L <- string:split(binary_to_list(Bin), "\n", all)],
    Useful = [L || L <- Lines, L =/= "", hd(L) =/= $#],
    {Files, ["[tokens]" | Tokens]} = lists:splitwith(fun(L) -> L =/= "[tokens]" end, tl(Useful)),
    {Files, Tokens}.

%% Same transformation as scripts/vendor.sh (and hex's vendor_hex_core.sh).
vendor(Src, Files, Tokens, Prefix, Out) ->
    ok = filelib:ensure_path(Out),
    lists:foreach(
        fun(F) ->
            {ok, Bin} = file:read_file(filename:join(Src, F)),
            New = lists:foldl(
                fun(Tok, Acc) ->
                    binary:replace(Acc, list_to_binary(Tok), list_to_binary(Prefix ++ Tok), [global])
                end,
                Bin,
                Tokens
            ),
            ok = file:write_file(filename:join(Out, Prefix ++ F), New)
        end,
        Files
    ).

compile_one(Dir, File) ->
    case compile:file(File, [binary, return_errors, {i, Dir}]) of
        {ok, Mod, Bin} -> {Mod, Bin};
        {ok, Mod, Bin, _Warnings} -> {Mod, Bin};
        Error -> ct:fail({compile_failed, File, Error})
    end.
