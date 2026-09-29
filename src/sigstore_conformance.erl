%% @doc Escript entrypoint implementing sigstore-conformance's cli_protocol.md
%% (SPEC.md §9). Exit 0 on success, 1 on any failure with the reason on stderr.
-module(sigstore_conformance).

-export([main/1, parse_args/1]).

-type cmd() ::
    {sign_bundle, #{
        staging := boolean(),
        in_toto := boolean(),
        identity_token := binary(),
        bundle := file:name_all(),
        trusted_root => file:name_all(),
        signing_config => file:name_all(),
        file := file:name_all()
    }}
    | {verify_bundle, #{
        staging := boolean(),
        bundle := file:name_all(),
        policy := {identity, binary(), binary()} | {key, file:name_all()},
        trusted_root => file:name_all(),
        input := {file, file:name_all()} | {digest, sha256, binary()}
    }}.

-spec main([string()]) -> no_return().
main(Args) ->
    case parse_args(Args) of
        {ok, Cmd} ->
            case run(Cmd) of
                ok ->
                    halt(0);
                {ok, _} ->
                    halt(0);
                {error, Reason} ->
                    io:format(standard_error, "error: ~0p~n", [Reason]),
                    halt(1)
            end;
        {error, Reason} ->
            io:format(standard_error, "usage error: ~0p~n", [Reason]),
            halt(2)
    end.

-spec run(cmd()) -> ok | {ok, term()} | {error, term()}.
run({sign_bundle, _Opts}) ->
    {error, {sign, not_implemented}};
run({verify_bundle, #{bundle := BundlePath, policy := PolicySpec, input := Input} = Opts}) ->
    Config = sigstore:default_config(),
    TrustOpts =
        case Opts of
            #{trusted_root := TR} -> #{config => Config, trusted_root => {file, TR}};
            #{staging := true} -> #{config => Config, instance => staging};
            #{} -> #{config => Config, instance => production}
        end,
    maybe_chain([
        fun(_) -> sigstore:trusted_root(TrustOpts) end,
        fun(Root) ->
            case load_policy(PolicySpec) of
                {ok, P} -> {ok, {Root, P}};
                E -> E
            end
        end,
        fun({Root, Policy}) ->
            case file:read_file(BundlePath) of
                {ok, Bin} -> {ok, {Root, Policy, Bin}};
                {error, R} -> {error, {bundle, {read, BundlePath, R}}}
            end
        end,
        fun({Root, Policy, Bin}) ->
            sigstore:verify(Input, Bin, #{config => Config, trusted_root => Root, policy => Policy})
        end
    ]).

load_policy({identity, I, U}) ->
    {ok, sigstore_policy:identity(I, U)};
load_policy({key, Path}) ->
    case file:read_file(Path) of
        {ok, Pem} ->
            case sigstore_keys:from_pem(Pem) of
                {ok, K} -> {ok, sigstore_policy:key(K)};
                E -> E
            end;
        {error, R} ->
            {error, {key, {read, Path, R}}}
    end.

maybe_chain(Steps) ->
    lists:foldl(
        fun
            (Step, {ok, Acc}) -> Step(Acc);
            (_Step, Err) -> Err
        end,
        {ok, undefined},
        Steps
    ).

%% Argument parsing is position-tolerant even though the suite guarantees order.
-spec parse_args([string()]) -> {ok, cmd()} | {error, term()}.
parse_args(["sign-bundle" | Rest]) ->
    parse_sign(Rest, #{staging => false, in_toto => false});
parse_args(["verify-bundle" | Rest]) ->
    parse_verify(Rest, #{staging => false});
parse_args(Other) ->
    {error, {unknown_command, Other}}.

parse_sign(["--staging" | R], Acc) ->
    parse_sign(R, Acc#{staging => true});
parse_sign(["--in-toto" | R], Acc) ->
    parse_sign(R, Acc#{in_toto => true});
parse_sign(["--identity-token", T | R], Acc) ->
    parse_sign(R, Acc#{identity_token => list_to_binary(T)});
parse_sign(["--bundle", F | R], Acc) ->
    parse_sign(R, Acc#{bundle => F});
parse_sign(["--trusted-root", F | R], Acc) ->
    parse_sign(R, Acc#{trusted_root => F});
parse_sign(["--signing-config", F | R], Acc) ->
    parse_sign(R, Acc#{signing_config => F});
parse_sign([[$-, $- | _] = Flag | _], _Acc) ->
    {error, {unknown_flag, Flag}};
parse_sign([File], #{identity_token := _, bundle := _} = Acc) ->
    {ok, {sign_bundle, Acc#{file => File}}};
parse_sign([_File], _Acc) ->
    {error, missing_required_flags};
parse_sign(Rest, _Acc) ->
    {error, {bad_positional, Rest}}.

parse_verify(["--staging" | R], Acc) ->
    parse_verify(R, Acc#{staging => true});
parse_verify(["--bundle", F | R], Acc) ->
    parse_verify(R, Acc#{bundle => F});
parse_verify(["--trusted-root", F | R], Acc) ->
    parse_verify(R, Acc#{trusted_root => F});
parse_verify(["--key", F | R], Acc) ->
    parse_verify(R, Acc#{policy => {key, F}});
parse_verify(["--certificate-identity", I | R], Acc) ->
    parse_verify(R, Acc#{identity => list_to_binary(I)});
parse_verify(["--certificate-oidc-issuer", U | R], Acc) ->
    parse_verify(R, Acc#{issuer => list_to_binary(U)});
parse_verify([[$-, $- | _] = Flag | _], _Acc) ->
    {error, {unknown_flag, Flag}};
parse_verify([Input], #{bundle := _} = Acc0) ->
    case policy(Acc0) of
        {ok, Policy} ->
            Acc = maps:without([identity, issuer], Acc0),
            {ok, {verify_bundle, Acc#{policy => Policy, input => input(Input)}}};
        {error, _} = E ->
            E
    end;
parse_verify([_Input], _Acc) ->
    {error, missing_required_flags};
parse_verify(Rest, _Acc) ->
    {error, {bad_positional, Rest}}.

policy(#{policy := {key, _} = K, identity := _}) -> {error, {conflicting_policy, K}};
policy(#{policy := {key, _} = K}) -> {ok, K};
policy(#{identity := I, issuer := U}) -> {ok, {identity, I, U}};
policy(_) -> {error, missing_policy}.

%% "sha256:" + 64 hex, and not an existing path ⇒ digest; otherwise a file path.
-spec input(string()) -> {file, string()} | {digest, sha256, binary()}.
input("sha256:" ++ Hex = S) when length(Hex) =:= 64 ->
    case filelib:is_file(S) of
        true ->
            {file, S};
        false ->
            try
                {digest, sha256, binary:decode_hex(list_to_binary(Hex))}
            catch
                error:_ -> {file, S}
            end
    end;
input(S) ->
    {file, S}.
