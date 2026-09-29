%% @doc Minimal in-toto Statement handling for verification: parse the
%% statement and match the artifact against its subjects. Predicate
%% semantics (SLSA etc.) are a higher layer (SPEC.md §12).
-module(sigstore_intoto).

-export([parse/2, subject_matches/2]).

-define(STATEMENT_TYPES, [
    <<"https://in-toto.io/Statement/v1">>, <<"https://in-toto.io/Statement/v0.1">>
]).

-spec parse(sigstore:config(), binary()) -> {ok, map()} | {error, {intoto, term()}}.
parse(Config, Payload) ->
    case sigstore_json:decode(Config, Payload) of
        {ok, #{<<"_type">> := T, <<"subject">> := [_ | _]} = S} ->
            case lists:member(T, ?STATEMENT_TYPES) of
                true -> {ok, S};
                false -> {error, {intoto, {unknown_statement_type, T}}}
            end;
        {ok, _} ->
            {error, {intoto, not_a_statement}};
        {error, R} ->
            {error, {intoto, R}}
    end.

%% @doc Does any subject carry `sha256' equal to `Digest'?
-spec subject_matches(map(), binary()) -> boolean().
subject_matches(#{<<"subject">> := Subjects}, Digest) ->
    Hex = sigstore_b64:hex_encode(Digest),
    lists:any(
        fun
            (#{<<"digest">> := #{<<"sha256">> := H}}) when is_binary(H) ->
                string:lowercase(H) =:= Hex;
            (_) ->
                false
        end,
        Subjects
    ).
