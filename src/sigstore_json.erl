%% @doc JSON decoding behaviour and dispatch (SPEC.md §8.5).
%%
%% Only decoding is pluggable. All JSON *output* is produced by
%% `sigstore_jcs' (deterministic, RFC 8785 sorted keys), which is valid JSON
%% and needs no external codec. Decoding dispatches through the config map:
%%
%% ```
%% #{json_adapter => {Module, AdapterConfig}}
%% '''
%%
%% The default adapter `sigstore_json_otp' uses OTP 27's `json' module when
%% it is loaded and returns `{error, {json, unavailable}}' otherwise, in the
%% same spirit as `mix hex.search'. Hosts on OTP 25/26 can plug any codec by
%% implementing this behaviour, e.g. an Elixir host wrapping Jason:
%%
%% ```
%% defmodule MyApp.SigstoreJason do
%%   @behaviour :sigstore_json
%%   def decode(bin, _cfg), do: Jason.decode(bin)
%% end
%% '''
%%
%% Decoded values must use: maps with binary keys, lists, binaries for
%% strings, integers, floats, `true | false | null'.
-module(sigstore_json).

-export([decode/2, default_adapter/0, strip_nulls/1]).

-export_type([value/0, adapter/0]).

-type value() ::
    #{binary() => value()} | [value()] | binary() | integer() | float() | boolean() | null.
-type adapter() :: {module(), AdapterConfig :: map()}.

-callback decode(binary(), AdapterConfig :: map()) -> {ok, value()} | {error, term()}.

%% @doc Decode `Bin' using the adapter in `Config' (or the default one).
-spec decode(map(), binary()) -> {ok, value()} | {error, {json, term()}}.
decode(Config, Bin) when is_map(Config), is_binary(Bin) ->
    {Mod, AdapterCfg} = maps:get(json_adapter, Config, default_adapter()),
    try Mod:decode(Bin, AdapterCfg) of
        {ok, V} -> {ok, strip_nulls(V)};
        {error, Reason} -> {error, {json, Reason}};
        Other -> {error, {json, {bad_adapter_return, Mod, Other}}}
    catch
        Class:Reason -> {error, {json, {adapter_crashed, Mod, Class, Reason}}}
    end.

%% @doc Proto3 JSON: `null' means "field not set". Remove null-valued object
%% members recursively so parsers only ever see present or absent fields.
-spec strip_nulls(value()) -> value().
strip_nulls(M) when is_map(M) -> maps:fold(fun strip_member/3, #{}, M);
strip_nulls(L) when is_list(L) -> [strip_nulls(V) || V <- L];
strip_nulls(V) -> V.

strip_member(_K, null, Acc) -> Acc;
strip_member(K, V, Acc) -> Acc#{K => strip_nulls(V)}.

-spec default_adapter() -> adapter().
default_adapter() -> {sigstore_json_otp, #{}}.
