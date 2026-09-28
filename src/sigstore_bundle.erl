%% @doc Sigstore bundle model (SPEC.md §5.1): parse, structurally validate,
%% and emit the proto3-JSON form for media types v0.1–v0.3.
-module(sigstore_bundle).

-include("sigstore.hrl").

-export([from_json/2, media_type/1, version/1]).

-export_type([t/0, version/0]).

%% JSON-shaped map with binary keys; bytes fields decoded, int64 fields as integers.
-type t() :: #{binary() => term()}.
-type version() :: v0_1 | v0_2 | v0_3.

-spec from_json(sigstore:config(), binary()) -> {ok, t()} | {error, {bundle, term()}}.
from_json(Config, Bin) ->
    case sigstore_json:decode(Config, Bin) of
        {ok, #{<<"mediaType">> := MT} = Map} ->
            case version(MT) of
                {ok, _} -> {ok, Map};
                {error, _} = E -> E
            end;
        {ok, _} ->
            {error, {bundle, missing_media_type}};
        {error, Reason} ->
            {error, {bundle, {malformed_json, Reason}}}
    end.

-spec media_type(t()) -> binary().
media_type(#{<<"mediaType">> := MT}) -> MT.

-spec version(binary()) -> {ok, version()} | {error, {bundle, {unknown_media_type, binary()}}}.
version(?BUNDLE_V01) -> {ok, v0_1};
version(?BUNDLE_V02) -> {ok, v0_2};
version(?BUNDLE_V03) -> {ok, v0_3};
version(?BUNDLE_V03_LEGACY) -> {ok, v0_3};
version(Other) when is_binary(Other) -> {error, {bundle, {unknown_media_type, Other}}}.
