%% @doc DSSE pre-authentication encoding (DSSE v1 spec).
-module(sigstore_dsse).

-export([pae/2]).

-spec pae(binary(), binary()) -> binary().
pae(Type, Payload) ->
    iolist_to_binary([
        <<"DSSEv1 ">>,
        integer_to_binary(byte_size(Type)),
        $\s,
        Type,
        $\s,
        integer_to_binary(byte_size(Payload)),
        $\s,
        Payload
    ]).
