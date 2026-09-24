-module(sct_probe).
-export([main/1]).
-include_lib("public_key/include/public_key.hrl").

-define(SCT_OID, {1,3,6,1,4,1,11129,2,4,2}).

main([BundleFile, TRFile]) ->
    {ok, BJ} = file:read_file(BundleFile),
    B = json:decode(BJ),
    LeafDer = base64:decode(maps:get(<<"rawBytes">>, maps:get(<<"certificate">>, maps:get(<<"verificationMaterial">>, B)))),
    {ok, TRJ} = file:read_file(TRFile),
    TR = json:decode(TRJ),
    %% --- 1. pure round-trip fidelity of TBSCertificate ---
    Plain = public_key:pkix_decode_cert(LeafDer, plain),
    TBS = Plain#'Certificate'.tbsCertificate,
    OrigTbsDer = orig_tbs_der(LeafDer),
    ReTbsDer = public_key:pkix_encode('TBSCertificate', TBS, plain),
    io:format("TBS round-trip byte-identical: ~p (~p vs ~p bytes)~n",
              [OrigTbsDer =:= ReTbsDer, byte_size(OrigTbsDer), byte_size(ReTbsDer)]),
    %% --- 2. strip SCT extension, re-encode ---
    Exts = TBS#'TBSCertificate'.extensions,
    {[SctExt], Rest} = lists:partition(fun(#'Extension'{extnID = O}) -> O =:= ?SCT_OID end, Exts),
    TBS2 = TBS#'TBSCertificate'{extensions = Rest},
    PreTbs = public_key:pkix_encode('TBSCertificate', TBS2, plain),
    io:format("precert TBS: ~p bytes (~p exts -> ~p)~n", [byte_size(PreTbs), length(Exts), length(Rest)]),
    %% --- 3. parse SCT list ---
    ExtVal0 = SctExt#'Extension'.extnValue,
    ExtVal = case ExtVal0 of <<4, _/binary>> -> {_, V} = der_tlv(ExtVal0), V; _ -> ExtVal0 end,
    <<_ListLen:16, ListBody/binary>> = ExtVal,
    Scts = parse_list(ListBody),
    io:format("SCTs in leaf: ~p~n", [length(Scts)]),
    %% --- 4. issuer key hash: issuer is intermediate from trusted root ---
    CAs = maps:get(<<"certificateAuthorities">>, TR),
    Issuers = [base64:decode(maps:get(<<"rawBytes">>, C)) || CA <- CAs, C <- maps:get(<<"certificates">>, maps:get(<<"certChain">>, CA))],
    CtKeys = [{base64:decode(maps:get(<<"keyId">>, maps:get(<<"logId">>, L))), base64:decode(maps:get(<<"rawBytes">>, maps:get(<<"publicKey">>, L)))} || L <- maps:get(<<"ctlogs">>, TR)],
    lists:foreach(fun(Sct) -> verify_sct(Sct, PreTbs, Issuers, CtKeys) end, Scts),
    halt().

verify_sct(<<0, LogId:32/binary, Ts:64, ExtLen:16, Ext:ExtLen/binary, _HashAlg, _SigAlg, SigLen:16, Sig:SigLen/binary>>, PreTbs, Issuers, CtKeys) ->
    io:format("SCT logId=~s ts=~p~n", [binary:encode_hex(LogId), Ts]),
    case lists:keyfind(LogId, 1, CtKeys) of
        false -> io:format("  no CT key with that logId~n");
        {_, Spki} ->
            Key = public_key:der_decode('SubjectPublicKeyInfo', Spki),
            PubKey = spki_to_key(Key),
            Results = [begin
                IKH = crypto:hash(sha256, issuer_spki_der(IssDer)),
                Signed = <<0, 0, Ts:64, 1:16, IKH/binary, (byte_size(PreTbs)):24, PreTbs/binary, ExtLen:16, Ext/binary>>,
                public_key:verify(Signed, sha256, Sig, PubKey)
            end || IssDer <- Issuers],
            io:format("  SCT signature verifies with some trusted-root issuer: ~p  (per-issuer: ~p)~n", [lists:member(true, Results), Results])
    end.

spki_to_key(#'SubjectPublicKeyInfo'{algorithm = #'AlgorithmIdentifier'{algorithm = ?'id-ecPublicKey', parameters = ParamsDer}, subjectPublicKey = Point}) ->
    {#'ECPoint'{point = Point}, ParamsDer}.

issuer_spki_der(CertDer) ->
    #'Certificate'{tbsCertificate = #'TBSCertificate'{subjectPublicKeyInfo = Spki}} = public_key:pkix_decode_cert(CertDer, plain),
    public_key:der_encode('SubjectPublicKeyInfo', Spki).

parse_list(<<>>) -> [];
parse_list(<<L:16, Sct:L/binary, Rest/binary>>) -> [Sct | parse_list(Rest)].

%% DER helpers
der_tlv(<<Tag, Bin/binary>>) ->
    {Len, Body} = der_len(Bin),
    <<V:Len/binary, _/binary>> = Body,
    {Tag, V}.
der_len(<<0:1, L:7, R/binary>>) -> {L, R};
der_len(<<1:1, N:7, R/binary>>) -> <<L:(N*8), R2/binary>> = R, {L, R2}.
der_hdr_len(<<_, 0:1, _:7, _/binary>>) -> 2;
der_hdr_len(<<_, 1:1, N:7, _/binary>>) -> 2 + N.

orig_tbs_der(CertDer) ->
    %% Certificate SEQUENCE { tbs SEQUENCE ... }
    H = der_hdr_len(CertDer), <<_:H/binary, Inner/binary>> = CertDer,
    {_, TbsBody} = der_tlv(Inner),
    H2 = der_hdr_len(Inner),
    <<Tbs:(H2 + byte_size(TbsBody))/binary, _/binary>> = Inner, Tbs.

%% Remove one Extension TLV from TBS by locating its DER encoding, fixing up lengths of extensions SEQ, [3] wrapper, TBS SEQ.
splice_out_ext(TbsDer, Ext) ->
    ExtDer = element(2, 'OTP-PKIX':encode('Extension', Ext)),
    {Pos, Len} = binary:match(TbsDer, ExtDer),
    <<Before:Pos/binary, _:Len/binary, After/binary>> = TbsDer,
    Body = <<Before/binary, After/binary>>,
    %% naive: re-encode lengths by re-parsing structure. Do it generically: rebuild TBS from its children.
    rebuild_lengths(Body, Len).

%% Recompute lengths of the three enclosing constructed TLVs (TBS SEQ, [3] EXPLICIT, Extensions SEQ) by decreasing each by Len.
rebuild_lengths(Bin, Delta) ->
    {TbsBody, TbsRest} = strip_tlv_body(Bin),         % TBS SEQUENCE
    %% find [3] extensions wrapper: last child of TBS
    Children = children(TbsBody),
    {Init, [ExtWrap]} = lists:split(length(Children) - 1, Children),
    {WrapBody, <<>>} = strip_tlv_body(ExtWrap),
    {ExtsSeqBody, <<>>} = strip_tlv_body(WrapBody),
    NewExtsSeq = tlv(16#30, ExtsSeqBody),
    NewWrap = tlv(16#A3, NewExtsSeq),
    NewTbsBody = iolist_to_binary(Init ++ [NewWrap]),
    _ = Delta, _ = TbsRest,
    tlv(16#30, NewTbsBody).

strip_tlv_body(<<_Tag, Bin/binary>>) ->
    {Len, Body} = der_len(Bin),
    <<V:Len/binary, Rest/binary>> = Body,
    {V, Rest}.
children(<<>>) -> [];
children(Bin) ->
    H = der_hdr_len(Bin),
    {Len, _} = der_len(binary:part(Bin, 1, byte_size(Bin) - 1)),
    <<Child:(H + Len)/binary, Rest/binary>> = Bin,
    [Child | children(Rest)].
tlv(Tag, Body) ->
    L = byte_size(Body),
    LenEnc = if L < 128 -> <<L>>; L < 256 -> <<16#81, L>>; L < 65536 -> <<16#82, L:16>>; true -> <<16#83, L:24>> end,
    <<Tag, LenEnc/binary, Body/binary>>.
