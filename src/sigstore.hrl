%% Media types (client-spec §5).
-define(BUNDLE_V01, <<"application/vnd.dev.sigstore.bundle+json;version=0.1">>).
-define(BUNDLE_V02, <<"application/vnd.dev.sigstore.bundle+json;version=0.2">>).
-define(BUNDLE_V03_LEGACY, <<"application/vnd.dev.sigstore.bundle+json;version=0.3">>).
-define(BUNDLE_V03, <<"application/vnd.dev.sigstore.bundle.v0.3+json">>).

-define(TRUSTED_ROOT_V01_LEGACY, <<"application/vnd.dev.sigstore.trustedroot+json;version=0.1">>).
-define(TRUSTED_ROOT_V01, <<"application/vnd.dev.sigstore.trustedroot.v0.1+json">>).
-define(TRUSTED_ROOT_V02, <<"application/vnd.dev.sigstore.trustedroot.v0.2+json">>).
-define(SIGNING_CONFIG_V02, <<"application/vnd.dev.sigstore.signingconfig.v0.2+json">>).
-define(CLIENT_TRUST_CONFIG_V01, <<"application/vnd.dev.sigstore.clienttrustconfig.v0.1+json">>).

-define(INTOTO_PAYLOAD_TYPE, <<"application/vnd.in-toto+json">>).

%% OIDs.
-define(OID_SCT_LIST, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}).
-define(OID_CT_PRECERT_SIGNING, {1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}).
-define(OID_FULCIO(N), {1, 3, 6, 1, 4, 1, 57264, 1, N}).
-define(OID_KP_CODE_SIGNING, {1, 3, 6, 1, 5, 5, 7, 3, 3}).
-define(OID_KP_TIME_STAMPING, {1, 3, 6, 1, 5, 5, 7, 3, 8}).
