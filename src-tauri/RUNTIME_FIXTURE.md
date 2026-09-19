# Isolated desktop runtime fixture

This debug-only configuration connects the real Catmos desktop application to the synthetic local gateway while retaining normal native MLS, protected storage, service authorization and receipts. It does not change production defaults or the user's normal Catmos profile. Client signing keys are generated in the isolated native store; only their public bytes are sent to the gateway's explicitly preseeded native-authority endpoint. This is not proof of native device enrollment.

Build with `local-runtime-fixture` and debug assertions. Release compilation with this feature is forbidden. A fixture binary refuses to start without `CATMOS_RUNTIME_FIXTURE_CONFIG`; it cannot silently open the production profile. The environment variable names a new mode-0600 JSON file:

```json
{
  "manifest": "/absolute/gateway-output/manifest.json",
  "sessions": "/absolute/gateway-output/sessions.json",
  "label": "alice",
  "profile": "/absolute/new-catmos-fixture-profile",
  "keychain_namespace": "blue.catbird.catmos.fixture.00000000-0000-4000-8000-000000000001"
}
```

Use a freshly generated namespace UUID and an isolated profile per account/run. The profile is created mode0700 and marked with the exact gateway/account/device/namespace identity; restart accepts only the same marker. All database, credential, session and native keychain entries use the isolated namespace. No system trust changes or host-file edits are needed. Protected session files must never enter reports, logs or source control.

The native HTTP client preserves HTTPS logical names/SNI and admits only the fixture CA. The manifest maps canonical synthetic fixture hosts and the fixed receipt authority host to explicit loopback sockets. Unknown DNS names, redirects, proxies and public-root trust are disabled in this mode. The gateway's shared `public.api.bsky.app` mapping belongs only to its server relationship fixture and is explicitly excluded from native transport. Files are bounded during reading and symlink/non-private/non-regular inputs are rejected.

The application creates its scoped signing key, posts only the public key to `/fixture/enroll`, and retains the supplied synthetic opaque session in the isolated OS keychain. Main-app session restoration still fetches `/auth/session`, validates current exact own-device identity/key/generation, and admits normal runtime authority. Request generation comes from that current verified binding, never from the manifest or a fixed fixture generation.

Build example (run from catmos):

```sh
CMAKE_POLICY_VERSION_MINIMUM=3.5 npm exec tauri build -- --debug \
  --features local-runtime-fixture --bundles app --no-sign \
  --config '{"productName":"Catmos Request Fixture","identifier":"blue.catbird.catmos.request-fixture","build":{"beforeBuildCommand":"npm exec vite build"}}'
```

Launch the resulting app executable with `CATMOS_RUNTIME_FIXTURE_CONFIG` pointing to the protected configuration. Coordinate the gateway's sole guarded test-database window with its owner. Use the normal main-app request composer and current verified preview/consent flows; local `/dev/request-preview` rendering does not qualify this runtime. Capture conversation/request/message IDs and screenshots without recording session tokens. Gateway recipe: `../mls-ds/e2e-tests/CLIENT_RUNTIME_GATEWAY.md` from the workspace's catmos directory.
