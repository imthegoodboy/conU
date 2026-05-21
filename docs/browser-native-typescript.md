# Browser-Native TypeScript Boundary

The current `@conu/sdk` package is a Node.js wrapper around installed native
`conu`, `conud`, and `conu-mcp` binaries. It is useful for local Node-based
agents, Electron main processes, build scripts, and controlled server-side
automation. It is not a browser-native protocol implementation.

## Current Package Behavior

- Normal Node.js imports use `sdk/typescript/src/index.js`.
- Browser-conditioned imports use `sdk/typescript/src/browser.js`.
- The browser entry exports `browserSupport.supported = false`.
- Constructing `ConuClient` from the browser entry throws
  `BrowserUnsupportedError`.
- The browser entry does not accept relay tokens, private keys, payload bytes,
  peer cards, endpoints, or account credentials.

This makes accidental browser bundling fail closed without leaking payloads,
tokens, keys, or endpoints into JavaScript logs, URLs, source maps, local
storage, or crash reports.

## Future Browser-Native SDK Requirements

A future browser-native TypeScript package must be separate from the Node
wrapper unless the package name and exports make the transport boundary obvious.
It must not shell out to local binaries, read local `CONU_HOME` state, or ask a
browser page to handle node private keys or relay credential tokens.

The future design needs a hosted account and relay credential model first:

- Browser clients should authenticate through short-lived, audience-scoped
  hosted credentials, not long-lived relay tokens embedded in application code.
- Private node signing, exchange, and storage keys should remain in the local
  runtime, a platform key store, a hardware-backed key, or a reviewed WebCrypto
  design with explicit export restrictions.
- Payload bytes must stay out of URLs, query strings, browser logs, telemetry,
  and exception messages.
- Receive APIs must preserve conU's explicit addressed-agent receive boundary:
  metadata by default, payload bytes only when an addressed recipient explicitly
  requests them.
- Browser transport should use certificate-validated `wss://` or a future
  authenticated direct transport; it must not weaken peer-card trust, peer
  policy, room topic policy, replay protection, or relay blindness.

## Naming And Versioning

Until those requirements are implemented, `@conu/sdk` should describe itself as
a Node.js wrapper. A browser-native package should use a distinct export or
package name, such as `@conu/browser-sdk`, and should not imply compatibility
with the local-binary wrapper.

## Verification

Run:

```sh
npm run check --prefix sdk/typescript
```

The package check verifies the Node wrapper syntax, the browser stub syntax, the
stdin-only payload behavior, the metadata-only receive default, explicit
addressed-agent payload receive, and the fail-closed browser boundary.

