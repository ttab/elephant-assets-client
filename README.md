# elephant-assets-client

Client library for the elephant asset CDN: signing-key handling and URL
signing for URL-minting services.

The asset CDN serves signed URLs of the shape

```
{base URL}/v1/{ns}/{id}/{version}/{selector}/{variant}.{ext}?s={token}
```

where the token is an HMAC over the asset path prefix up to and including
the selector — one token authorizes every variant its scope permits for
that exact asset version and selection. See the asset CDN specification
in the elephant-assets repository for the full contract.

The host is arbitrary — the client makes no assumptions about the CDN's
domain structure. The asset path always sits at the root of the host:
the base URL is just scheme, host, and optional port, and only the
`/v1/…` path is part of the signed contract.

## Packages

- `signing` — the token scheme itself: canonical string, MAC, `Signer`,
  crop selectors, and the signing `Key`/`Set` types. This package is the
  single source of truth for the token format; the asset service imports
  it from here and validates it against the shared edge test vectors.
- `assetsclient` (module root) — the service-facing client:
  - `KeyProvider` fetches the signing key set from the asset service's
    `Keys.GetSigningKeys` RPC (client credentials with the
    `asset_keys_read` scope), caches it in memory, and refreshes it in
    the background. Keys are pre-distributed, so signing never waits on
    the network.
  - `BuildURL` composes unsigned asset CDN URLs from address variables,
    validated against the edge grammar.
  - `URLSigner`/`SignSession` mint delivery tokens for unsigned URLs,
    reusing tokens across variants that share a signed prefix.

## Usage

```go
provider := assetsclient.NewKeyProvider(endpoint, authClient)
go provider.Run(ctx)

signer := assetsclient.URLSigner{
	Keys:  provider,
	Scope: "web",
	TTL:   24 * time.Hour,
}

sess, err := signer.NewSession("customer-slug")
// ...
signed, err := sess.SignURL(unsignedURL)
```
