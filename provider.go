// Package assetsclient provides client-side access to the elephant asset
// service: fetching and caching the asset CDN signing keys, and building
// and signing asset CDN URLs.
//
// Keys are pre-distributed by the asset service — upcoming keys are
// published well before their validity window opens — so a caller that
// keeps a KeyProvider running signs entirely from the in-memory key set,
// with no network calls in the signing path.
package assetsclient

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/ttab/elephant-assets-client/signing"
	"github.com/ttab/elephant-public-api/assets"
)

// ScopeKeysRead is the access token scope that grants the key-fetch RPC.
const ScopeKeysRead = "asset_keys_read"

// DefaultRefreshInterval is the default key refresh interval. Keys are
// pre-distributed weeks before rotation, so refreshes are not
// time-critical.
const DefaultRefreshInterval = 15 * time.Minute

// ProviderOption configures a KeyProvider.
type ProviderOption func(p *KeyProvider)

// WithRefreshInterval sets the background refresh interval used by Run.
func WithRefreshInterval(d time.Duration) ProviderOption {
	return func(p *KeyProvider) {
		p.interval = d
	}
}

// WithLogger sets the logger used for background refresh failures.
func WithLogger(log *slog.Logger) ProviderOption {
	return func(p *KeyProvider) {
		p.log = log
	}
}

// KeyProvider fetches and caches the signing key set from the asset
// service's Keys RPC. Use Run to keep the set refreshed in the
// background, and ActiveSigner to get a signer for the key that is
// currently active.
type KeyProvider struct {
	client   assets.Keys
	log      *slog.Logger
	interval time.Duration

	mu  sync.RWMutex
	set signing.Set
}

// NewKeyProvider creates a key provider talking to the asset service at
// endpoint. The HTTP client must authenticate the requests (normal client
// credentials with the "asset_keys_read" scope), e.g. an oauth2.NewClient
// wrapping a client credentials token source.
func NewKeyProvider(
	endpoint string, client *http.Client, opts ...ProviderOption,
) *KeyProvider {
	p := KeyProvider{
		client:   assets.NewKeysProtobufClient(endpoint, client),
		log:      slog.New(slog.DiscardHandler),
		interval: DefaultRefreshInterval,
	}

	for _, opt := range opts {
		opt(&p)
	}

	return &p
}

// Refresh fetches the current key set and replaces the cached set.
func (p *KeyProvider) Refresh(ctx context.Context) error {
	res, err := p.client.GetSigningKeys(ctx, &assets.GetSigningKeysRequest{})
	if err != nil {
		return fmt.Errorf("fetch signing keys: %w", err)
	}

	set := signing.Set{
		Keys: make([]signing.Key, 0, len(res.Keys)),
	}

	for _, k := range res.Keys {
		secret, err := hex.DecodeString(k.Secret)
		if err != nil {
			return fmt.Errorf("decode secret of key %q: %w",
				k.Kid, err)
		}

		set.Keys = append(set.Keys, signing.Key{
			KID:       k.Kid,
			Secret:    secret,
			NotBefore: time.Unix(k.NotBefore, 0),
			NotAfter:  time.Unix(k.NotAfter, 0),
			Use:       signing.KeyUse(k.Use),
		})
	}

	p.mu.Lock()
	p.set = set
	p.mu.Unlock()

	return nil
}

// Run fetches the key set and keeps it refreshed until the context is
// cancelled. The initial fetch is retried with backoff; later refresh
// failures are logged and retried on the next interval, since the cached
// set (which includes pre-distributed upcoming keys) stays usable.
func (p *KeyProvider) Run(ctx context.Context) error {
	backoff := time.Second

	for {
		err := p.Refresh(ctx)
		if err == nil {
			break
		}

		p.log.WarnContext(ctx, "fetch asset signing keys",
			"err", err,
			"retry_in", backoff)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff = min(2*backoff, time.Minute)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitter(p.interval)):
		}

		err := p.Refresh(ctx)
		if err != nil {
			p.log.WarnContext(ctx, "refresh asset signing keys",
				"err", err)
		}
	}
}

// jitter spreads an interval ±10% so that co-deployed instances don't
// synchronize their refresh calls.
func jitter(d time.Duration) time.Duration {
	spread := d / 5
	if spread <= 0 {
		return d
	}

	//nolint:gosec // G404: refresh jitter is not security-sensitive.
	return d - spread/2 + rand.N(spread)
}

// ActiveSigner returns a signer for the delivery or public key whose
// validity window covers t, or false when the set has no such key (not
// yet fetched, or a key set gap).
func (p *KeyProvider) ActiveSigner(
	t time.Time, use signing.KeyUse,
) (*signing.Signer, bool) {
	p.mu.RLock()
	key, ok := p.set.ActiveFor(t, use)
	p.mu.RUnlock()

	if !ok {
		return nil, false
	}

	return key.Signer(), true
}
