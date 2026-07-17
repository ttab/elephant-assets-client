// Package assetsclient provides client-side access to the elephant asset
// service: fetching and caching the asset CDN signing keys and delivery
// configuration, and building and signing asset CDN URLs.
//
// Keys are pre-distributed by the asset service — upcoming keys are
// published well before their validity window opens — so a caller that
// keeps a Provider running signs entirely from the in-memory key set,
// with no network calls in the signing path.
package assetsclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/ttab/elephant-assets-client/signing"
	"github.com/ttab/elephant-public-api/assets"
	"github.com/twitchtv/twirp"
)

// ScopeKeysRead is the access token scope that grants the key and
// variant fetch RPCs.
const ScopeKeysRead = "asset_keys_read"

// DefaultRefreshInterval is the default refresh interval. Keys are
// pre-distributed weeks before rotation and variant configuration rarely
// changes, so refreshes are not time-critical.
const DefaultRefreshInterval = 15 * time.Minute

// ProviderOption configures a Provider.
type ProviderOption func(p *Provider)

// WithRefreshInterval sets the background refresh interval used by Run.
func WithRefreshInterval(d time.Duration) ProviderOption {
	return func(p *Provider) {
		p.interval = d
	}
}

// WithLogger sets the logger used for background refresh failures.
func WithLogger(log *slog.Logger) ProviderOption {
	return func(p *Provider) {
		p.log = log
	}
}

// Provider fetches and caches the signing key set and the rendition
// variant configuration from the asset service's Keys RPC. Use Run to
// keep them refreshed in the background, ActiveSigner to get a signer
// for the key that is currently active, and Variant to look up variant
// geometry.
type Provider struct {
	client   assets.Keys
	log      *slog.Logger
	interval time.Duration

	mu       sync.RWMutex
	set      signing.Set
	variants map[string]Variant
}

// NewProvider creates a provider talking to the asset service at
// endpoint. The HTTP client must authenticate the requests (normal
// client credentials with the "asset_keys_read" scope), e.g. an
// oauth2.NewClient wrapping a client credentials token source.
func NewProvider(
	endpoint string, client *http.Client, opts ...ProviderOption,
) *Provider {
	p := Provider{
		client:   assets.NewKeysProtobufClient(endpoint, client),
		log:      slog.New(slog.DiscardHandler),
		interval: DefaultRefreshInterval,
	}

	for _, opt := range opts {
		opt(&p)
	}

	return &p
}

// Refresh fetches the current key set and variant configuration and
// replaces the cached state.
func (p *Provider) Refresh(ctx context.Context) error {
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

	variants, err := p.fetchVariants(ctx)
	if err != nil {
		return err
	}

	p.mu.Lock()
	p.set = set
	p.variants = variants
	p.mu.Unlock()

	return nil
}

// fetchVariants loads the variant configuration. An asset service that
// predates the GetVariants RPC yields an empty map rather than an error,
// so that key fetching (and with it URL signing) keeps working against
// older deployments.
func (p *Provider) fetchVariants(
	ctx context.Context,
) (map[string]Variant, error) {
	res, err := p.client.GetVariants(ctx, &assets.GetVariantsRequest{})

	var twErr twirp.Error

	if errors.As(err, &twErr) && twErr.Code() == twirp.BadRoute {
		p.log.WarnContext(ctx,
			"asset service does not serve variants, no size hints available")

		return map[string]Variant{}, nil
	}

	if err != nil {
		return nil, fmt.Errorf("fetch variants: %w", err)
	}

	variants := make(map[string]Variant, len(res.Variants))

	for _, v := range res.Variants {
		variants[v.Name] = Variant{
			Name:    v.Name,
			Kind:    v.Kind,
			Max:     int(v.Max),
			Width:   int(v.Width),
			Height:  int(v.Height),
			Fit:     v.Fit,
			Public:  v.Public,
			Classes: v.Classes,
		}
	}

	return variants, nil
}

// Run fetches the key set and variant configuration and keeps them
// refreshed until the context is cancelled. The initial fetch is retried
// with backoff; later refresh failures are logged and retried on the
// next interval, since the cached state (which includes pre-distributed
// upcoming keys) stays usable.
func (p *Provider) Run(ctx context.Context) error {
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
func (p *Provider) ActiveSigner(
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

// Variant returns the named rendition variant, or false when it isn't
// configured (or the variant configuration hasn't been fetched).
func (p *Provider) Variant(name string) (Variant, bool) {
	p.mu.RLock()
	v, ok := p.variants[name]
	p.mu.RUnlock()

	return v, ok
}

// Variants returns the configured rendition variants.
func (p *Provider) Variants() []Variant {
	p.mu.RLock()
	defer p.mu.RUnlock()

	list := make([]Variant, 0, len(p.variants))

	for _, v := range p.variants {
		list = append(list, v)
	}

	return list
}
