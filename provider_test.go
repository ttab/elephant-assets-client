package assetsclient_test

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	assetsclient "github.com/ttab/elephant-assets-client"
	"github.com/ttab/elephant-assets-client/signing"
	"github.com/ttab/elephant-public-api/assets"
)

// keysService is a static Keys RPC implementation.
type keysService struct {
	keys     []*assets.SigningKey
	variants []*assets.Variant
}

func (s *keysService) GetSigningKeys(
	_ context.Context, _ *assets.GetSigningKeysRequest,
) (*assets.GetSigningKeysResponse, error) {
	return &assets.GetSigningKeysResponse{Keys: s.keys}, nil
}

func (s *keysService) GetVariants(
	_ context.Context, _ *assets.GetVariantsRequest,
) (*assets.GetVariantsResponse, error) {
	return &assets.GetVariantsResponse{Variants: s.variants}, nil
}

func TestKeyProviderRefresh(t *testing.T) {
	now := time.Now()

	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	service := keysService{
		keys: []*assets.SigningKey{
			{
				Kid:       "2026a",
				Secret:    hex.EncodeToString(secret),
				NotBefore: now.Add(-time.Hour).Unix(),
				NotAfter:  now.Add(24 * time.Hour).Unix(),
				Use:       "delivery",
			},
			{
				Kid:       "2026b",
				Secret:    hex.EncodeToString(secret),
				NotBefore: now.Add(24 * time.Hour).Unix(),
				NotAfter:  now.Add(48 * time.Hour).Unix(),
				Use:       "delivery",
			},
			{
				Kid:       "pub2026a",
				Secret:    hex.EncodeToString(secret),
				NotBefore: now.Add(-time.Hour).Unix(),
				NotAfter:  now.Add(24 * time.Hour).Unix(),
				Use:       "public",
			},
		},
		variants: []*assets.Variant{
			{
				Name: "preview", Kind: "image", Max: 800,
				Fit: "inside", Classes: []string{"web"},
			},
			{
				Name: "thumbnail", Kind: "image", Max: 256,
				Fit: "inside", Classes: []string{"web"},
			},
		},
	}

	server := httptest.NewServer(assets.NewKeysServer(&service))
	defer server.Close()

	provider := assetsclient.NewProvider(server.URL, http.DefaultClient)

	_, ok := provider.ActiveSigner(now, signing.KeyUseDelivery)
	if ok {
		t.Fatal("expected no signer before the first refresh")
	}

	err := provider.Refresh(t.Context())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}

	signer, ok := provider.ActiveSigner(now, signing.KeyUseDelivery)
	if !ok {
		t.Fatal("expected an active delivery signer")
	}

	token, err := signer.SignPrefix(
		"/v1/mm/abc/0/full/", "acme", "web", "1800000000")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	want, err := signing.NewSigner("2026a", secret).SignPrefix(
		"/v1/mm/abc/0/full/", "acme", "web", "1800000000")
	if err != nil {
		t.Fatalf("sign reference: %v", err)
	}

	if token != want {
		t.Error("provider signer does not match the served key")
	}

	// The upcoming key is selected once its window opens.
	future, ok := provider.ActiveSigner(
		now.Add(25*time.Hour), signing.KeyUseDelivery)
	if !ok {
		t.Fatal("expected the upcoming key to become active")
	}

	futureToken, err := future.SignPrefix(
		"/v1/mm/abc/0/full/", "acme", "web", "1800000000")
	if err != nil {
		t.Fatalf("sign with upcoming key: %v", err)
	}

	if futureToken == token {
		t.Error("expected the upcoming key to sign with its own kid")
	}

	_, ok = provider.ActiveSigner(now, signing.KeyUsePublic)
	if !ok {
		t.Error("expected an active public signer")
	}

	preview, ok := provider.Variant("preview")
	if !ok {
		t.Fatal("expected the preview variant to be cached")
	}

	if preview.Max != 800 || preview.Kind != "image" {
		t.Errorf("unexpected variant: %+v", preview)
	}

	_, ok = provider.Variant("nosuch")
	if ok {
		t.Error("did not expect an unconfigured variant")
	}

	if len(provider.Variants()) != 2 {
		t.Errorf("expected 2 variants, got %d", len(provider.Variants()))
	}
}

func TestVariantFitSize(t *testing.T) {
	preview := assetsclient.Variant{Name: "preview", Kind: "image", Max: 800}

	cases := map[string]struct {
		srcW, srcH int
		w, h       int
		ok         bool
	}{
		"landscape":      {1024, 707, 800, 552, true},
		"portrait":       {707, 1024, 552, 800, true},
		"never upscale":  {400, 300, 400, 300, true},
		"exact fit":      {800, 600, 800, 600, true},
		"unknown source": {0, 0, 0, 0, false},
	}

	for name, c := range cases {
		w, h, ok := preview.FitSize(c.srcW, c.srcH)
		if w != c.w || h != c.h || ok != c.ok {
			t.Errorf("%s: got (%d, %d, %v), want (%d, %d, %v)",
				name, w, h, ok, c.w, c.h, c.ok)
		}
	}

	noBox := assetsclient.Variant{Name: "original", Kind: "data"}

	_, _, ok := noBox.FitSize(1024, 707)
	if ok {
		t.Error("expected no size for a variant without a bounding box")
	}
}

func TestSelectorSize(t *testing.T) {
	cases := map[string]struct {
		selector   string
		srcW, srcH int
		w, h       int
		ok         bool
	}{
		"full":           {"full", 1024, 707, 1024, 707, true},
		"half crop":      {"c-0.2-0.2-0.5-0.5", 100, 100, 50, 50, true},
		"inward rounded": {"c-0.198-0.198-0.495-0.495", 100, 100, 49, 49, true},
		"outside unit":   {"c-0.8-0.8-0.5-0.5", 100, 100, 0, 0, false},
		"temporal clip":  {"t-0-30", 100, 100, 0, 0, false},
		"unknown source": {"full", 0, 0, 0, 0, false},
		"collapsing":     {"c-0.5-0.5-0.001-0.001", 100, 100, 0, 0, false},
	}

	for name, c := range cases {
		w, h, ok := assetsclient.SelectorSize(c.selector, c.srcW, c.srcH)
		if w != c.w || h != c.h || ok != c.ok {
			t.Errorf("%s: got (%d, %d, %v), want (%d, %d, %v)",
				name, w, h, ok, c.w, c.h, c.ok)
		}
	}
}

func TestKeyProviderBadSecret(t *testing.T) {
	service := keysService{
		keys: []*assets.SigningKey{
			{Kid: "2026a", Secret: "not-hex", Use: "delivery"},
		},
	}

	server := httptest.NewServer(assets.NewKeysServer(&service))
	defer server.Close()

	provider := assetsclient.NewProvider(server.URL, http.DefaultClient)

	err := provider.Refresh(t.Context())
	if err == nil {
		t.Fatal("expected a decode error")
	}
}
