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
	keys []*assets.SigningKey
}

func (s *keysService) GetSigningKeys(
	_ context.Context, _ *assets.GetSigningKeysRequest,
) (*assets.GetSigningKeysResponse, error) {
	return &assets.GetSigningKeysResponse{Keys: s.keys}, nil
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
	}

	server := httptest.NewServer(assets.NewKeysServer(&service))
	defer server.Close()

	provider := assetsclient.NewKeyProvider(server.URL, http.DefaultClient)

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
}

func TestKeyProviderBadSecret(t *testing.T) {
	service := keysService{
		keys: []*assets.SigningKey{
			{Kid: "2026a", Secret: "not-hex", Use: "delivery"},
		},
	}

	server := httptest.NewServer(assets.NewKeysServer(&service))
	defer server.Close()

	provider := assetsclient.NewKeyProvider(server.URL, http.DefaultClient)

	err := provider.Refresh(t.Context())
	if err == nil {
		t.Fatal("expected a decode error")
	}
}
