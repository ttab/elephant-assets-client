package assetsclient_test

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	assetsclient "github.com/ttab/elephant-assets-client"
	"github.com/ttab/elephant-assets-client/signing"
)

func TestBuildURL(t *testing.T) {
	got, err := assetsclient.BuildURL(
		"https://assets.example.com", "mm", "sdl9U4BhXDxe2w", "0",
		"full", "preview", "jpg")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	want := "https://assets.example.com/v1/mm/sdl9U4BhXDxe2w/0/full/preview.jpg"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildURLTrailingSlashAndNoExt(t *testing.T) {
	got, err := assetsclient.BuildURL(
		"https://assets.example.com/", "repo", "0a1b2c3d", "4",
		"c-0.2-0.2-0.5-0.5", "original", "")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	want := "https://assets.example.com/v1/repo/0a1b2c3d/4/c-0.2-0.2-0.5-0.5/original"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildURLArbitraryHost(t *testing.T) {
	// The host is arbitrary; the asset path sits at its root.
	got, err := assetsclient.BuildURL(
		"https://cdn-77.example.net:8443", "mm", "abc",
		"0", "full", "preview", "jpg")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	want := "https://cdn-77.example.net:8443/v1/mm/abc/0/full/preview.jpg"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildURLValidation(t *testing.T) {
	cases := map[string][7]string{
		"relative base":    {"assets.example.com", "mm", "a", "0", "full", "preview", "jpg"},
		"empty ns":         {"https://a.example.com", "", "a", "0", "full", "preview", "jpg"},
		"traversal id":     {"https://a.example.com", "mm", "a/../b", "0", "full", "preview", "jpg"},
		"bad selector":     {"https://a.example.com", "mm", "a", "0", "x-1-2", "preview", "jpg"},
		"uppercase":        {"https://a.example.com", "mm", "a", "0", "full", "Preview", "jpg"},
		"bad ext":          {"https://a.example.com", "mm", "a", "0", "full", "preview", "j.pg"},
		"empty variant":    {"https://a.example.com", "mm", "a", "0", "full", "", "jpg"},
		"selector charset": {"https://a.example.com", "mm", "a", "0", "c-0,2-0-1-1", "preview", "jpg"},
		"path in base":     {"https://a.example.com/base", "mm", "a", "0", "full", "preview", "jpg"},
		"query in base":    {"https://a.example.com/?x=y", "mm", "a", "0", "full", "preview", "jpg"},
		"fragment in base": {"https://a.example.com/#frag", "mm", "a", "0", "full", "preview", "jpg"},
	}

	for name, c := range cases {
		_, err := assetsclient.BuildURL(c[0], c[1], c[2], c[3], c[4], c[5], c[6])
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// staticKeys is a KeysSource with a fixed key.
type staticKeys struct {
	key signing.Key
}

func (s staticKeys) ActiveSigner(
	t time.Time, use signing.KeyUse,
) (*signing.Signer, bool) {
	if s.key.Use != use || !s.key.ValidAt(t) {
		return nil, false
	}

	return s.key.Signer(), true
}

func testDeliveryKey(t *testing.T) signing.Key {
	t.Helper()

	key, err := signing.GenerateKey("2026a", signing.KeyUseDelivery,
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return key
}

func TestURLSignerSignURL(t *testing.T) {
	key := testDeliveryKey(t)

	signer := assetsclient.URLSigner{
		Keys:  staticKeys{key: key},
		Scope: "web",
		TTL:   time.Hour,
	}

	signed, err := signer.SignURL(
		"https://assets.example.com/v1/mm/abc123/0/full/preview.jpg",
		"acme")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}

	token := u.Query().Get("s")
	if token == "" {
		t.Fatal("expected an s query parameter")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 6 {
		t.Fatalf("expected 6 token fields, got %d: %q", len(parts), token)
	}

	// Recompute the MAC with the raw key to verify the token contents.
	want, err := key.Signer().SignPrefix(
		"/v1/mm/abc123/0/full/", "acme", "web", parts[2])
	if err != nil {
		t.Fatalf("sign reference token: %v", err)
	}

	if token != want {
		t.Errorf("token mismatch:\ngot  %q\nwant %q", token, want)
	}
}

func TestSignSessionSharedTokens(t *testing.T) {
	signer := assetsclient.URLSigner{
		Keys:  staticKeys{key: testDeliveryKey(t)},
		Scope: "web",
		TTL:   time.Hour,
	}

	sess, err := signer.NewSession("acme")
	if err != nil {
		t.Fatalf("new session: %v", err)
	}

	sign := func(rawURL string) string {
		t.Helper()

		signed, err := sess.SignURL(rawURL)
		if err != nil {
			t.Fatalf("sign %q: %v", rawURL, err)
		}

		u, err := url.Parse(signed)
		if err != nil {
			t.Fatalf("parse %q: %v", signed, err)
		}

		return u.Query().Get("s")
	}

	base := "https://assets.example.com/v1/mm/abc123/0"

	preview := sign(base + "/full/preview.jpg")
	thumb := sign(base + "/full/thumbnail.webp")
	cropped := sign(base + "/c-0.2-0.2-0.5-0.5/preview.jpg")

	if preview != thumb {
		t.Error("variants of one prefix should share a token")
	}

	if preview == cropped {
		t.Error("different selectors must have different tokens")
	}

	// The host plays no part in the signed prefix: the same asset path
	// served through another CDN host signs identically.
	moved := sign("https://cdn-77.example.net/v1/mm/abc123/0/full/preview.jpg")

	if moved != preview {
		t.Error("the signed prefix must be host independent")
	}
}

func TestURLSignerErrors(t *testing.T) {
	signer := assetsclient.URLSigner{
		Keys:  staticKeys{key: testDeliveryKey(t)},
		Scope: "web",
	}

	_, err := signer.SignURL(
		"https://assets.example.com/v1/mm/abc123/0/full/preview.jpg",
		"Bad Audience")
	if err == nil {
		t.Error("expected an invalid audience error")
	}

	_, err = signer.SignURL("https://example.com/some/other/path.jpg", "acme")
	if err == nil {
		t.Error("expected a path shape error")
	}

	expired := signing.Key{
		KID:       "2020a",
		Secret:    make([]byte, 32),
		NotBefore: time.Unix(0, 0),
		NotAfter:  time.Unix(1, 0),
		Use:       signing.KeyUseDelivery,
	}

	noKey := assetsclient.URLSigner{
		Keys:  staticKeys{key: expired},
		Scope: "web",
	}

	_, err = noKey.SignURL(
		"https://assets.example.com/v1/mm/abc123/0/full/preview.jpg",
		"acme")
	if !errors.Is(err, assetsclient.ErrNoActiveKey) {
		t.Errorf("expected ErrNoActiveKey, got %v", err)
	}
}

func testPublicKey(t *testing.T) signing.Key {
	t.Helper()

	key, err := signing.GenerateKey("pub2026a", signing.KeyUsePublic,
		time.Now().Add(-time.Hour), time.Now().Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatalf("generate public key: %v", err)
	}

	return key
}

func TestPublicSignerSignsNonExpiring(t *testing.T) {
	key := testPublicKey(t)

	signer := assetsclient.PublicSigner{Keys: staticKeys{key: key}}

	signed, err := signer.SignURL(
		"https://assets.example.com/v1/repo/abc123/0/full/large-wm.jpg",
		"public")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	token := mustToken(t, signed)

	parts := strings.Split(token, ".")
	if len(parts) != 6 {
		t.Fatalf("expected 6 token fields, got %d: %q", len(parts), token)
	}

	// Non-expiring and public-tier scope.
	if parts[2] != signing.ExpNever {
		t.Errorf("expected exp=%q, got %q", signing.ExpNever, parts[2])
	}

	if parts[4] != assetsclient.ScopePublic {
		t.Errorf("expected scope %q, got %q", assetsclient.ScopePublic, parts[4])
	}

	// Signed with the public key.
	want, err := key.Signer().SignPrefix(
		"/v1/repo/abc123/0/full/", "public", assetsclient.ScopePublic,
		signing.ExpNever)
	if err != nil {
		t.Fatalf("reference token: %v", err)
	}

	if token != want {
		t.Errorf("token mismatch:\ngot  %q\nwant %q", token, want)
	}
}

func TestPublicSignerNeedsPublicKey(t *testing.T) {
	// Only a delivery key available: the public signer must refuse.
	signer := assetsclient.PublicSigner{Keys: staticKeys{key: testDeliveryKey(t)}}

	_, err := signer.SignURL(
		"https://assets.example.com/v1/repo/abc123/0/full/large-wm.jpg",
		"public")
	if !errors.Is(err, assetsclient.ErrNoPublicKey) {
		t.Fatalf("expected ErrNoPublicKey, got: %v", err)
	}
}

func mustToken(t *testing.T, signed string) string {
	t.Helper()

	u, err := url.Parse(signed)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}

	token := u.Query().Get("s")
	if token == "" {
		t.Fatal("expected an s query parameter")
	}

	return token
}
