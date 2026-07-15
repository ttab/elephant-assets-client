package assetsclient

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ttab/elephant-assets-client/signing"
)

var (
	variantPattern  = regexp.MustCompile(`^[a-z0-9-]+$`)
	extPattern      = regexp.MustCompile(`^[a-z0-9]+$`)
	audiencePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// BuildURL composes an unsigned asset CDN URL from its address variables:
//
//	{baseURL}/v1/{ns}/{id}/{version}/{selector}/{variant}.{ext}
//
// The base URL names an arbitrary host — scheme, host, and optional port,
// nothing else — since the URL contract puts the asset path at the root
// of whatever host serves the CDN. An empty ext omits the extension (the
// "original" variant has none). The segments are validated against the
// edge grammar so that a URL that builds is also one the edge will parse.
func BuildURL(
	baseURL, ns, id, version, selector, variant, ext string,
) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}

	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("base URL %q must be absolute", baseURL)
	}

	if strings.Trim(base.Path, "/") != "" ||
		base.RawQuery != "" || base.Fragment != "" {
		return "", fmt.Errorf(
			"base URL %q must not have a path, query, or fragment",
			baseURL)
	}

	for _, seg := range []struct {
		name  string
		value string
	}{
		{"namespace", ns},
		{"id", id},
		{"version", version},
	} {
		if !signing.ValidSegment(seg.value) {
			return "", fmt.Errorf("invalid %s segment %q",
				seg.name, seg.value)
		}
	}

	if !signing.ValidSelector(selector) {
		return "", fmt.Errorf("invalid selector %q", selector)
	}

	if !variantPattern.MatchString(variant) {
		return "", fmt.Errorf("invalid variant %q", variant)
	}

	if ext != "" && !extPattern.MatchString(ext) {
		return "", fmt.Errorf("invalid extension %q", ext)
	}

	file := variant
	if ext != "" {
		file += "." + ext
	}

	return strings.TrimSuffix(base.String(), "/") +
		signing.Prefix(ns, id, version, selector) + file, nil
}

// ErrNoActiveKey is returned when the key source has no active delivery
// key: the initial key fetch hasn't completed yet, or the key set has a
// coverage gap.
var ErrNoActiveKey = errors.New("no active delivery key")

// ErrNoPublicKey is returned when the key source has no active public key.
var ErrNoPublicKey = errors.New("no active public key")

// ScopePublic is the scope carried by public (non-expiring) tokens. Public
// renditions are reachable by any valid signature, so it grants nothing
// beyond what the exp=0 rule already allows; it labels the public tier in
// the edge's access logs.
const ScopePublic = "_public"

// KeysSource provides active signing keys. *KeyProvider implements it;
// tests can substitute a static source.
type KeysSource interface {
	ActiveSigner(t time.Time, use signing.KeyUse) (*signing.Signer, bool)
}

// URLSigner mints delivery tokens for asset CDN URLs.
type URLSigner struct {
	// Keys provides the active delivery key.
	Keys KeysSource
	// Scope is the access-class scope claim of minted tokens, e.g. "web".
	Scope string
	// TTL is the token lifetime. It must stay under the edge's 30-day
	// cap; a zero TTL defaults to 24 hours.
	TTL time.Duration
}

// DefaultTokenTTL is the token lifetime used when URLSigner.TTL is zero.
const DefaultTokenTTL = 24 * time.Hour

// SignURL signs a single asset CDN URL for an audience. When signing many
// URLs for the same audience — variants of one asset share a token — use
// NewSession to reuse tokens across calls.
func (s *URLSigner) SignURL(rawURL, aud string) (string, error) {
	sess, err := s.NewSession(aud)
	if err != nil {
		return "", err
	}

	return sess.SignURL(rawURL)
}

// NewSession prepares signing for one audience with a fixed expiry.
// Tokens cover the path prefix up to and including the selector, so all
// variants and formats of one asset share a token; the session caches
// them per prefix. A session is not safe for concurrent use.
func (s *URLSigner) NewSession(aud string) (*SignSession, error) {
	if !audiencePattern.MatchString(aud) {
		return nil, fmt.Errorf("invalid audience %q", aud)
	}

	now := time.Now()

	signer, ok := s.Keys.ActiveSigner(now, signing.KeyUseDelivery)
	if !ok {
		return nil, ErrNoActiveKey
	}

	ttl := s.TTL
	if ttl == 0 {
		ttl = DefaultTokenTTL
	}

	return &SignSession{
		signer: signer,
		aud:    aud,
		scope:  s.Scope,
		exp:    strconv.FormatInt(now.Add(ttl).Unix(), 10),
		tokens: make(map[string]string),
	}, nil
}

// SignSession signs URLs for one audience with a shared expiry, reusing
// tokens across URLs that share a signed prefix.
type SignSession struct {
	signer *signing.Signer
	aud    string
	scope  string
	exp    string
	tokens map[string]string
}

// SignURL parses an unsigned asset CDN URL, signs its path prefix, and
// returns the URL with the token in the `s` query parameter. The host is
// opaque, but the URL path must be the asset path
// `/v1/{ns}/{id}/{version}/{selector}/{variant}.{ext}` — the URL
// contract puts it at the root of whatever host serves the CDN.
func (s *SignSession) SignURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}

	cut := strings.LastIndex(u.Path, "/")
	if cut == -1 || cut == len(u.Path)-1 {
		return "", fmt.Errorf(
			"URL path %q does not end in a variant segment", u.Path)
	}

	// The prefix shape, /v1/ at the root included, is validated by
	// SignPrefix.
	prefix := u.Path[:cut+1]

	token, ok := s.tokens[prefix]
	if !ok {
		minted, err := s.signer.SignPrefix(prefix, s.aud, s.scope, s.exp)
		if err != nil {
			return "", fmt.Errorf("sign prefix: %w", err)
		}

		s.tokens[prefix] = minted
		token = minted
	}

	query := u.Query()
	query.Set("s", token)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

// PublicSigner mints permanent (non-expiring, exp=0) tokens for public
// asset renditions, signed with the public key. The edge serves such a
// token only for variants the asset service marks public (thumbnails, the
// -wm watermarked forms); any other variant is rejected. Because the
// tokens never expire, the URLs can be cached, embedded, or shared
// indefinitely — a leaked one only ever yields a public rendition.
//
// The public key is rotated rarely and deliberately (rotating it
// invalidates every permanent URL in circulation), so these URLs are
// stable across ordinary delivery-key rotation.
type PublicSigner struct {
	// Keys provides the active public key.
	Keys KeysSource
}

// SignURL signs a single public asset CDN URL for an audience. Use
// NewSession when signing many URLs for one audience.
func (s *PublicSigner) SignURL(rawURL, aud string) (string, error) {
	sess, err := s.NewSession(aud)
	if err != nil {
		return "", err
	}

	return sess.SignURL(rawURL)
}

// NewSession prepares public signing for one audience. Tokens are
// non-expiring and carry the _public scope; the session caches them per
// signed prefix like the delivery session. Not safe for concurrent use.
func (s *PublicSigner) NewSession(aud string) (*SignSession, error) {
	if !audiencePattern.MatchString(aud) {
		return nil, fmt.Errorf("invalid audience %q", aud)
	}

	signer, ok := s.Keys.ActiveSigner(time.Now(), signing.KeyUsePublic)
	if !ok {
		return nil, ErrNoPublicKey
	}

	return &SignSession{
		signer: signer,
		aud:    aud,
		scope:  ScopePublic,
		exp:    signing.ExpNever,
		tokens: make(map[string]string),
	}, nil
}
