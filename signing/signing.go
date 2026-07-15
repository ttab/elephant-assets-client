// Package signing implements the asset CDN URL token scheme (spec §5): a
// packed dot-separated token whose HMAC covers the canonical path prefix —
// namespace, id, version, and selector — so one token authorizes every
// variant its scope permits for that exact asset version and crop.
//
// The package is the single source of truth for the token format: the
// asset service (key authority and edge-vector generator) and every
// URL-minting service import it from here.
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TokenVersion is the token format version, versioning the claim tuple and
// canonical string independently of the URL contract version.
const TokenVersion = "1"

// ExpNever is the exp value of non-expiring tokens. Only valid for scopes
// naming an access class flagged public in configuration.
const ExpNever = "0"

var (
	segmentPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	audiencePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	// Scopes allow a leading underscore for the reserved
	// _all/_public/_original scopes.
	scopePattern    = regexp.MustCompile(`^[a-z0-9_-]+$`)
	coordPattern    = regexp.MustCompile(`^\d(\.\d+)?$`)
	selectorPattern = regexp.MustCompile(
		`^(full|c(-\d(\.\d+)?){4}|t(-\d+(\.\d{1,3})?){2})$`)
)

// ValidSegment reports whether s is a valid namespace, id, or version path
// segment.
func ValidSegment(s string) bool {
	return segmentPattern.MatchString(s)
}

// ValidSelector reports whether s is a selector the edge grammar accepts:
// the literal "full", an image soft crop "c-{x}-{y}-{w}-{h}", or a
// temporal clip "t-{start}-{end}" (spec §4.1).
func ValidSelector(s string) bool {
	return selectorPattern.MatchString(s)
}

// Crop is a signed content selection for image assets: the full frame or a
// soft crop rectangle.
type Crop struct {
	selector string
}

// FullCrop selects the full frame.
var FullCrop = Crop{selector: "full"}

// SoftCrop builds a crop selection from the document's core/softcrop
// values, verbatim — the package never parses or re-serializes the
// coordinates, since the document string is the canonical form (spec §7.5).
func SoftCrop(x, y, w, h string) (Crop, error) {
	for _, coord := range []string{x, y, w, h} {
		if !coordPattern.MatchString(coord) {
			return Crop{}, fmt.Errorf(
				"coordinate %q does not match the crop grammar",
				coord)
		}
	}

	return Crop{
		selector: "c-" + x + "-" + y + "-" + w + "-" + h,
	}, nil
}

// Selector returns the selector path segment for the crop.
func (c Crop) Selector() string {
	if c.selector == "" {
		return "full"
	}

	return c.selector
}

// Canonical builds the canonical string covered by the MAC (spec §5):
// newline-joined token version, path prefix, expiry, audience, and scope.
func Canonical(prefix string, exp string, aud string, scope string) string {
	return strings.Join([]string{
		TokenVersion, prefix, exp, aud, scope,
	}, "\n")
}

// Prefix builds the signed path prefix, including the trailing slash.
func Prefix(ns, id, version, selector string) string {
	return "/v1/" + ns + "/" + id + "/" + version + "/" + selector + "/"
}

// MAC computes the token MAC for a canonical string: base64url without
// padding of HMAC-SHA256.
func MAC(key []byte, canonical string) string {
	mac := hmac.New(sha256.New, key)

	_, _ = mac.Write([]byte(canonical))

	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Signer mints tokens with a specific key.
type Signer struct {
	kid string
	key []byte
}

func NewSigner(kid string, key []byte) *Signer {
	return &Signer{kid: kid, key: key}
}

// SignImageURL mints a token authorizing the variants of one image version
// and crop for an audience and scope. A zero exp mints a non-expiring
// token, which the edge only accepts for scopes naming a public access
// class. The returned token goes in the `s` query parameter, and the
// caller appends `{variant}.{ext}` to the signed prefix.
func (s *Signer) SignImageURL(
	ns, id, version string, crop Crop, aud, scope string, exp time.Time,
) (string, error) {
	expStr := ExpNever
	if !exp.IsZero() {
		expStr = strconv.FormatInt(exp.Unix(), 10)
	}

	return s.SignPrefix(Prefix(ns, id, version, crop.Selector()),
		aud, scope, expStr)
}

// SignPrefix mints a token for an already-built path prefix. Most callers
// want SignImageURL.
func (s *Signer) SignPrefix(
	prefix string, aud string, scope string, exp string,
) (string, error) {
	err := validatePrefix(prefix)
	if err != nil {
		return "", err
	}

	if !audiencePattern.MatchString(aud) {
		return "", fmt.Errorf("invalid audience %q", aud)
	}

	if !scopePattern.MatchString(scope) {
		return "", fmt.Errorf("invalid scope %q", scope)
	}

	if exp != ExpNever {
		_, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid expiry %q", exp)
		}
	}

	mac := MAC(s.key, Canonical(prefix, exp, aud, scope))

	return strings.Join([]string{
		TokenVersion, s.kid, exp, aud, scope, mac,
	}, "."), nil
}

func validatePrefix(prefix string) error {
	rest, ok := strings.CutPrefix(prefix, "/v1/")
	if !ok {
		return fmt.Errorf("prefix %q does not start with /v1/", prefix)
	}

	rest, ok = strings.CutSuffix(rest, "/")
	if !ok {
		return fmt.Errorf("prefix %q does not end with a slash", prefix)
	}

	parts := strings.Split(rest, "/")
	if len(parts) != 4 {
		return fmt.Errorf(
			"prefix %q must have namespace, id, version, and selector segments",
			prefix)
	}

	for _, part := range parts[:3] {
		if !segmentPattern.MatchString(part) {
			return fmt.Errorf("invalid path segment %q", part)
		}
	}

	return nil
}
