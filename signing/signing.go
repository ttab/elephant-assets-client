// Package signing implements the asset CDN URL token scheme (spec §5): a
// packed dot-separated token whose HMAC covers the full request path, so a
// token authorizes exactly one rendition of one asset version and crop —
// access control is the minting decision itself.
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

// ExpNever is the exp value of non-expiring tokens. Only valid for public
// renditions, signed with a public-use key.
const ExpNever = "0"

var (
	segmentPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	audiencePattern = regexp.MustCompile(`^[a-z0-9-]+$`)
	coordPattern    = regexp.MustCompile(`^\d(\.\d+)?$`)
	selectorPattern = regexp.MustCompile(
		`^(full|c(-\d(\.\d+)?){4}((-\d(\.\d+)?){2})?|t(-\d+(\.\d{1,3})?){2})$`)
	variantPattern = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9]+)?$`)
)

// ValidSegment reports whether s is a valid namespace, id, or version path
// segment.
func ValidSegment(s string) bool {
	return segmentPattern.MatchString(s)
}

// ValidSelector reports whether s is a selector the edge grammar accepts:
// the literal "full", an image soft crop "c-{x}-{y}-{w}-{h}" optionally
// carrying a focus point "c-{x}-{y}-{w}-{h}-{fx}-{fy}", or a temporal clip
// "t-{start}-{end}" (spec §4.1).
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

// WithFocus returns the crop extended with the document's core/softcrop
// focus point, verbatim like SoftCrop. The focus anchors the aspect window
// of fit:cover variants; it is a hint and grants nothing beyond the crop
// bounds. Only valid on soft crops.
func (c Crop) WithFocus(fx, fy string) (Crop, error) {
	if !strings.HasPrefix(c.selector, "c-") || strings.Count(c.selector, "-") != 4 {
		return Crop{}, fmt.Errorf(
			"focus points only apply to focus-free soft crops")
	}

	for _, coord := range []string{fx, fy} {
		if !coordPattern.MatchString(coord) {
			return Crop{}, fmt.Errorf(
				"coordinate %q does not match the crop grammar",
				coord)
		}
	}

	return Crop{
		selector: c.selector + "-" + fx + "-" + fy,
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
// newline-joined token version, request path, expiry, and audience.
func Canonical(path string, exp string, aud string) string {
	return strings.Join([]string{
		TokenVersion, path, exp, aud,
	}, "\n")
}

// Path builds the signed request path. An empty ext omits the extension
// (the "original" variant has none).
func Path(ns, id, version, selector, variant, ext string) string {
	path := "/v1/" + ns + "/" + id + "/" + version + "/" + selector +
		"/" + variant

	if ext != "" {
		path += "." + ext
	}

	return path
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

// SignImageURL mints a token authorizing one rendition of one image
// version and crop for an audience. variant names the rendition including
// any class suffix, and ext the format ("large-wm", "jpg"); the original
// is variant "original" with an empty ext. A zero exp mints a
// non-expiring token, which the edge only accepts for public renditions
// under a public-use key. The returned token goes in the `s` query
// parameter of the exact URL that was signed.
func (s *Signer) SignImageURL(
	ns, id, version string, crop Crop, variant, ext, aud string,
	exp time.Time,
) (string, error) {
	expStr := ExpNever
	if !exp.IsZero() {
		expStr = strconv.FormatInt(exp.Unix(), 10)
	}

	return s.SignPath(Path(ns, id, version, crop.Selector(), variant, ext),
		aud, expStr)
}

// SignPath mints a token for an already-built request path. Most callers
// want SignImageURL.
func (s *Signer) SignPath(
	path string, aud string, exp string,
) (string, error) {
	err := validatePath(path)
	if err != nil {
		return "", err
	}

	if !audiencePattern.MatchString(aud) {
		return "", fmt.Errorf("invalid audience %q", aud)
	}

	if exp != ExpNever {
		_, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid expiry %q", exp)
		}
	}

	mac := MAC(s.key, Canonical(path, exp, aud))

	return strings.Join([]string{
		TokenVersion, s.kid, exp, aud, mac,
	}, "."), nil
}

func validatePath(path string) error {
	rest, ok := strings.CutPrefix(path, "/v1/")
	if !ok {
		return fmt.Errorf("path %q does not start with /v1/", path)
	}

	parts := strings.Split(rest, "/")
	if len(parts) != 5 {
		return fmt.Errorf(
			"path %q must have namespace, id, version, selector, and variant segments",
			path)
	}

	for _, part := range parts[:3] {
		if !segmentPattern.MatchString(part) {
			return fmt.Errorf("invalid path segment %q", part)
		}
	}

	if !selectorPattern.MatchString(parts[3]) {
		return fmt.Errorf("invalid selector %q", parts[3])
	}

	if !variantPattern.MatchString(parts[4]) {
		return fmt.Errorf("invalid variant segment %q", parts[4])
	}

	return nil
}
