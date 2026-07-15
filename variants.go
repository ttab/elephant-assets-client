package assetsclient

import (
	"math"
	"strconv"
	"strings"
)

// VariantOriginal is the reserved variant name addressing the source
// asset itself: the full source for the "full" selector, or the crop
// region at native resolution for a crop selector. It is part of the URL
// contract rather than the configured variant set, and its rendition
// size is the selector region's own dimensions (SelectorSize).
const VariantOriginal = "original"

// Variant is a configured rendition variant, as served by the asset
// service's GetVariants RPC. The asset service owns variant geometry;
// URL-minting services use it to know which variants exist and to
// compute rendition size hints.
type Variant struct {
	// Name of the variant, used as the variant path segment.
	Name string
	// Kind is the asset kind the variant applies to, e.g. "image".
	Kind string
	// Max is the bounding box in pixels (longest side) for image
	// variants.
	Max int
	// Fit controls how an image is fitted to the bounding box. Only
	// "inside" is defined: scale down to fit, never upscale.
	Fit string
	// Public marks the variant as a public derivative: reachable by any
	// valid signature and usable with non-expiring (exp=0) tokens.
	Public bool
	// Scopes are the named scopes that grant access to the variant.
	Scopes []string
	// Classes are the class names available as a {variant}-{class}
	// suffix, e.g. "wm" makes {variant}-wm a public watermarked
	// rendition.
	Classes []string
}

// FitSize computes the pixel size of the variant rendition for an asset
// with the given source dimensions: scaled to fit inside the variant's
// bounding box, never upscaled. Returns false when the source dimensions
// or the variant bounding box are unknown.
func (v Variant) FitSize(srcWidth, srcHeight int) (int, int, bool) {
	if srcWidth < 1 || srcHeight < 1 || v.Max < 1 {
		return 0, 0, false
	}

	longest := max(srcWidth, srcHeight)
	if longest <= v.Max {
		return srcWidth, srcHeight, true
	}

	factor := float64(v.Max) / float64(longest)

	width := int(math.Round(float64(srcWidth) * factor))
	height := int(math.Round(float64(srcHeight) * factor))

	return width, height, true
}

// SelectorSize computes the source dimensions of a content selection:
// the full frame for "full", or the crop region for a soft crop
// selector, using the same inward pixel rounding as the asset service's
// image transformer. Returns false for other selectors, invalid crop
// rects, or unknown source dimensions.
func SelectorSize(selector string, srcWidth, srcHeight int) (int, int, bool) {
	if srcWidth < 1 || srcHeight < 1 {
		return 0, 0, false
	}

	if selector == "full" {
		return srcWidth, srcHeight, true
	}

	parts := strings.Split(selector, "-")
	if len(parts) != 5 || parts[0] != "c" {
		return 0, 0, false
	}

	coords := make([]float64, 4)

	for i, part := range parts[1:] {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, 0, false
		}

		coords[i] = v
	}

	x, y, w, h := coords[0], coords[1], coords[2], coords[3]

	if x < 0 || y < 0 || w <= 0 || h <= 0 || x+w > 1 || y+h > 1 {
		return 0, 0, false
	}

	// Inward pixel rounding, mirroring the transformer: the rect always
	// shrinks to whole pixels inside it.
	left := int(math.Ceil(x * float64(srcWidth)))
	top := int(math.Ceil(y * float64(srcHeight)))
	right := int(math.Floor((x + w) * float64(srcWidth)))
	bottom := int(math.Floor((y + h) * float64(srcHeight)))

	if right-left < 1 || bottom-top < 1 {
		return 0, 0, false
	}

	return right - left, bottom - top, true
}
