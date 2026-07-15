package signing

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// KeyUse separates delivery keys (routinely rotated) from public keys
// (rotated rarely and deliberately — doing so invalidates every permanent
// public URL in circulation, spec §8).
type KeyUse string

const (
	KeyUseDelivery KeyUse = "delivery"
	KeyUsePublic   KeyUse = "public"
)

// Key is a signing key with an explicit validity window. Signers select
// the key whose window covers now; the edge accepts every key it has been
// given (retired keys are removed from the edge store 45 days after their
// window closes).
type Key struct {
	KID       string    `json:"kid"`
	Secret    Secret    `json:"secret"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Use       KeyUse    `json:"use"`
}

// Secret is raw key material, JSON-encoded as base64url.
type Secret []byte

func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(s)) //nolint:wrapcheck
}

func (s *Secret) UnmarshalJSON(data []byte) error {
	var encoded string

	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err //nolint:wrapcheck
	}

	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode secret: %w", err)
	}

	*s = decoded

	return nil
}

// Hex returns the hex encoding of the secret, the format used in the edge
// key store.
func (s Secret) Hex() string {
	return hex.EncodeToString(s)
}

// GenerateKey creates a key with 32 bytes of random material.
func GenerateKey(
	kid string, use KeyUse, notBefore time.Time, notAfter time.Time,
) (Key, error) {
	secret := make([]byte, 32)

	_, err := rand.Read(secret)
	if err != nil {
		return Key{}, fmt.Errorf("generate key material: %w", err)
	}

	return Key{
		KID:       kid,
		Secret:    secret,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Use:       use,
	}, nil
}

// ValidAt reports whether the key's validity window covers t.
func (k Key) ValidAt(t time.Time) bool {
	return !t.Before(k.NotBefore) && t.Before(k.NotAfter)
}

// Signer returns a Signer using this key.
func (k Key) Signer() *Signer {
	return NewSigner(k.KID, k.Secret)
}
