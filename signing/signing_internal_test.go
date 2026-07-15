package signing

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

const (
	testNS    = "repo"
	testAud   = "acme"
	testScope = "web"
)

func TestSignImageURL(t *testing.T) {
	signer := NewSigner("2026a", testKey)

	exp := time.Unix(1800000000, 0)

	token, err := signer.SignImageURL(
		testNS, "0a1b2c3d", "4", FullCrop, testAud, testScope, exp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 6 {
		t.Fatalf("expected 6 token fields, got %d: %q", len(parts), token)
	}

	if parts[0] != "1" || parts[1] != "2026a" ||
		parts[2] != "1800000000" || parts[3] != testAud ||
		parts[4] != testScope {
		t.Errorf("unexpected token fields: %q", token)
	}

	want := MAC(testKey, Canonical(
		"/v1/repo/0a1b2c3d/4/full/", "1800000000", testAud, testScope))
	if parts[5] != want {
		t.Errorf("MAC mismatch: got %q, want %q", parts[5], want)
	}
}

func TestSignImageURLNonExpiring(t *testing.T) {
	signer := NewSigner("pub2026a", testKey)

	token, err := signer.SignImageURL(
		"mm", "abc", "0", FullCrop, "public", "wm", time.Time{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if !strings.HasPrefix(token, "1.pub2026a.0.public.wm.") {
		t.Errorf("expected exp=0 token, got %q", token)
	}
}

func TestSoftCropSelector(t *testing.T) {
	crop, err := SoftCrop("0.2", "0.2", "0.5", "0.5")
	if err != nil {
		t.Fatalf("soft crop: %v", err)
	}

	if crop.Selector() != "c-0.2-0.2-0.5-0.5" {
		t.Errorf("got selector %q", crop.Selector())
	}

	// Verbatim: a differently-spelled but numerically equal value must
	// produce a different selector, because the document string is the
	// canonical form.
	crop2, err := SoftCrop("0.20", "0.2", "0.5", "0.5")
	if err != nil {
		t.Fatalf("soft crop: %v", err)
	}

	if crop2.Selector() == crop.Selector() {
		t.Error("expected verbatim coordinates to be preserved")
	}

	for _, bad := range [][4]string{
		{"-0.2", "0", "1", "1"},
		{"0,2", "0", "1", "1"},
		{"", "0", "1", "1"},
		{"10.5", "0", "1", "1"}, // two integer digits
	} {
		_, err := SoftCrop(bad[0], bad[1], bad[2], bad[3])
		if err == nil {
			t.Errorf("expected %v to be rejected", bad)
		}
	}
}

func TestSignValidation(t *testing.T) {
	signer := NewSigner("2026a", testKey)

	exp := time.Unix(1800000000, 0)

	cases := map[string][5]string{
		"bad audience":  {testNS, "id", "1", "ACME", testScope},
		"empty scope":   {testNS, "id", "1", testAud, ""},
		"bad id":        {testNS, "id/../x", "1", testAud, testScope},
		"empty version": {testNS, "id", "", testAud, testScope},
	}

	for name, c := range cases {
		_, err := signer.SignImageURL(
			c[0], c[1], c[2], FullCrop, c[3], c[4], exp)
		if err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestKeyRoundtrip(t *testing.T) {
	key, err := GenerateKey("2026a", KeyUseDelivery,
		time.Unix(1800000000, 0), time.Unix(1810000000, 0))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(key.Secret) != 32 {
		t.Fatalf("expected 32 byte secret, got %d", len(key.Secret))
	}

	// Serializing key material is this type's purpose; the test asserts
	// the round trip with a generated throwaway key.
	data, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back Key

	err = json.Unmarshal(data, &back)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if string(back.Secret) != string(key.Secret) || back.KID != key.KID {
		t.Error("key did not survive a JSON round trip")
	}

	if key.ValidAt(time.Unix(1799999999, 0)) {
		t.Error("key valid before not_before")
	}

	if !key.ValidAt(time.Unix(1800000000, 0)) {
		t.Error("key not valid at not_before")
	}

	if key.ValidAt(time.Unix(1810000000, 0)) {
		t.Error("key valid at not_after")
	}
}
