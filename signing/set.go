package signing

import (
	"time"
)

// Set is the full key set for a tenant: active, upcoming, and
// not-yet-retired keys for both uses.
type Set struct {
	Keys []Key `json:"keys"`
}

// ActiveFor returns the signing key for a use at time t: the key whose
// validity window covers t, preferring the most recently opened window.
func (s *Set) ActiveFor(t time.Time, use KeyUse) (Key, bool) {
	var (
		best  Key
		found bool
	)

	for _, k := range s.Keys {
		if k.Use != use || !k.ValidAt(t) || len(k.Secret) == 0 {
			continue
		}

		if !found || k.NotBefore.After(best.NotBefore) {
			best = k
			found = true
		}
	}

	return best, found
}

// VerificationKeys returns every key the edge should accept at time t: all
// keys that are not yet past their retention horizon. Upcoming keys are
// included — pre-distribution means the edge knows a key before signers
// start using it.
func (s *Set) VerificationKeys(t time.Time, retention time.Duration) []Key {
	var out []Key

	for _, k := range s.Keys {
		if t.After(k.NotAfter.Add(retention)) || len(k.Secret) == 0 {
			continue
		}

		out = append(out, k)
	}

	return out
}
