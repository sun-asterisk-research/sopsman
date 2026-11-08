// Package testutil provides helpers shared by tests.
package testutil

import (
	"strings"
	"testing"

	"filippo.io/age"
)

// Identity is a generated age key pair.
type Identity struct{ Secret, Recipient string }

// NewIdentity generates an age identity.
func NewIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Secret: id.String(), Recipient: id.Recipient().String()}
}

// UseIdentities makes exactly the given identities available to sops for
// decryption, isolating the test from the user's own keys.
func UseIdentities(t *testing.T, ids ...Identity) {
	t.Helper()
	var s []string
	for _, id := range ids {
		s = append(s, id.Secret)
	}
	t.Setenv("SOPS_AGE_KEY", strings.Join(s, "\n"))
	t.Setenv("SOPS_AGE_KEY_FILE", "/nonexistent")
	t.Setenv("SOPS_AGE_SSH_PRIVATE_KEY_FILE", "/nonexistent")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}
