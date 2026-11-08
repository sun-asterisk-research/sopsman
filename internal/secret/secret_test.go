package secret

import (
	"errors"
	"strings"
	"testing"

	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/sun-asterisk-research/sopsman/internal/config"
	"github.com/sun-asterisk-research/sopsman/internal/testutil"
)

type identity = testutil.Identity

func newIdentity(t *testing.T) identity { return testutil.NewIdentity(t) }

func useIdentities(t *testing.T, ids ...identity) { testutil.UseIdentities(t, ids...) }

var svcs = []keyservice.KeyServiceClient{keyservice.NewLocalClient()}

func encrypt(t *testing.T, f formats.Format, plain string, existing []byte, recipients ...identity) *Result {
	t.Helper()
	var ages []string
	for _, r := range recipients {
		ages = append(ages, r.Recipient)
	}
	ks, err := BuildKeys(map[string][]string{"age": ages})
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Format: f, Plain: []byte(plain), Keys: ks, Services: svcs}
	if existing != nil {
		file, err := Load(f, existing)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Decrypt(svcs); err != nil {
			t.Fatal(err)
		}
		req.Existing = file
	}
	res, err := Encrypt(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func decrypt(t *testing.T, f formats.Format, enc []byte) string {
	t.Helper()
	file, err := Load(f, enc)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := file.Decrypt(svcs)
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// changedLines returns the lines of b that do not appear at the same index in a.
func changedLines(a, b []byte) []string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	var out []string
	for i, l := range bl {
		if i >= len(al) || al[i] != l {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return out
}

const yamlPlain = `# database settings
db:
  user: admin
  password: hunter2
  port: 5432
  tls: true
api_key: abc123
`

func TestEncryptRoundTripAndUnchanged(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)

	res := encrypt(t, formats.Yaml, yamlPlain, nil, alice)
	if res.Action != Created {
		t.Fatalf("action = %s, want created", res.Action)
	}
	if got := decrypt(t, formats.Yaml, res.Output); got != yamlPlain {
		t.Fatalf("round trip mismatch:\n%s", got)
	}

	// Same content, reformatted: no rewrite.
	reformatted := strings.ReplaceAll(yamlPlain, "  ", "    ")
	again := encrypt(t, formats.Yaml, reformatted, res.Output, alice)
	if again.Action != Unchanged || again.Output != nil {
		t.Fatalf("action = %s, want unchanged", again.Action)
	}
}

func TestEncryptMinimalDiffOnValueChange(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)

	first := encrypt(t, formats.Yaml, yamlPlain, nil, alice).Output
	edited := strings.Replace(yamlPlain, "hunter2", "s3cret", 1)
	res := encrypt(t, formats.Yaml, edited, first, alice)
	if res.Action != Updated {
		t.Fatalf("action = %s, want updated", res.Action)
	}
	// Only the edited value, the MAC and (unless within the same second)
	// lastmodified may change.
	changed := changedLines(first, res.Output)
	var sawValue, sawMac bool
	for _, l := range changed {
		switch {
		case strings.HasPrefix(l, "password: ENC["):
			sawValue = true
		case strings.HasPrefix(l, "mac: ENC["):
			sawMac = true
		case strings.HasPrefix(l, "lastmodified:"):
		default:
			t.Errorf("unexpected changed line: %q", l)
		}
	}
	if !sawValue || !sawMac {
		t.Fatalf("expected the value and mac to change, got:\n%s", strings.Join(changed, "\n"))
	}
	if got := decrypt(t, formats.Yaml, res.Output); got != edited {
		t.Fatalf("decrypted mismatch:\n%s", got)
	}
}

func TestEncryptAddRecipientKeepsDataKey(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	useIdentities(t, alice)

	first := encrypt(t, formats.Yaml, yamlPlain, nil, alice).Output
	res := encrypt(t, formats.Yaml, yamlPlain, first, alice, bob)
	if res.Action != Rekeyed || len(res.Added) != 1 {
		t.Fatalf("action = %s added = %v, want rekeyed with one addition", res.Action, res.Added)
	}
	// Every original line survives; only bob's stanza is new.
	for _, line := range strings.Split(string(first), "\n") {
		if !strings.Contains(string(res.Output), line) {
			t.Errorf("line lost after adding a recipient: %q", line)
		}
	}
	if !strings.Contains(string(res.Output), bob.Recipient) {
		t.Fatal("bob's stanza missing")
	}
	useIdentities(t, bob)
	if got := decrypt(t, formats.Yaml, res.Output); got != yamlPlain {
		t.Fatalf("bob cannot decrypt:\n%s", got)
	}
}

func TestEncryptRemoveRecipientRotatesDataKey(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	useIdentities(t, alice)

	first := encrypt(t, formats.Yaml, yamlPlain, nil, alice, bob).Output
	res := encrypt(t, formats.Yaml, yamlPlain, first, alice)
	if res.Action != Rotated || len(res.Removed) != 1 {
		t.Fatalf("action = %s removed = %v, want rotated with one removal", res.Action, res.Removed)
	}
	if strings.Contains(string(res.Output), bob.Recipient) {
		t.Fatal("bob still listed after removal")
	}
	if strings.Contains(string(res.Output), strings.Split(strings.Split(string(first), "password: ")[1], "\n")[0]) {
		t.Fatal("ciphertext reused after data key rotation")
	}
	useIdentities(t, bob)
	file, _ := Load(formats.Yaml, res.Output)
	var noKey *NoKeyError
	if _, err := file.Decrypt(svcs); !errors.As(err, &noKey) {
		t.Fatalf("bob decrypt err = %v, want NoKeyError", err)
	}
}

func TestEncryptOptionsChange(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)
	ks, _ := BuildKeys(map[string][]string{"age": {alice.Recipient}})

	first := encrypt(t, formats.Yaml, yamlPlain, nil, alice).Output
	file, _ := Load(formats.Yaml, first)
	if _, err := file.Decrypt(svcs); err != nil {
		t.Fatal(err)
	}
	res, err := Encrypt(Request{
		Format: formats.Yaml, Plain: []byte(yamlPlain), Existing: file, Keys: ks, Services: svcs,
		Options: config.Options{EncryptedRegex: "^password$"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != Updated {
		t.Fatalf("action = %s, want updated", res.Action)
	}
	if !strings.Contains(string(res.Output), "api_key: abc123") {
		t.Fatalf("api_key should be left in cleartext:\n%s", res.Output)
	}
}

func TestFormats(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)
	cases := map[formats.Format]string{
		formats.Json:   "{\n  \"a\": \"b\",\n  \"n\": 1\n}\n",
		formats.Dotenv: "A=b\nTOKEN=xyz\n",
		formats.Ini:    "[s]\nkey = value\n",
		formats.Binary: "user:$apr1$hash\nno trailing newline",
	}
	for f, plain := range cases {
		res := encrypt(t, f, plain, nil, alice)
		if got := decrypt(t, f, res.Output); got != plain {
			t.Errorf("format %d: round trip got %q want %q", f, got, plain)
		}
		if again := encrypt(t, f, plain, res.Output, alice); again.Action != Unchanged {
			t.Errorf("format %d: second encrypt action = %s, want unchanged", f, again.Action)
		}
	}
}

func TestEncryptRejectsAlreadyEncrypted(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)
	enc := encrypt(t, formats.Yaml, yamlPlain, nil, alice).Output
	ks, _ := BuildKeys(map[string][]string{"age": {alice.Recipient}})
	if _, err := Encrypt(Request{Format: formats.Yaml, Plain: enc, Keys: ks, Services: svcs}); err == nil {
		t.Fatal("expected an error encrypting an already encrypted file")
	}
}

func TestDuplicateListValuesKeepDistinctCiphertext(t *testing.T) {
	alice, bob := newIdentity(t), newIdentity(t)
	useIdentities(t, alice)
	const plain = "items:\n  - version: v1\n  - version: v1\n  - version: v1\n"

	first := encrypt(t, formats.Yaml, plain, nil, alice).Output
	assertDistinct := func(out []byte) {
		t.Helper()
		seen := map[string]bool{}
		for _, l := range strings.Split(string(out), "\n") {
			if strings.Contains(l, "version: ENC[") {
				if seen[l] {
					t.Fatalf("duplicate ciphertext reveals equal values:\n%s", out)
				}
				seen[l] = true
			}
		}
	}
	assertDistinct(first)

	rekeyed := encrypt(t, formats.Yaml, plain, first, alice, bob)
	if rekeyed.Action != Rekeyed {
		t.Fatalf("action = %s, want rekeyed", rekeyed.Action)
	}
	assertDistinct(rekeyed.Output)
	for _, l := range strings.Split(string(first), "\n") {
		if strings.Contains(l, "version: ENC[") && !strings.Contains(string(rekeyed.Output), l) {
			t.Errorf("ciphertext not kept after adding a recipient: %q", l)
		}
	}

	grown := encrypt(t, formats.Yaml, plain+"  - version: v1\n", rekeyed.Output, alice, bob)
	assertDistinct(grown.Output)
}

// sops decryption moves inline comments onto their own line; a plaintext that
// still has them inline must not count as changed.
func TestInlineCommentsDoNotCountAsChange(t *testing.T) {
	alice := newIdentity(t)
	useIdentities(t, alice)
	const plain = "auth:\n  secret: x # rotated yearly\n  enabled: true\n"
	first := encrypt(t, formats.Yaml, plain, nil, alice)
	if !strings.Contains(string(first.Output), "secret: ENC[") || !strings.Contains(string(first.Output), "type:str] #ENC[") {
		t.Fatalf("inline comment not kept inline in the encrypted file:\n%s", first.Output)
	}
	if again := encrypt(t, formats.Yaml, plain, first.Output, alice); again.Action != Unchanged {
		t.Fatalf("action = %s, want unchanged", again.Action)
	}
}
