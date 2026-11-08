package files

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/getsops/sops/v3/cmd/sops/formats"

	"github.com/sun-asterisk-research/sopsman/internal/config"
)

func TestEncAndPlainPath(t *testing.T) {
	cases := map[string]string{
		"a/secret.yaml":     "a/secret.enc.yaml",
		"secret.env":        "secret.enc.env",
		"a/.env":            "a/.enc.env",
		"a/htpasswd":        "a/htpasswd.enc",
		"a/b.c/values.json": "a/b.c/values.enc.json",
		"x.tar.gz":          "x.tar.enc.gz",
	}
	for plain, enc := range cases {
		if got := EncPath(plain); got != enc {
			t.Errorf("EncPath(%q) = %q, want %q", plain, got, enc)
		}
		if got, ok := PlainPath(enc); !ok || got != plain {
			t.Errorf("PlainPath(%q) = %q, %v, want %q", enc, got, ok, plain)
		}
	}
	for _, notEnc := range []string{"a/secret.yaml", "a/x.yaml.enc", "a/.enc", "a/y.enc.tar.gz"} {
		if _, ok := PlainPath(notEnc); ok {
			t.Errorf("%q reported as encrypted", notEnc)
		}
	}
}

func TestFormat(t *testing.T) {
	cases := map[string]formats.Format{
		"a.yaml": formats.Yaml, "a.yml": formats.Yaml, "a.json": formats.Json,
		"a.env": formats.Dotenv, "a.ini": formats.Ini, "a.tfvars": formats.Binary, "htpasswd": formats.Binary,
	}
	for p, want := range cases {
		if got := (Entry{Plain: p}).Format(); got != want {
			t.Errorf("format(%q) = %v, want %v", p, got, want)
		}
	}
}

func touch(t *testing.T, root string, paths ...string) {
	t.Helper()
	for _, p := range paths {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiscoverAndFilter(t *testing.T) {
	root := t.TempDir()
	touch(t, root,
		"apps/prod/secret.yaml",      // plaintext only
		"apps/prod/values.enc.yaml",  // encrypted only
		"apps/prod/other.yaml",       // not matched
		"apps/stg/secret.env",        // matched by both rules: first wins
		"apps/stg/secret.enc.env",    // same entry as above
		".git/apps/prod/secret.yaml", // ignored
		"tg/clusters/x/terraform.enc.tfvars",
		"exact/secret.enc.yaml", // only the encrypted file exists
		"sopsman.yml",           // the config itself is never managed
	)
	rules := []config.Rule{
		{Files: []string{"apps/**/{secret,values}*.*"}},
		{Files: []string{"apps/stg/*", "tg/**/*.tfvars", "exact/secret.yaml", "*.yml"}},
	}
	got, err := Discover(root, rules, "sopsman.yml")
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{Plain: "apps/prod/secret.yaml", Enc: "apps/prod/secret.enc.yaml", Rule: 0},
		{Plain: "apps/prod/values.yaml", Enc: "apps/prod/values.enc.yaml", Rule: 0},
		{Plain: "apps/stg/secret.env", Enc: "apps/stg/secret.enc.env", Rule: 0},
		{Plain: "exact/secret.yaml", Enc: "exact/secret.enc.yaml", Rule: 1},
		{Plain: "tg/clusters/x/terraform.tfvars", Enc: "tg/clusters/x/terraform.enc.tfvars", Rule: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}

	filtered, err := Filter(got, root, filepath.Join(root, "apps"), []string{"prod", "../tg/clusters/x/terraform.enc.tfvars"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 3 || filtered[2].Plain != "tg/clusters/x/terraform.tfvars" {
		t.Fatalf("filtered = %+v", filtered)
	}
	if _, err := Filter(got, root, root, []string{"/elsewhere"}); err == nil {
		t.Fatal("expected error for a path outside the root")
	}
}
