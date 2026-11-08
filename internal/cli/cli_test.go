package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sun-asterisk-research/sopsman/internal/testutil"
)

func setupProject(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, c := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(root)
	return root
}

func run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(args, strings.NewReader(""), &out, &errOut)
	return out.String() + errOut.String(), code
}

func TestCLI(t *testing.T) {
	alice, bob := testutil.NewIdentity(t), testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	root := setupProject(t, map[string]string{
		"sopsman.yml": "recipients:\n  alice: { age: " + alice.Recipient + " }\n" +
			"groups:\n  team: [alice]\n" +
			"rules:\n  - files: [\"**/secret.*\"]\n    recipients: [team]\n",
		"a/secret.yaml": "k: v\n",
		"b/secret.json": "{\"k\": \"v\"}\n",
	})

	if out, code := run(t, "encrypt", "a"); code != 0 || !strings.Contains(out, "created    a/secret.yaml") || strings.Contains(out, "b/secret.json") {
		t.Fatalf("encrypt a: %d\n%s", code, out)
	}
	if out, code := run(t, "check"); code != 1 || !strings.Contains(out, "b/secret.json (not encrypted)") {
		t.Fatalf("check: %d\n%s", code, out)
	}
	if out, code := run(t, "encrypt"); code != 0 || !strings.Contains(out, "created    b/secret.json") {
		t.Fatalf("encrypt all: %d\n%s", code, out)
	}

	if out, code := run(t, "recipient", "add", "bob", "--age", bob.Recipient, "-g", "team"); code != 0 {
		t.Fatalf("recipient add: %d\n%s", code, out)
	}
	if out, code := run(t, "encrypt"); code != 0 || strings.Count(out, "rekeyed") != 2 {
		t.Fatalf("encrypt after add: %d\n%s", code, out)
	}
	if out, code := run(t, "recipient", "add", "eve", "--age", "not-a-key"); code != 1 || !strings.Contains(out, "invalid key") {
		t.Fatalf("recipient add with invalid key: %d\n%s", code, out)
	}
	if out, code := run(t, "recipient", "remove", "bob"); code != 0 {
		t.Fatalf("recipient remove: %d\n%s", code, out)
	}
	if out, code := run(t, "encrypt"); code != 0 || strings.Count(out, "rotated") != 2 {
		t.Fatalf("encrypt after remove: %d\n%s", code, out)
	}

	if err := os.WriteFile(filepath.Join(root, "a/secret.yaml"), []byte("k: local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := run(t, "decrypt"); code != 1 || !strings.Contains(out, "local changes not overwritten") {
		t.Fatalf("decrypt conflict: %d\n%s", code, out)
	}
	if out, code := run(t, "decrypt", "--force"); code != 0 {
		t.Fatalf("decrypt --force: %d\n%s", code, out)
	}
	if out, code := run(t, "status"); code != 0 || !strings.Contains(out, "a/secret.yaml") {
		t.Fatalf("status: %d\n%s", code, out)
	}
	if out, code := run(t, "encrypt", "/outside"); code != 1 || !strings.Contains(out, "outside the config directory") {
		t.Fatalf("outside path: %d\n%s", code, out)
	}
}

// TestSopsCLICompatibility guards the invariants that make sopsman a drop-in
// for files written by the sops CLI with `--indent 2`: such files are reported
// unchanged, and sopsman decrypts them byte for byte like `sops --decrypt`.
func TestSopsCLICompatibility(t *testing.T) {
	sops, err := exec.LookPath("sops")
	if err != nil {
		t.Skip("sops binary not installed")
	}
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	plain := map[string]string{
		"secret.yaml":   "# comment\na: 1\nlist:\n  - x\n  - x\nnested:\n  b: true\n",
		"secret.json":   "{\n  \"a\": \"b\"\n}\n",
		"secret.env":    "A=b\n",
		"secret.ini":    "[s]\nk = v\n",
		"secret.txt":    "no trailing newline",
		"secret.tfvars": "x = \"y\"\n",
	}
	files := map[string]string{
		"sopsman.yml": "recipients:\n  alice: { age: " + alice.Recipient + " }\n" +
			"rules:\n  - files: [\"secret.*\"]\n    recipients: [alice]\n",
	}
	for k, v := range plain {
		files[k] = v
	}
	root := setupProject(t, files)
	for name := range plain {
		ext := filepath.Ext(name)
		enc := strings.TrimSuffix(name, ext) + ".enc" + ext
		args := []string{"--encrypt", "--indent", "2", "--age", alice.Recipient}
		if ext == ".txt" || ext == ".tfvars" {
			args = append(args, "--input-type", "binary", "--output-type", "binary")
		}
		out, err := exec.Command(sops, append(args, filepath.Join(root, name))...).Output()
		if err != nil {
			t.Fatalf("sops encrypt %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(root, enc), out, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out, code := run(t, "encrypt")
	if code != 0 || strings.Count(out, "unchanged") != len(plain) {
		t.Fatalf("files written by the sops CLI should be unchanged: %d\n%s", code, out)
	}

	for name := range plain {
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if out, code := run(t, "decrypt"); code != 0 {
		t.Fatalf("decrypt: %d\n%s", code, out)
	}
	for name := range plain {
		ext := filepath.Ext(name)
		enc := strings.TrimSuffix(name, ext) + ".enc" + ext
		want, err := exec.Command(sops, "--decrypt", "--indent", "2", filepath.Join(root, enc)).Output()
		if err != nil {
			t.Fatalf("sops decrypt %s: %v", enc, err)
		}
		got, _ := os.ReadFile(filepath.Join(root, name))
		if !bytes.Equal(got, want) {
			t.Errorf("%s: sopsman decrypt differs from sops --decrypt:\n%q\n%q", name, got, want)
		}
	}
}
