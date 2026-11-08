package engine

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sun-asterisk-research/sopsman/internal/config"
	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/testutil"
)

type project struct {
	t    *testing.T
	root string
	out  bytes.Buffer
	eng  *Engine
}

func newProject(t *testing.T, cfg string, contents map[string]string) *project {
	t.Helper()
	p := &project{t: t, root: t.TempDir()}
	p.write("sopsman.yml", cfg)
	for name, c := range contents {
		p.write(name, c)
	}
	p.reload()
	return p
}

func (p *project) reload() {
	p.t.Helper()
	c, err := config.Load(filepath.Join(p.root, "sopsman.yml"))
	if err != nil {
		p.t.Fatal(err)
	}
	p.eng = New(c, &p.out)
}

func (p *project) write(name, content string) {
	p.t.Helper()
	full := filepath.Join(p.root, name)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		p.t.Fatal(err)
	}
}

func (p *project) read(name string) string {
	p.t.Helper()
	b, err := os.ReadFile(filepath.Join(p.root, name))
	if err != nil {
		p.t.Fatal(err)
	}
	return string(b)
}

func (p *project) entries() []files.Entry {
	p.t.Helper()
	es, err := p.eng.Entries(p.root, nil)
	if err != nil {
		p.t.Fatal(err)
	}
	return es
}

func (p *project) encrypt(es []files.Entry) error { return p.eng.Encrypt(es, EncryptOptions{}) }

// run executes fn, returning its error and the output it printed.
func (p *project) run(fn func([]files.Entry) error) (string, error) {
	p.out.Reset()
	err := fn(p.entries())
	return p.out.String(), err
}

func configFor(ids ...testutil.Identity) string {
	var b strings.Builder
	b.WriteString("recipients:\n")
	names := []string{"alice", "bob", "carol"}
	var members []string
	for i, id := range ids {
		b.WriteString("  " + names[i] + ": { age: " + id.Recipient + " }\n")
		members = append(members, names[i])
	}
	b.WriteString("rules:\n  - files: [\"**/secret*.*\"]\n    recipients: [" + strings.Join(members, ", ") + "]\n")
	return b.String()
}

const secretYAML = "token: abc\npassword: hunter2\n"

func TestEncryptThenUnchangedThenDecrypt(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"app/secret.yaml": secretYAML})

	out, err := p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "created    app/secret.yaml") {
		t.Fatalf("encrypt: %v\n%s", err, out)
	}
	enc := p.read("app/secret.enc.yaml")

	out, err = p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "unchanged  app/secret.yaml") || p.read("app/secret.enc.yaml") != enc {
		t.Fatalf("second encrypt: %v\n%s", err, out)
	}

	if err := os.Remove(filepath.Join(p.root, "app/secret.yaml")); err != nil {
		t.Fatal(err)
	}
	out, err = p.run(func(es []files.Entry) error { return p.eng.Decrypt(es, DecryptOptions{}) })
	if err != nil || p.read("app/secret.yaml") != secretYAML {
		t.Fatalf("decrypt: %v\n%s", err, out)
	}
	info, _ := os.Stat(filepath.Join(p.root, "app/secret.yaml"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("plaintext mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestNoKey(t *testing.T) {
	alice, mallory := testutil.NewIdentity(t), testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"secret.yaml": secretYAML})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	enc := p.read("secret.enc.yaml")

	testutil.UseIdentities(t, mallory)
	p.write("secret.yaml", "token: changed\n")
	out, err := p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "warning    secret.yaml (plaintext present but no key; not encrypted)") {
		t.Fatalf("encrypt without key: %v\n%s", err, out)
	}
	if p.read("secret.enc.yaml") != enc {
		t.Fatal("encrypted file modified without a key")
	}
	out, err = p.run(func(es []files.Entry) error { return p.eng.Decrypt(es, DecryptOptions{}) })
	if err != nil || !strings.Contains(out, "skipped    secret.yaml (no key)") {
		t.Fatalf("decrypt without key: %v\n%s", err, out)
	}
}

type scriptedPrompter struct{ answers []Choice }

func (s *scriptedPrompter) Confirm(string) (Choice, error) {
	if len(s.answers) == 0 {
		return ChoiceNo, errors.New("unexpected prompt")
	}
	c := s.answers[0]
	s.answers = s.answers[1:]
	return c, nil
}

func TestDecryptConflict(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"secret.yaml": secretYAML})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	decrypt := func(opts DecryptOptions) (string, error) {
		return p.run(func(es []files.Entry) error { return p.eng.Decrypt(es, opts) })
	}

	// Formatting-only difference: overwritten without asking.
	p.write("secret.yaml", "token:   abc\npassword: hunter2\n")
	if out, err := decrypt(DecryptOptions{}); err != nil || p.read("secret.yaml") != secretYAML {
		t.Fatalf("reformatted: %v\n%s", err, out)
	}

	local := "token: abc\npassword: local-edit\n"
	p.write("secret.yaml", local)

	out, err := decrypt(DecryptOptions{})
	if !errors.Is(err, ErrFailed) || p.read("secret.yaml") != local || !strings.Contains(out, "local changes not overwritten") {
		t.Fatalf("non-interactive: %v\n%s", err, out)
	}

	out, err = decrypt(DecryptOptions{Prompter: &scriptedPrompter{answers: []Choice{ChoiceDiff, ChoiceNo}}})
	if !errors.Is(err, ErrFailed) || p.read("secret.yaml") != local {
		t.Fatalf("answered no: %v\n%s", err, out)
	}
	if !strings.Contains(out, "-password: local-edit") || !strings.Contains(out, "+password: hunter2") {
		t.Fatalf("diff not shown:\n%s", out)
	}

	if _, err := decrypt(DecryptOptions{Prompter: &scriptedPrompter{answers: []Choice{ChoiceYes}}}); err != nil || p.read("secret.yaml") != secretYAML {
		t.Fatalf("answered yes: %v", err)
	}

	p.write("secret.yaml", local)
	if _, err := decrypt(DecryptOptions{Force: true}); err != nil || p.read("secret.yaml") != secretYAML {
		t.Fatalf("force: %v", err)
	}
}

func TestRecipientChanges(t *testing.T) {
	alice, bob := testutil.NewIdentity(t), testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"secret.yaml": secretYAML})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}

	p.write("sopsman.yml", configFor(alice, bob))
	p.reload()
	out, err := p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "rekeyed    secret.yaml (+bob)") {
		t.Fatalf("add: %v\n%s", err, out)
	}

	p.write("sopsman.yml", configFor(alice))
	p.reload()
	out, err = p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "rotated    secret.yaml (-") || !strings.Contains(out, "new data key") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
}

func TestCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	alice, bob := testutil.NewIdentity(t), testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{
		".gitignore":  "secret.*\n!*.enc.*\n",
		"secret.yaml": secretYAML,
	})
	gitCmd := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", p.root}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	gitCmd("init", "-q")

	out, err := p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "secret.yaml (not encrypted)") {
		t.Fatalf("missing encryption: %v\n%s", err, out)
	}

	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	if out, err := p.run(p.eng.Check); err != nil {
		t.Fatalf("clean check: %v\n%s", err, out)
	}

	p.write("secret.yaml", "token: drifted\n")
	out, err = p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "plaintext differs") {
		t.Fatalf("drift: %v\n%s", err, out)
	}
	p.write("secret.yaml", secretYAML)

	p.write("sopsman.yml", configFor(alice, bob))
	p.reload()
	out, err = p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "stale recipients +bob") {
		t.Fatalf("stale recipients: %v\n%s", err, out)
	}
	p.write("sopsman.yml", configFor(alice))
	p.reload()

	p.write(".gitignore", "")
	out, err = p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "plaintext is not gitignored") {
		t.Fatalf("not ignored: %v\n%s", err, out)
	}
	gitCmd("add", "secret.yaml")
	p.write(".gitignore", "secret.*\n!*.enc.*\n")
	out, err = p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "plaintext is tracked by git") {
		t.Fatalf("tracked: %v\n%s", err, out)
	}
}

func TestStatus(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"secret.yaml": secretYAML, "secret.env": "A=1\n"})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	p.write("secret.env", "A=2\n")
	out, err := p.run(p.eng.Status)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FILE", "secret.env  1     alice       modified   ok", "secret.yaml  1     alice       present    ok"} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), strings.Join(strings.Fields(want), " ")) {
			t.Errorf("status missing %q:\n%s", want, out)
		}
	}
}

// A rule naming an exact plaintext must still manage it in a fresh clone
// where only the encrypted file exists.
func TestExactRuleWithOnlyEncryptedFile(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	cfg := "recipients:\n  alice: { age: " + alice.Recipient + " }\n" +
		"rules:\n  - files: [\"app/secret.yaml\", \"app/htpasswd\"]\n    recipients: [alice]\n"
	p := newProject(t, cfg, map[string]string{"app/secret.yaml": secretYAML, "app/htpasswd": "u:h"})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"app/secret.yaml", "app/htpasswd"} {
		if err := os.Remove(filepath.Join(p.root, f)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := p.run(func(es []files.Entry) error { return p.eng.Decrypt(es, DecryptOptions{}) })
	if err != nil || strings.Count(out, "decrypted") != 2 {
		t.Fatalf("decrypt: %v\n%s", err, out)
	}
}

// Removing a recipient must rotate files even when no plaintext is present.
func TestRotateWithoutPlaintext(t *testing.T) {
	alice, bob := testutil.NewIdentity(t), testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice, bob), map[string]string{"secret.yaml": secretYAML})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(p.root, "secret.yaml")); err != nil {
		t.Fatal(err)
	}
	p.write("sopsman.yml", configFor(alice))
	p.reload()
	out, err := p.run(p.encrypt)
	if err != nil || !strings.Contains(out, "rotated    secret.yaml") || strings.Contains(p.read("secret.enc.yaml"), bob.Recipient) {
		t.Fatalf("rotate without plaintext: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(p.root, "secret.yaml")); err == nil {
		t.Fatal("rotation must not write a plaintext")
	}
	out, err = p.run(p.encrypt)
	if err != nil || strings.TrimSpace(out) != "" {
		t.Fatalf("nothing to do without plaintext: %v\n%s", err, out)
	}
}

// The config file is never treated as a secret, even when a glob matches it.
func TestConfigFileNotManaged(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	cfg := "recipients:\n  alice: { age: " + alice.Recipient + " }\nrules:\n  - files: [\"*.yml\"]\n    recipients: [alice]\n"
	p := newProject(t, cfg, map[string]string{"app.yml": "a: 1\n"})
	es := p.entries()
	if len(es) != 1 || es[0].Plain != "app.yml" {
		t.Fatalf("entries = %+v", es)
	}
	if _, err := p.eng.Entries(p.root, []string{"nothing-here"}); err == nil {
		t.Fatal("expected an error when path arguments match no managed file")
	}
}

// Git hooks export GIT_DIR; check must still see a force-added plaintext when
// the config lives in a subdirectory of the repository.
func TestCheckInsideGitHook(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	p := &project{t: t, root: filepath.Join(repo, "infra")}
	p.write("sopsman.yml", configFor(alice))
	p.write(".gitignore", "secret.*\n!*.enc.*\n")
	p.write("secret.yaml", secretYAML)
	p.reload()
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	run("add", "-f", "infra/secret.yaml")

	t.Setenv("GIT_DIR", filepath.Join(repo, ".git"))
	out, err := p.run(p.eng.Check)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "plaintext is tracked by git") {
		t.Fatalf("check in hook env: %v\n%s", err, out)
	}
}

// A plaintext older than a differing encrypted file must not revert it.
func TestEncryptRefusesStalePlaintext(t *testing.T) {
	alice := testutil.NewIdentity(t)
	testutil.UseIdentities(t, alice)
	p := newProject(t, configFor(alice), map[string]string{"secret.yaml": "v: 1\n"})
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	// A teammate encrypts v2 later; our plaintext still holds v1 and is older.
	plainPath := filepath.Join(p.root, "secret.yaml")
	past := time.Now().Add(-time.Hour)
	p.write("secret.yaml", "v: 2\n")
	if _, err := p.run(p.encrypt); err != nil {
		t.Fatal(err)
	}
	newer := p.read("secret.enc.yaml")
	p.write("secret.yaml", "v: 1\n")
	if err := os.Chtimes(plainPath, past, past); err != nil {
		t.Fatal(err)
	}

	out, err := p.run(p.encrypt)
	if !errors.Is(err, ErrFailed) || !strings.Contains(out, "encrypted file is newer than your plaintext") || p.read("secret.enc.yaml") != newer {
		t.Fatalf("stale plaintext: %v\n%s", err, out)
	}
	out, err = p.run(func(es []files.Entry) error { return p.eng.Encrypt(es, EncryptOptions{Force: true}) })
	if err != nil || !strings.Contains(out, "updated    secret.yaml") {
		t.Fatalf("force: %v\n%s", err, out)
	}
	// An edit made after the latest encryption is not stale.
	p.write("secret.yaml", "v: 3\n")
	if out, err := p.run(p.encrypt); err != nil || !strings.Contains(out, "updated") {
		t.Fatalf("fresh edit: %v\n%s", err, out)
	}
}
