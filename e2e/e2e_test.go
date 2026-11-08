// Package e2e drives the built sopsman binary against a fixture project with
// three generated age identities and every supported file format.
//
// Run with: CGO_ENABLED=0 go test ./e2e/
package e2e

import (
	"bytes"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

// secrets lists the fixture plaintexts and the encrypted paths sopsman must
// produce for them.
var secrets = map[string]string{
	"apps/production/web/secret.yaml":                                      "apps/production/web/secret.enc.yaml",
	"apps/production/web/values.yaml":                                      "apps/production/web/values.enc.yaml",
	"apps/production/web/secret.env":                                       "apps/production/web/secret.enc.env",
	"apps/production/redis/secret.redis-password.txt":                      "apps/production/redis/secret.redis-password.enc.txt",
	"apps/staging/web/values.yml":                                          "apps/staging/web/values.enc.yml",
	"apps/staging/web/secret.ini":                                          "apps/staging/web/secret.enc.ini",
	"components/patches/production/registry-auth/secret.dockerconfig.json": "components/patches/production/registry-auth/secret.dockerconfig.enc.json",
	"infrastructure/production/loki/secret.htpasswd":                       "infrastructure/production/loki/secret.enc.htpasswd",
	"infrastructure/production/loki/htpasswd":                              "infrastructure/production/loki/htpasswd.enc",
	"tg/clusters/production/terraform.tfvars":                              "tg/clusters/production/terraform.enc.tfvars",
}

// operatorsOnly are the secrets the cluster key (fluxcd) must not be able to read.
var operatorsOnly = []string{"tg/clusters/production/terraform.tfvars"}

type env struct {
	t       *testing.T
	bin     string
	keys    map[string]string // identity name -> key file
	recips  map[string]string // identity name -> age recipient
	home    string
	fixture string
}

type result struct {
	out  string
	code int
}

func setup(t *testing.T) *env {
	t.Helper()
	if testing.Short() {
		t.Skip("e2e test skipped in -short mode")
	}
	for _, tool := range []string{"go", "git"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
	work := t.TempDir()
	e := &env{t: t, keys: map[string]string{}, recips: map[string]string{}, home: filepath.Join(work, "home")}

	_, thisFile, _, _ := runtime.Caller(0)
	moduleRoot := filepath.Dir(filepath.Dir(thisFile))
	e.fixture = filepath.Join(moduleRoot, "e2e", "testdata", "project")
	e.bin = filepath.Join(work, "sopsman")
	build := exec.Command("go", "build", "-o", e.bin, ".")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	for _, name := range []string{"alice", "bob", "fluxcd"} {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		e.keys[name] = filepath.Join(work, name+".agekey")
		if err := os.WriteFile(e.keys[name], []byte(id.String()+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		e.recips[name] = id.Recipient().String()
	}
	return e
}

// newRepo copies the fixture into a fresh git repository and returns its path.
func (e *env) newRepo() string {
	e.t.Helper()
	dir := filepath.Join(e.t.TempDir(), "infra")
	err := filepath.WalkDir(e.fixture, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(e.fixture, p)
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		switch rel {
		case "sopsman.yml.tmpl":
			rel = "sopsman.yml"
			data = []byte(strings.NewReplacer("{{ALICE}}", e.recips["alice"], "{{BOB}}", e.recips["bob"], "{{FLUX}}", e.recips["fluxcd"]).Replace(string(data)))
		case "gitignore.tmpl":
			rel = ".gitignore"
		}
		return writeFile(filepath.Join(dir, rel), data)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.git(dir, "init", "-q", "-b", "main")
	return dir
}

func writeFile(name string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		return err
	}
	return os.WriteFile(name, data, 0o644)
}

// environ isolates sopsman from the user's real keys and git config, and
// selects which identity (if any) can decrypt.
func (e *env) environ(identity string) []string {
	var out []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "SOPS_") || strings.HasPrefix(name, "GIT_") || name == "HOME" || name == "XDG_CONFIG_HOME" {
			continue
		}
		out = append(out, kv)
	}
	keyFile := "/nonexistent"
	if identity != "" {
		keyFile = e.keys[identity]
	}
	return append(out,
		"HOME="+e.home,
		"XDG_CONFIG_HOME="+filepath.Join(e.home, ".config"),
		"SOPS_AGE_KEY_FILE="+keyFile,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=e2e", "GIT_AUTHOR_EMAIL=e2e@example.com",
		"GIT_COMMITTER_NAME=e2e", "GIT_COMMITTER_EMAIL=e2e@example.com",
	)
}

// sopsman runs the binary in dir as the given identity.
func (e *env) sopsman(dir, identity string, args ...string) result {
	e.t.Helper()
	cmd := exec.Command(e.bin, args...)
	cmd.Dir = dir
	cmd.Env = e.environ(identity)
	cmd.Stdin = strings.NewReader("")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return result{string(out), code}
}

// must runs sopsman and fails the test unless it exits with want.
func (e *env) must(want int, dir, identity string, args ...string) string {
	e.t.Helper()
	r := e.sopsman(dir, identity, args...)
	if r.code != want {
		e.t.Fatalf("sopsman %s (as %s): exit %d, want %d\n%s", strings.Join(args, " "), identity, r.code, want, r.out)
	}
	return r.out
}

func (e *env) git(dir string, args ...string) string {
	e.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = e.environ("")
	out, err := cmd.CombinedOutput()
	if err != nil {
		e.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func countStatus(out, status string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == status {
			n++
		}
	}
	return n
}

// removedLines returns the lines of before that are missing from after,
// counting duplicates.
func removedLines(before, after string) []string {
	left := map[string]int{}
	for _, l := range strings.Split(after, "\n") {
		left[l]++
	}
	var out []string
	for _, l := range strings.Split(before, "\n") {
		if left[l] > 0 {
			left[l]--
			continue
		}
		out = append(out, l)
	}
	return out
}

func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, enc := range secrets {
		out[enc] = read(t, filepath.Join(dir, enc))
	}
	return out
}

func TestE2E(t *testing.T) {
	e := setup(t)
	repo := e.newRepo()

	// Fixture plaintexts, the expected output of every later decrypt.
	want := map[string]string{}
	for plain := range secrets {
		want[plain] = read(t, filepath.Join(e.fixture, plain))
	}

	step := func(name string, fn func(t *testing.T)) {
		if !t.Run(name, fn) {
			t.FailNow()
		}
	}

	step("encrypt creates every format", func(t *testing.T) {
		out := e.must(0, repo, "alice", "encrypt")
		if got := countStatus(out, "created"); got != len(secrets) {
			t.Fatalf("created %d files, want %d\n%s", got, len(secrets), out)
		}
		if strings.Contains(out, "release.yaml") {
			t.Fatalf("unmatched file was processed:\n%s", out)
		}
		for plain, enc := range secrets {
			data := read(t, filepath.Join(repo, enc))
			if !strings.Contains(data, "ENC[AES256_GCM") || !strings.Contains(data, e.recips["alice"]) {
				t.Errorf("%s is not encrypted to alice", enc)
			}
			for _, secret := range []string{"fake-db-password", "fake-client-secret", "fake-smtp-password", "fake-redis-password", "fake-ini-password", "ZmFrZTpmYWtl", "fake-cloud-token", "hashhash"} {
				if strings.Contains(data, secret) {
					t.Errorf("%s (from %s) leaks %q", enc, plain, secret)
				}
			}
			isOperatorsOnly := slices.Contains(operatorsOnly, plain)
			if strings.Contains(data, e.recips["fluxcd"]) == isOperatorsOnly {
				t.Errorf("%s: fluxcd recipient presence = %v, want %v", enc, !isOperatorsOnly, !isOperatorsOnly)
			}
		}
		// Structured formats keep keys readable; encrypted_regex leaves
		// metadata in cleartext.
		secretYAML := read(t, filepath.Join(repo, secrets["apps/production/web/secret.yaml"]))
		if !strings.Contains(secretYAML, "name: web-credentials") || !strings.Contains(secretYAML, "DATABASE_URL: ENC[") {
			t.Errorf("encrypted_regex not applied:\n%s", secretYAML)
		}
		if !strings.Contains(read(t, filepath.Join(repo, secrets["apps/production/web/secret.env"])), "SMTP_PASSWORD=ENC[") {
			t.Error("dotenv not encrypted per key")
		}
		if !strings.Contains(read(t, filepath.Join(repo, secrets["apps/staging/web/secret.ini"])), "password = ENC[") {
			t.Error("ini not encrypted per key")
		}
		if !strings.Contains(read(t, filepath.Join(repo, secrets["tg/clusters/production/terraform.tfvars"])), `"data": "ENC[`) {
			t.Error("tfvars not encrypted as a binary blob")
		}
		e.git(repo, "add", "-A")
		e.git(repo, "commit", "-qm", "encrypt secrets")
		if tracked := e.git(repo, "ls-files"); strings.Contains(tracked, "secret.yaml\n") || strings.Contains(tracked, "terraform.tfvars\n") {
			t.Fatalf("plaintext committed:\n%s", tracked)
		}
	})

	step("second encrypt changes nothing", func(t *testing.T) {
		out := e.must(0, repo, "alice", "encrypt")
		if got := countStatus(out, "unchanged"); got != len(secrets) {
			t.Fatalf("unchanged %d, want %d\n%s", got, len(secrets), out)
		}
		if status := e.git(repo, "status", "--porcelain"); status != "" {
			t.Fatalf("git changes after no-op encrypt:\n%s", status)
		}
		e.must(0, repo, "alice", "check")
	})

	// Fixtures are in the canonical form sops emits on decryption. Plaintexts
	// that differ only in formatting (indentation, an inline comment that sops
	// would move above its key, unaligned INI keys) must not cause rewrites.
	step("formatting-only changes are unchanged", func(t *testing.T) {
		reformatted := map[string]string{
			"apps/production/web/values.yaml": strings.ReplaceAll(
				strings.Replace(want["apps/production/web/values.yaml"],
					"  # rotated yearly\n  clientSecret: fake-client-secret\n",
					"  clientSecret: fake-client-secret # rotated yearly\n", 1),
				"  ", "    "),
			"apps/staging/web/secret.ini":                                          strings.Replace(want["apps/staging/web/secret.ini"], "user     = web", "user = web", 1),
			"components/patches/production/registry-auth/secret.dockerconfig.json": `{"auths":{"registry.example.com":{"auth":"ZmFrZTpmYWtl"}}}`,
		}
		for plain, content := range reformatted {
			if content == want[plain] {
				t.Fatalf("%s: reformatting had no effect", plain)
			}
			if err := os.WriteFile(filepath.Join(repo, plain), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := e.must(0, repo, "alice", "encrypt")
		if countStatus(out, "unchanged") != len(secrets) || e.git(repo, "status", "--porcelain") != "" {
			t.Fatalf("reformatting caused a rewrite:\n%s", out)
		}
		for plain := range reformatted {
			if err := os.WriteFile(filepath.Join(repo, plain), []byte(want[plain]), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})

	step("fresh clone decrypts byte for byte", func(t *testing.T) {
		clone := filepath.Join(t.TempDir(), "clone")
		e.git(repo, "clone", "-q", repo, clone)
		out := e.must(0, clone, "alice", "decrypt")
		if got := countStatus(out, "decrypted"); got != len(secrets) {
			t.Fatalf("decrypted %d, want %d\n%s", got, len(secrets), out)
		}
		for plain, content := range want {
			p := filepath.Join(clone, plain)
			if got := read(t, p); got != content {
				t.Errorf("%s: got %q, want %q", plain, got, content)
			}
			if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v, want 0600", plain, info.Mode().Perm())
			}
		}
		e.must(0, clone, "alice", "check")
	})

	step("cluster key decrypts only what it may", func(t *testing.T) {
		clone := filepath.Join(t.TempDir(), "flux")
		e.git(repo, "clone", "-q", repo, clone)
		out := e.must(0, clone, "fluxcd", "decrypt")
		if got := countStatus(out, "decrypted"); got != len(secrets)-len(operatorsOnly) {
			t.Fatalf("decrypted %d, want %d\n%s", got, len(secrets)-len(operatorsOnly), out)
		}
		for _, plain := range operatorsOnly {
			if !strings.Contains(out, "skipped    "+plain+" (no key)") {
				t.Errorf("%s not reported as skipped:\n%s", plain, out)
			}
			if _, err := os.Stat(filepath.Join(clone, plain)); err == nil {
				t.Errorf("%s written without a key", plain)
			}
		}
		// A plaintext for a file the identity cannot read is reported, not encrypted.
		if err := os.WriteFile(filepath.Join(clone, operatorsOnly[0]), []byte("x = 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		out = e.must(0, clone, "fluxcd", "encrypt")
		if !strings.Contains(out, "warning    "+operatorsOnly[0]+" (plaintext present but no key; not encrypted)") || countStatus(out, "unchanged") != len(secrets)-1 {
			t.Fatalf("encrypt as fluxcd:\n%s", out)
		}
		if e.git(clone, "status", "--porcelain") != "" {
			t.Fatal("encrypt without a key modified files")
		}
	})

	step("no key at all", func(t *testing.T) {
		out := e.must(0, repo, "", "encrypt")
		if countStatus(out, "warning") != len(secrets) {
			t.Fatalf("encrypt without keys:\n%s", out)
		}
		if e.git(repo, "status", "--porcelain") != "" {
			t.Fatal("files modified without keys")
		}
	})

	step("editing one value changes only that value, mac and lastmodified", func(t *testing.T) {
		edits := map[string][2]string{
			"apps/production/web/secret.yaml":                                      {"fake-session-key", "new-session-key"},
			"apps/production/web/values.yaml":                                      {"fake-client-secret", "new-client-secret"},
			"apps/production/web/secret.env":                                       {"fake-smtp-password", "new-smtp-password"},
			"apps/staging/web/secret.ini":                                          {"fake-ini-password", "new-ini-password"},
			"components/patches/production/registry-auth/secret.dockerconfig.json": {"ZmFrZTpmYWtl", "bmV3Om5ldw=="},
			"apps/production/redis/secret.redis-password.txt":                      {"fake-redis-password", "new-redis-password"},
		}
		before := snapshot(t, repo)
		for plain, ed := range edits {
			p := filepath.Join(repo, plain)
			if err := os.WriteFile(p, []byte(strings.Replace(read(t, p), ed[0], ed[1], 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := e.must(0, repo, "alice", "encrypt")
		if countStatus(out, "updated") != len(edits) || countStatus(out, "unchanged") != len(secrets)-len(edits) {
			t.Fatalf("encrypt after edits:\n%s", out)
		}
		for plain, enc := range secrets {
			removed := removedLines(before[enc], read(t, filepath.Join(repo, enc)))
			if _, edited := edits[plain]; !edited {
				if len(removed) != 0 {
					t.Errorf("%s changed without an edit: %q", enc, removed)
				}
				continue
			}
			var value int
			for _, l := range removed {
				switch {
				case strings.Contains(l, "lastmodified"), strings.Contains(l, "mac"):
				case strings.Contains(l, "ENC["):
					value++
				default:
					t.Errorf("%s: unexpected changed line %q", enc, l)
				}
			}
			if value != 1 {
				t.Errorf("%s: %d value lines changed, want 1: %q", enc, value, removed)
			}
		}
		// The edited content round-trips through a fresh clone.
		e.git(repo, "commit", "-qam", "edit secrets")
		clone := filepath.Join(t.TempDir(), "clone")
		e.git(repo, "clone", "-q", repo, clone)
		e.must(0, clone, "alice", "decrypt")
		for plain := range edits {
			if read(t, filepath.Join(clone, plain)) != read(t, filepath.Join(repo, plain)) {
				t.Errorf("%s does not round-trip after edit", plain)
			}
		}
	})

	step("adding a recipient re-keys without touching values", func(t *testing.T) {
		before := snapshot(t, repo)
		e.must(0, repo, "alice", "recipient", "add", "bob", "--age", e.recips["bob"], "--group", "operators")
		out := e.must(1, repo, "alice", "check")
		if !strings.Contains(out, "stale recipients +bob") {
			t.Fatalf("check did not flag the new recipient:\n%s", out)
		}
		out = e.must(0, repo, "alice", "encrypt")
		if countStatus(out, "rekeyed") != len(secrets) || !strings.Contains(out, "(+bob)") {
			t.Fatalf("encrypt after adding bob:\n%s", out)
		}
		for _, enc := range secrets {
			after := read(t, filepath.Join(repo, enc))
			if removed := removedLines(before[enc], after); len(removed) != 0 {
				t.Errorf("%s: lines changed while adding a recipient: %q", enc, removed)
			}
			if !strings.Contains(after, e.recips["bob"]) {
				t.Errorf("%s not encrypted to bob", enc)
			}
		}
		e.must(0, repo, "alice", "check")
		e.git(repo, "commit", "-qam", "add bob")

		clone := filepath.Join(t.TempDir(), "bob")
		e.git(repo, "clone", "-q", repo, clone)
		if out := e.must(0, clone, "bob", "decrypt"); countStatus(out, "decrypted") != len(secrets) {
			t.Fatalf("bob cannot decrypt everything:\n%s", out)
		}
	})

	step("removing a recipient rotates data keys", func(t *testing.T) {
		before := snapshot(t, repo)
		e.must(0, repo, "alice", "recipient", "remove", "bob")
		out := e.must(0, repo, "alice", "encrypt")
		if countStatus(out, "rotated") != len(secrets) || !strings.Contains(out, "new data key") {
			t.Fatalf("encrypt after removing bob:\n%s", out)
		}
		for _, enc := range secrets {
			after := read(t, filepath.Join(repo, enc))
			if strings.Contains(after, e.recips["bob"]) {
				t.Errorf("%s still encrypted to bob", enc)
			}
			for _, l := range strings.Split(before[enc], "\n") {
				if strings.Contains(l, "ENC[") && strings.Contains(after, l) {
					t.Errorf("%s: ciphertext survived rotation: %q", enc, l)
				}
			}
		}
		e.git(repo, "commit", "-qam", "remove bob")
		clone := filepath.Join(t.TempDir(), "bob-revoked")
		e.git(repo, "clone", "-q", repo, clone)
		if out := e.must(0, clone, "bob", "decrypt"); countStatus(out, "skipped") != len(secrets) {
			t.Fatalf("bob can still decrypt:\n%s", out)
		}
	})

	step("rotation works without plaintexts", func(t *testing.T) {
		clone := filepath.Join(t.TempDir(), "no-plaintext")
		e.git(repo, "clone", "-q", repo, clone)
		e.must(0, clone, "alice", "recipient", "add", "bob", "--age", e.recips["bob"], "-g", "operators")
		e.must(0, clone, "alice", "encrypt")
		e.must(0, clone, "alice", "recipient", "remove", "bob")
		out := e.must(0, clone, "alice", "encrypt")
		if countStatus(out, "rotated") != len(secrets) {
			t.Fatalf("rotation without plaintexts:\n%s", out)
		}
		for plain := range secrets {
			if _, err := os.Stat(filepath.Join(clone, plain)); err == nil {
				t.Errorf("rotation wrote plaintext %s", plain)
			}
		}
	})

	step("stale plaintext cannot revert a teammate's change", func(t *testing.T) {
		teammate := filepath.Join(t.TempDir(), "teammate")
		e.git(repo, "clone", "-q", repo, teammate)
		e.must(0, teammate, "alice", "decrypt")
		plain := "apps/production/web/secret.env"
		p := filepath.Join(teammate, plain)
		if err := os.WriteFile(p, []byte(strings.Replace(read(t, p), "web@example.com", "team@example.com", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		e.must(0, teammate, "alice", "encrypt", plain)
		e.git(teammate, "commit", "-qam", "teammate change")

		// Our plaintext predates the teammate's encryption.
		local := filepath.Join(repo, plain)
		past := time.Now().Add(-time.Hour)
		if err := os.Chtimes(local, past, past); err != nil {
			t.Fatal(err)
		}
		e.git(repo, "pull", "-q", teammate, "main")
		pulled := read(t, filepath.Join(repo, secrets[plain]))

		out := e.must(1, repo, "alice", "encrypt", plain)
		if !strings.Contains(out, "encrypted file is newer than your plaintext") || read(t, filepath.Join(repo, secrets[plain])) != pulled {
			t.Fatalf("stale plaintext was encrypted:\n%s", out)
		}
		out = e.must(1, repo, "alice", "decrypt", plain)
		if !strings.Contains(out, "local changes not overwritten") {
			t.Fatalf("decrypt overwrote local plaintext without a terminal:\n%s", out)
		}
		e.must(0, repo, "alice", "decrypt", "--force", plain)
		if !strings.Contains(read(t, local), "team@example.com") {
			t.Fatal("decrypt --force did not take the teammate's version")
		}
		if out := e.must(0, repo, "alice", "encrypt", plain); countStatus(out, "unchanged") != 1 {
			t.Fatalf("encrypt after syncing:\n%s", out)
		}
	})

	step("check guards gitignore", func(t *testing.T) {
		gi := filepath.Join(repo, ".gitignore")
		orig := read(t, gi)
		if err := os.WriteFile(gi, []byte(strings.Replace(orig, "*.tfvars\n", "", 1)), 0o644); err != nil {
			t.Fatal(err)
		}
		out := e.must(1, repo, "alice", "check")
		if !strings.Contains(out, "tg/clusters/production/terraform.tfvars (plaintext is not gitignored)") {
			t.Fatalf("check missed an unignored plaintext:\n%s", out)
		}
		if err := os.WriteFile(gi, []byte(orig), 0o644); err != nil {
			t.Fatal(err)
		}
		e.must(0, repo, "alice", "check")
	})

	step("status and path filters", func(t *testing.T) {
		out := e.must(0, repo, "fluxcd", "status", "tg", "apps/staging")
		lines := strings.Split(strings.TrimSpace(out), "\n")
		if len(lines) != 4 { // header + values.yml + secret.ini + terraform.tfvars
			t.Fatalf("status rows:\n%s", out)
		}
		if !strings.Contains(out, "no key") || !strings.Contains(out, "alice,fluxcd") {
			t.Fatalf("status content:\n%s", out)
		}
		if r := e.sopsman(repo, "alice", "encrypt", "does/not/exist"); r.code != 1 {
			t.Fatalf("unmatched path: exit %d\n%s", r.code, r.out)
		}
	})

	step("sops CLI reads sopsman output", func(t *testing.T) {
		sops, err := exec.LookPath("sops")
		if err != nil {
			t.Skip("sops binary not installed")
		}
		for plain, enc := range secrets {
			cmd := exec.Command(sops, "--decrypt", "--indent", "2", filepath.Join(repo, enc))
			cmd.Env = e.environ("alice")
			got, err := cmd.Output()
			if err != nil {
				t.Errorf("sops --decrypt %s: %v", enc, err)
				continue
			}
			if !bytes.Equal(got, []byte(read(t, filepath.Join(repo, plain)))) {
				t.Errorf("%s: sops CLI output differs from sopsman plaintext", enc)
			}
		}
	})
}
