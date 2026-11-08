package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const validConfig = `# team secrets
recipients:
  alice: { age: age1alice }
  bob:
    age: "age1bob1, age1bob2"
  ci: { kms: [arn:aws:kms:eu-west-1:1:key/a] }
groups:
  humans: [alice, bob]   # people
  everyone: [humans, ci]
rules:
  - files: ["apps/**/secret*.*"]
    recipients: [everyone]
    encrypted_regex: ^(data|stringData)$
  - files: ["tg/**/*.tfvars"]
    recipients: [humans]
`

func TestParseAndResolve(t *testing.T) {
	c, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Resolve(c.Rules[0].Recipients)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"alice", "bob", "ci"}; !slices.Equal(got, want) {
		t.Fatalf("resolve = %v, want %v", got, want)
	}
	if bob := c.Recipients["bob"].Age; !slices.Equal(bob, StringList{"age1bob1", "age1bob2"}) {
		t.Fatalf("comma-separated keys not split: %v", bob)
	}
	specs := c.KeySpecs(got)
	if len(specs["age"]) != 3 || len(specs["kms"]) != 1 {
		t.Fatalf("key specs = %v", specs)
	}
	if c.Rules[0].EncryptedRegex == "" {
		t.Fatal("inline options not parsed")
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown recipient": `
recipients: { a: { age: x } }
rules: [{ files: ["*"], recipients: [nobody] }]`,
		"group cycle": `
recipients: { a: { age: x } }
groups: { g1: [g2], g2: [g1] }
rules: [{ files: ["*"], recipients: [a] }]`,
		"is both a recipient and a group": `
recipients: { a: { age: x } }
groups: { a: [a] }
rules: [{ files: ["*"], recipients: [a] }]`,
		"only one of": `
recipients: { a: { age: x } }
rules: [{ files: ["*"], recipients: [a], encrypted_regex: x, unencrypted_suffix: y }]`,
		"resolve to no one": `
recipients: { a: { age: x } }
groups: { empty: [] }
rules: [{ files: ["*"], recipients: [empty] }]`,
		"has no keys": `
recipients: { a: {} }
rules: [{ files: ["*"], recipients: [a] }]`,
		"no rules": `
recipients: { a: { age: x } }`,
		"invalid glob": `
recipients: { a: { age: x } }
rules: [{ files: ["[a"], recipients: [a] }]`,
		"must be relative": `
recipients: { a: { age: x } }
rules: [{ files: ["../x"], recipients: [a] }]`,
		"field nope not found": `
recipients: { a: { age: x } }
rules: [{ files: ["*"], recipients: [a], nope: 1 }]`,
	}
	for want, cfg := range cases {
		_, err := Parse([]byte(cfg))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
}

func TestFind(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sopsman.yml"), []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Find(sub)
	if err != nil || got != filepath.Join(root, "sopsman.yml") {
		t.Fatalf("Find = %q, %v", got, err)
	}
	c, err := Load(got)
	if err != nil || c.Root != root {
		t.Fatalf("Load root = %q, %v", c.Root, err)
	}
}

func TestAddAndRemoveRecipient(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sopsman.yml")
	if err := os.WriteFile(path, []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddRecipient(path, "carol", map[string][]string{"age": {"age1carol"}}, []string{"humans", "newgroup"}); err != nil {
		t.Fatal(err)
	}
	if err := AddRecipient(path, "carol", map[string][]string{"age": {"x"}}, nil); err == nil {
		t.Fatal("expected duplicate recipient error")
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"# team secrets", "# people", "carol:", "age: age1carol"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("after add, missing %q in:\n%s", want, data)
		}
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Groups["humans"], "carol") || !slices.Contains(c.Groups["newgroup"], "carol") {
		t.Fatalf("groups = %v", c.Groups)
	}

	if err := RemoveRecipient(path, "carol"); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Recipients["carol"]; ok || slices.Contains(c.Groups["humans"], "carol") {
		t.Fatal("carol not fully removed")
	}

	// Removing the last recipient of a rule leaves an invalid config: refuse.
	if err := RemoveRecipient(path, "ci"); err != nil {
		t.Fatal(err)
	}
	if err := RemoveRecipient(path, "alice"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := RemoveRecipient(path, "bob"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("err = %v, want invalid config refusal", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("config modified despite refusal")
	}
}
