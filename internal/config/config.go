// Package config loads and resolves sopsman.yml.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"gopkg.in/yaml.v3"
)

// FileNames are the config file names searched for, in order.
var FileNames = []string{"sopsman.yml", "sopsman.yaml"}

// KeyTypes lists the supported recipient key types, in the order they are
// emitted when building key groups.
var KeyTypes = []string{"age", "pgp", "kms", "gcp_kms", "azure_kv", "hc_vault", "hckms"}

// StringList accepts either a YAML string (comma-separated values allowed) or a
// list of strings.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	var raw []string
	switch n.Kind {
	case yaml.ScalarNode:
		raw = strings.Split(n.Value, ",")
	case yaml.SequenceNode:
		if err := n.Decode(&raw); err != nil {
			return err
		}
	default:
		return fmt.Errorf("line %d: expected a string or a list of strings", n.Line)
	}
	for _, v := range raw {
		if v = strings.TrimSpace(v); v != "" {
			*s = append(*s, v)
		}
	}
	return nil
}

// Recipient holds the keys of one named recipient, per key type.
type Recipient struct {
	Age     StringList `yaml:"age"`
	PGP     StringList `yaml:"pgp"`
	KMS     StringList `yaml:"kms"`
	GCPKMS  StringList `yaml:"gcp_kms"`
	AzureKV StringList `yaml:"azure_kv"`
	HCVault StringList `yaml:"hc_vault"`
	HCKMS   StringList `yaml:"hckms"`
}

// Keys returns the recipient's keys indexed by key type.
func (r Recipient) Keys() map[string][]string {
	return map[string][]string{
		"age": r.Age, "pgp": r.PGP, "kms": r.KMS, "gcp_kms": r.GCPKMS,
		"azure_kv": r.AzureKV, "hc_vault": r.HCVault, "hckms": r.HCKMS,
	}
}

// Options are the sops encryption options a rule may set.
type Options struct {
	EncryptedRegex          string `yaml:"encrypted_regex"`
	UnencryptedRegex        string `yaml:"unencrypted_regex"`
	EncryptedSuffix         string `yaml:"encrypted_suffix"`
	UnencryptedSuffix       string `yaml:"unencrypted_suffix"`
	EncryptedCommentRegex   string `yaml:"encrypted_comment_regex"`
	UnencryptedCommentRegex string `yaml:"unencrypted_comment_regex"`
	MACOnlyEncrypted        bool   `yaml:"mac_only_encrypted"`
}

// Rule maps file globs to recipients.
type Rule struct {
	Files      []string `yaml:"files"`
	Recipients []string `yaml:"recipients"`
	Options    `yaml:",inline"`
}

// Config is the parsed sopsman.yml.
type Config struct {
	Recipients map[string]Recipient `yaml:"recipients"`
	Groups     map[string][]string  `yaml:"groups"`
	Rules      []Rule               `yaml:"rules"`

	// Path is the absolute path of the loaded config file.
	Path string `yaml:"-"`
	// Root is the directory containing the config; rule globs are relative to it.
	Root string `yaml:"-"`
}

// Find returns the path of the nearest config file, searching from dir upward.
func Find(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		for _, name := range FileNames {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s found in this directory or any parent", strings.Join(FileNames, " or "))
		}
		dir = parent
	}
}

// Load reads, parses and validates the config at path.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	c.Path = abs
	c.Root = filepath.Dir(abs)
	return c, nil
}

// Parse parses and validates config bytes.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	for name := range c.Groups {
		if _, ok := c.Recipients[name]; ok {
			errs = append(errs, fmt.Errorf("name %q is both a recipient and a group", name))
		}
	}
	for name, r := range c.Recipients {
		n := 0
		for _, v := range r.Keys() {
			n += len(v)
		}
		if n == 0 {
			errs = append(errs, fmt.Errorf("recipient %q has no keys", name))
		}
	}
	for name := range c.Groups {
		if _, err := c.Resolve([]string{name}); err != nil {
			errs = append(errs, fmt.Errorf("group %q: %w", name, err))
		}
	}
	if len(c.Rules) == 0 {
		errs = append(errs, errors.New("no rules defined"))
	}
	for i, r := range c.Rules {
		prefix := fmt.Sprintf("rule %d", i+1)
		if len(r.Files) == 0 {
			errs = append(errs, fmt.Errorf("%s: files is empty", prefix))
		}
		for _, g := range r.Files {
			if !doublestar.ValidatePattern(g) {
				errs = append(errs, fmt.Errorf("%s: invalid glob %q", prefix, g))
			}
			if filepath.IsAbs(g) || strings.HasPrefix(g, "../") {
				errs = append(errs, fmt.Errorf("%s: glob %q must be relative to the config directory", prefix, g))
			}
		}
		if len(r.Recipients) == 0 {
			errs = append(errs, fmt.Errorf("%s: recipients is empty", prefix))
		} else if names, err := c.Resolve(r.Recipients); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", prefix, err))
		} else if len(names) == 0 {
			errs = append(errs, fmt.Errorf("%s: recipients resolve to no one", prefix))
		}
		set := 0
		for _, v := range []string{r.EncryptedRegex, r.UnencryptedRegex, r.EncryptedSuffix, r.UnencryptedSuffix, r.EncryptedCommentRegex, r.UnencryptedCommentRegex} {
			if v != "" {
				set++
			}
		}
		if set > 1 {
			errs = append(errs, fmt.Errorf("%s: only one of encrypted_regex, unencrypted_regex, encrypted_suffix, unencrypted_suffix, encrypted_comment_regex, unencrypted_comment_regex may be set", prefix))
		}
	}
	return errors.Join(errs...)
}

// Resolve expands recipient and group names into a sorted, de-duplicated list
// of recipient names.
func (c *Config) Resolve(names []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	var walk func(name string, stack []string) error
	walk = func(name string, stack []string) error {
		if slices.Contains(stack, name) {
			return fmt.Errorf("group cycle: %s", strings.Join(append(stack, name), " -> "))
		}
		if _, ok := c.Recipients[name]; ok {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
			return nil
		}
		members, ok := c.Groups[name]
		if !ok {
			return fmt.Errorf("unknown recipient or group %q", name)
		}
		for _, m := range members {
			if err := walk(m, append(stack, name)); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range names {
		if err := walk(n, nil); err != nil {
			return nil, err
		}
	}
	slices.Sort(out)
	return out, nil
}

// KeySpecs returns the de-duplicated keys of the given recipients, per key type.
func (c *Config) KeySpecs(recipients []string) map[string][]string {
	out := map[string][]string{}
	for _, name := range recipients {
		for typ, vals := range c.Recipients[name].Keys() {
			for _, v := range vals {
				if !slices.Contains(out[typ], v) {
					out[typ] = append(out[typ], v)
				}
			}
		}
	}
	return out
}
