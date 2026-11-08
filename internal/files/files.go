// Package files discovers secret files and maps plaintext paths to their
// encrypted counterparts.
package files

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/getsops/sops/v3/cmd/sops/formats"

	"github.com/sun-asterisk-research/sopsman/internal/config"
)

// Entry is one managed secret: a plaintext path, its encrypted path, and the
// index of the first rule that matched either of them. Paths are slash-separated
// and relative to the config root.
type Entry struct {
	Plain string
	Enc   string
	Rule  int
}

// Format returns the sops format of the entry, chosen by file extension only.
func (e Entry) Format() formats.Format {
	return formats.FormatForPath(e.Plain)
}

var encName = regexp.MustCompile(`^(.*)\.enc(\.[^.]+)?$`)

// EncPath returns the encrypted path for a plaintext path:
// "a/secret.yaml" -> "a/secret.enc.yaml", "a/htpasswd" -> "a/htpasswd.enc".
func EncPath(plain string) string {
	dir, base := path.Split(plain)
	ext := path.Ext(base)
	if ext == "" {
		return dir + base + ".enc"
	}
	return dir + strings.TrimSuffix(base, ext) + ".enc" + ext
}

// PlainPath returns the plaintext path for an encrypted path, and whether the
// given path is an encrypted path at all. Only names produced by EncPath count
// as encrypted, so "x.yaml.enc" or a bare ".enc" are ordinary files.
func PlainPath(enc string) (string, bool) {
	dir, base := path.Split(enc)
	m := encName.FindStringSubmatch(base)
	if m == nil || m[1]+m[2] == "" {
		return "", false
	}
	plain := dir + m[1] + m[2]
	if EncPath(plain) != enc {
		return "", false
	}
	return plain, true
}

// Discover walks root and returns one entry per plaintext/encrypted pair of
// which at least one file exists, assigned to the first rule with a glob
// matching either path. The config file itself and .git directories are
// skipped. Results are sorted by plaintext path.
func Discover(root string, rules []config.Rule, exclude ...string) ([]Entry, error) {
	plains := map[string]bool{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if slices.Contains(exclude, rel) {
			return nil
		}
		if plain, ok := PlainPath(rel); ok {
			rel = plain
		}
		plains[rel] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	var out []Entry
	for plain := range plains {
		enc := EncPath(plain)
		if i := matchRule(rules, plain, enc); i >= 0 {
			out = append(out, Entry{Plain: plain, Enc: enc, Rule: i})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Plain < out[b].Plain })
	return out, nil
}

func matchRule(rules []config.Rule, paths ...string) int {
	for i, r := range rules {
		for _, g := range r.Files {
			for _, p := range paths {
				if ok, _ := doublestar.Match(g, p); ok {
					return i
				}
			}
		}
	}
	return -1
}

// Filter keeps entries whose plaintext or encrypted path equals, or lies under,
// one of the given paths. Paths are resolved against cwd and must lie inside
// root. No paths means no filtering.
func Filter(entries []Entry, root, cwd string, paths []string) ([]Entry, error) {
	if len(paths) == 0 {
		return entries, nil
	}
	var prefixes []string
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("path %q is outside the config directory %s", p, root)
		}
		prefixes = append(prefixes, filepath.ToSlash(rel))
	}
	var out []Entry
	for _, e := range entries {
		for _, pre := range prefixes {
			if pre == "." || under(e.Plain, pre) || under(e.Enc, pre) {
				out = append(out, e)
				break
			}
		}
	}
	return out, nil
}

func under(p, prefix string) bool {
	return p == prefix || strings.HasPrefix(p, prefix+"/")
}

// ReadOptional reads a file, returning nil data and no error if it does not exist.
func ReadOptional(name string) ([]byte, error) {
	data, err := os.ReadFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}
