// Package engine implements sopsman's commands over the discovered secret
// files: plan work for every file in parallel, then apply it in path order.
package engine

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"golang.org/x/sync/errgroup"

	"github.com/sun-asterisk-research/sopsman/internal/config"
	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/secret"
)

// Engine runs commands against one config.
type Engine struct {
	Config   *config.Config
	Services []keyservice.KeyServiceClient
	Out      io.Writer
	// Jobs bounds how many files are processed concurrently.
	Jobs int
	// Verbose shows full key errors for skipped files.
	Verbose bool

	mu       sync.Mutex
	keyNames map[string]string
}

// New returns an engine using the local key service.
func New(cfg *config.Config, out io.Writer) *Engine {
	return &Engine{
		Config:   cfg,
		Services: []keyservice.KeyServiceClient{keyservice.NewLocalClient()},
		Out:      out,
		Jobs:     8,
	}
}

// ErrFailed is returned when one or more files failed; details were printed.
var ErrFailed = errors.New("one or more files failed")

// Entries discovers the managed files, narrowed to paths (resolved against cwd).
func (e *Engine) Entries(cwd string, paths []string) ([]files.Entry, error) {
	cfgRel, err := filepath.Rel(e.Config.Root, e.Config.Path)
	if err != nil {
		return nil, err
	}
	all, err := files.Discover(e.Config.Root, e.Config.Rules, filepath.ToSlash(cfgRel))
	if err != nil {
		return nil, err
	}
	out, err := files.Filter(all, e.Config.Root, cwd, paths)
	if err == nil && len(paths) > 0 && len(out) == 0 {
		return nil, fmt.Errorf("no managed files match %s", strings.Join(paths, ", "))
	}
	return out, err
}

func (e *Engine) abs(rel string) string { return filepath.Join(e.Config.Root, filepath.FromSlash(rel)) }

// rule returns the rule, resolved recipient names and master keys for an entry.
func (e *Engine) rule(en files.Entry) (config.Rule, []string, []keys.MasterKey, error) {
	r := e.Config.Rules[en.Rule]
	names, err := e.Config.Resolve(r.Recipients)
	if err != nil {
		return r, nil, nil, err
	}
	ks, err := secret.BuildKeys(e.Config.KeySpecs(names))
	return r, names, ks, err
}

// describeKeys maps key ids back to recipient names for display.
func (e *Engine) describeKeys(ids []string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keyNames == nil {
		e.keyNames = map[string]string{}
		for name := range e.Config.Recipients {
			ks, err := secret.BuildKeys(e.Config.KeySpecs([]string{name}))
			if err != nil {
				continue
			}
			for _, k := range ks {
				e.keyNames[secret.KeyID(k)] = name
			}
		}
	}
	var out []string
	for _, id := range ids {
		if n, ok := e.keyNames[id]; ok {
			out = append(out, n)
		} else {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), ",")
}

// parallel runs fn for every entry with bounded concurrency and returns the
// results in entry order.
func parallel[T any](e *Engine, entries []files.Entry, fn func(files.Entry) T) []T {
	out := make([]T, len(entries))
	var g errgroup.Group
	g.SetLimit(max(e.Jobs, 1))
	for i, en := range entries {
		g.Go(func() error {
			out[i] = fn(en)
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func (e *Engine) line(status, path, detail string) {
	if detail != "" {
		fmt.Fprintf(e.Out, "  %-10s %s (%s)\n", status, path, detail)
	} else {
		fmt.Fprintf(e.Out, "  %-10s %s\n", status, path)
	}
}

func (e *Engine) noKeyDetail(err error) string {
	var nk *secret.NoKeyError
	if errors.As(err, &nk) && (nk.Cloud || e.Verbose) {
		msg := nk.Err.Error()
		if !e.Verbose {
			msg = firstLine(msg)
		}
		return "no key: " + msg
	}
	return "no key"
}

// noKeyHint explains how to diagnose a run in which no file could be decrypted.
func (e *Engine) noKeyHint(attempted, noKey int) {
	if attempted > 0 && attempted == noKey {
		fmt.Fprintln(e.Out, "hint: no file could be decrypted; check SOPS_AGE_KEY_FILE / SOPS_AGE_KEY or your other key sources (run with -v for details)")
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// writeFile writes data atomically with the given permissions.
func writeFile(name string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(name), "."+filepath.Base(name)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

func equalNormalized(en files.Entry, a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	na, _, errA := secret.Normalize(en.Format(), a)
	nb, _, errB := secret.Normalize(en.Format(), b)
	return errA == nil && errB == nil && bytes.Equal(na, nb)
}
