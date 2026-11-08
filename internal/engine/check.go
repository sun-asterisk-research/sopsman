package engine

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/secret"
)

type fileState struct {
	entry      files.Entry
	recipients []string
	plain, enc bool
	// encState: "missing", "ok", or a description of what is stale.
	encState string
	// decrypt: "yes", "no key", "-" (no encrypted file) or an error.
	decrypt string
	// drift is set when the plaintext differs from the decrypted content.
	drift bool
	err   error
}

func (e *Engine) inspect(en files.Entry) fileState {
	s := fileState{entry: en, encState: "missing", decrypt: "-"}
	rule, names, ks, err := e.rule(en)
	if err != nil {
		s.err = err
		return s
	}
	s.recipients = names
	plain, err := files.ReadOptional(e.abs(en.Plain))
	if err != nil {
		s.err = err
		return s
	}
	s.plain = plain != nil
	enc, err := files.ReadOptional(e.abs(en.Enc))
	if err != nil {
		s.err = err
		return s
	}
	if enc == nil {
		return s
	}
	s.enc = true
	f, err := secret.Load(en.Format(), enc)
	if err != nil {
		s.err = err
		return s
	}
	var stale []string
	want := secret.KeyIDsOf(ks)
	have := f.KeyIDs()
	if !slices.Equal(want, have) {
		var parts []string
		if add := diff(want, have); len(add) > 0 {
			parts = append(parts, "+"+e.describeKeys(add))
		}
		if rm := diff(have, want); len(rm) > 0 {
			parts = append(parts, "-"+e.describeKeys(rm))
		}
		stale = append(stale, "recipients "+strings.Join(parts, " "))
	}
	if !f.OptionsMatch(rule.Options) {
		stale = append(stale, "options")
	}
	s.encState = "ok"
	if len(stale) > 0 {
		s.encState = "stale " + strings.Join(stale, ", ")
	}
	decrypted, err := f.Decrypt(e.Services)
	var nk *secret.NoKeyError
	switch {
	case errors.As(err, &nk):
		s.decrypt = "no key"
	case err != nil:
		s.err = err
		return s
	default:
		s.decrypt = "yes"
		s.drift = plain != nil && !equalNormalized(en, plain, decrypted)
	}
	return s
}

// Check reports, without writing anything, every entry whose encrypted file is
// missing or stale, whose plaintext (when decryptable) differs from the
// encrypted content, or whose plaintext is tracked by git or not gitignored.
// It returns ErrFailed if any problem was found.
func (e *Engine) Check(entries []files.Entry) error {
	states := parallel(e, entries, e.inspect)
	git, skipped, err := e.gitState(entries)
	if err != nil {
		return err
	}
	if skipped != "" {
		fmt.Fprintf(e.Out, "warning: gitignore checks skipped: %s\n", skipped)
	}
	problems := 0
	report := func(path, msg string) {
		problems++
		e.line("problem", path, msg)
	}
	for _, s := range states {
		en := s.entry
		if s.err != nil {
			report(en.Plain, s.err.Error())
			continue
		}
		if s.plain && !s.enc {
			report(en.Plain, "not encrypted")
		}
		if strings.HasPrefix(s.encState, "stale") {
			report(en.Enc, s.encState)
		}
		if s.drift {
			report(en.Plain, "plaintext differs from encrypted file; run encrypt or decrypt")
		}
		if git != nil {
			if git.tracked[en.Plain] {
				report(en.Plain, "plaintext is tracked by git")
			} else if !git.ignored[en.Plain] {
				report(en.Plain, "plaintext is not gitignored")
			}
		}
	}
	fmt.Fprintf(e.Out, "%d files checked, %d problems\n", len(states), problems)
	if problems > 0 {
		return ErrFailed
	}
	return nil
}

// Status prints a table describing every entry.
func (e *Engine) Status(entries []files.Entry) error {
	states := parallel(e, entries, e.inspect)
	w := tabwriter.NewWriter(e.Out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "FILE\tRULE\tRECIPIENTS\tPLAINTEXT\tENCRYPTED\tDECRYPT")
	for _, s := range states {
		plain := "absent"
		if s.plain {
			plain = "present"
			if s.drift {
				plain = "modified"
			}
		}
		dec := s.decrypt
		if s.err != nil {
			dec = "error: " + firstLine(s.err.Error())
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\n", s.entry.Plain, s.entry.Rule+1,
			strings.Join(s.recipients, ","), plain, s.encState, dec)
	}
	return w.Flush()
}

type gitState struct {
	tracked map[string]bool
	ignored map[string]bool
}

// gitState returns which plaintext paths are tracked and which are ignored.
// It returns nil state and a non-empty reason when the git checks cannot run;
// the reason is empty when the config root is simply not in a git work tree.
func (e *Engine) gitState(entries []files.Entry) (*gitState, string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return nil, "git is not installed", nil
	}
	if out, err := e.gitCmd(nil, "rev-parse", "--is-inside-work-tree").CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "not a git repository") {
			return nil, "", nil
		}
		return nil, "git rev-parse failed: " + firstLine(msg), nil
	}
	st := &gitState{tracked: map[string]bool{}, ignored: map[string]bool{}}
	if len(entries) == 0 {
		return st, "", nil
	}
	var paths []string
	for _, en := range entries {
		paths = append(paths, en.Plain)
	}

	// Paths are relative to the config root, which is git's working directory.
	out, err := e.git(nil, "ls-files", "-z", "--", ".")
	if err != nil {
		return nil, "", err
	}
	for _, p := range splitNul(out) {
		st.tracked[p] = true
	}

	// --no-index also reports ignore patterns for tracked files; exit status 1
	// means nothing is ignored.
	out, err = e.gitCmd([]byte(strings.Join(paths, "\x00")+"\x00"), "check-ignore", "--no-index", "-z", "--stdin").Output()
	var exitErr *exec.ExitError
	if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() != 1) {
		return nil, "", fmt.Errorf("git check-ignore: %w", err)
	}
	for _, p := range splitNul(out) {
		st.ignored[p] = true
	}
	return st, "", nil
}

// gitCmd builds a git command run in the config root. Repository-location
// variables are removed: git hooks export GIT_DIR (and, in linked worktrees,
// no GIT_WORK_TREE), which would make git treat the config root as the top of
// the work tree. A relative GIT_INDEX_FILE would resolve against the wrong
// directory, so only an absolute one (such as a partial-commit index) is kept.
func (e *Engine) gitCmd(stdin []byte, args ...string) *exec.Cmd {
	cmd := exec.Command("git", append([]string{"-C", e.Config.Root}, args...)...)
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		switch name {
		case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_PREFIX":
			continue
		case "GIT_INDEX_FILE":
			if !filepath.IsAbs(val) {
				continue
			}
		}
		cmd.Env = append(cmd.Env, kv)
	}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	return cmd
}

func (e *Engine) git(stdin []byte, args ...string) ([]byte, error) {
	out, err := e.gitCmd(stdin, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", args[0], err)
	}
	return out, nil
}

func splitNul(b []byte) []string {
	var out []string
	for _, p := range strings.Split(string(b), "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func diff(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
