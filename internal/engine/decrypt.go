package engine

import (
	"errors"
	"fmt"
	"os"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/secret"
)

// Choice is a user's answer to an overwrite prompt.
type Choice int

const (
	ChoiceNo Choice = iota
	ChoiceYes
	ChoiceDiff
)

// Prompter asks whether to overwrite a locally modified plaintext. A nil
// Prompter means the session is non-interactive.
type Prompter interface {
	Confirm(question string) (Choice, error)
}

// DecryptOptions controls Decrypt.
type DecryptOptions struct {
	// Force overwrites locally modified plaintexts without asking.
	Force    bool
	Prompter Prompter
}

type decryptPlan struct {
	entry files.Entry
	plain []byte
	local []byte
	// state is one of: "", "unchanged", "skipped", "write", "conflict".
	state  string
	detail string
	err    error
}

// Decrypt writes the plaintext (mode 0600) of every entry the available keys can
// decrypt. Entries without a key are skipped. When a local plaintext differs
// from the encrypted content, the user is asked; without a prompter the file
// is skipped and Decrypt returns ErrFailed, unless opts.Force is set.
func (e *Engine) Decrypt(entries []files.Entry, opts DecryptOptions) error {
	plans := parallel(e, entries, e.planDecrypt)
	failed := false
	attempted, noKey := 0, 0
	for _, p := range plans {
		if p.state != "" {
			attempted++
		}
	}
	defer func() { e.noKeyHint(attempted, noKey) }()
	for _, p := range plans {
		en := p.entry
		switch p.state {
		case "":
			if p.err != nil {
				failed = true
				e.line("error", en.Enc, p.err.Error())
			}
			continue
		case "skipped":
			noKey++
			e.line(p.state, en.Plain, p.detail)
			continue
		case "unchanged":
			// Tighten permissions of plaintexts written by other tools.
			if err := os.Chmod(e.abs(en.Plain), 0o600); err != nil {
				failed = true
				e.line("error", en.Plain, err.Error())
				continue
			}
			e.line(p.state, en.Plain, p.detail)
			continue
		case "conflict":
			ok, err := e.resolveConflict(p, opts)
			if err != nil {
				return err
			}
			if !ok {
				failed = true
				e.line("skipped", en.Plain, "local changes not overwritten")
				continue
			}
		}
		if err := writeFile(e.abs(en.Plain), p.plain, 0o600); err != nil {
			failed = true
			e.line("error", en.Plain, err.Error())
			continue
		}
		e.line("decrypted", en.Plain, "")
	}
	if failed {
		return ErrFailed
	}
	return nil
}

func (e *Engine) resolveConflict(p decryptPlan, opts DecryptOptions) (bool, error) {
	if opts.Force {
		return true, nil
	}
	if opts.Prompter == nil {
		return false, nil
	}
	q := fmt.Sprintf("%s differs from %s. Overwrite? [y]es / [n]o / [d]iff: ", p.entry.Plain, p.entry.Enc)
	for {
		c, err := opts.Prompter.Confirm(q)
		if err != nil {
			return false, err
		}
		switch c {
		case ChoiceYes:
			return true, nil
		case ChoiceNo:
			return false, nil
		case ChoiceDiff:
			fmt.Fprint(e.Out, unifiedDiff(p.local, p.plain, "local "+p.entry.Plain, "encrypted "+p.entry.Enc))
		}
	}
}

func unifiedDiff(a, b []byte, from, to string) string {
	s, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(a)),
		B:        difflib.SplitLines(string(b)),
		FromFile: from,
		ToFile:   to,
		Context:  3,
	})
	if err != nil {
		return err.Error() + "\n"
	}
	return s
}

func (e *Engine) planDecrypt(en files.Entry) decryptPlan {
	p := decryptPlan{entry: en}
	enc, err := files.ReadOptional(e.abs(en.Enc))
	if err != nil || enc == nil {
		p.err = err
		return p
	}
	f, err := secret.Load(en.Format(), enc)
	if err != nil {
		p.err = err
		return p
	}
	plain, err := f.Decrypt(e.Services)
	if err != nil {
		var nk *secret.NoKeyError
		if errors.As(err, &nk) {
			p.state, p.detail = "skipped", e.noKeyDetail(err)
		} else {
			p.err = err
		}
		return p
	}
	p.plain = plain
	local, err := files.ReadOptional(e.abs(en.Plain))
	switch {
	case err != nil:
		p.err = err
	case local == nil:
		p.state = "write"
	case string(local) == string(plain):
		p.state = "unchanged"
	case equalNormalized(en, local, plain):
		// Same content, different formatting: nothing would be lost.
		p.state = "write"
	default:
		p.state, p.local = "conflict", local
	}
	return p
}
