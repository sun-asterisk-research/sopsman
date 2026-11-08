package engine

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/secret"
)

type encryptPlan struct {
	entry  files.Entry
	result *secret.Result
	// warning is set when the file was skipped for a reason the user should see.
	warning string
	// stale is set when the plaintext is older than a differing encrypted file.
	stale bool
	err   error
}

// EncryptOptions controls Encrypt.
type EncryptOptions struct {
	// Force encrypts plaintexts even when the encrypted file is newer.
	Force bool
}

// Encrypt encrypts every entry whose plaintext exists, writing only files whose
// content, recipients or options changed. Files that cannot be decrypted are
// skipped; a plaintext present for such a file is reported as a warning.
//
// A plaintext whose content differs from an encrypted file that was encrypted
// after the plaintext was last modified is stale (for example, a teammate's
// newer version was pulled); it is refused unless opts.Force is set, so it
// cannot silently revert the newer content.
func (e *Engine) Encrypt(entries []files.Entry, opts EncryptOptions) error {
	plans := parallel(e, entries, func(en files.Entry) encryptPlan { return e.planEncrypt(en, opts) })
	failed := false
	for _, p := range plans {
		en := p.entry
		switch {
		case p.err != nil:
			failed = true
			e.line("error", en.Plain, p.err.Error())
		case p.stale:
			failed = true
			e.line("skipped", en.Plain, "encrypted file is newer than your plaintext; run decrypt first, or encrypt --force")
		case p.warning != "":
			e.line("warning", en.Plain, p.warning)
		case p.result == nil:
			// No plaintext: nothing to encrypt.
		case p.result.Action == secret.Unchanged:
			e.line("unchanged", en.Plain, "")
		default:
			if err := writeFile(e.abs(en.Enc), p.result.Output, 0o644); err != nil {
				failed = true
				e.line("error", en.Plain, err.Error())
				continue
			}
			e.line(string(p.result.Action), en.Plain, e.changeDetail(p.result))
		}
	}
	if failed {
		return ErrFailed
	}
	return nil
}

func (e *Engine) changeDetail(r *secret.Result) string {
	var parts []string
	if len(r.Added) > 0 {
		parts = append(parts, "+"+e.describeKeys(r.Added))
	}
	if len(r.Removed) > 0 {
		parts = append(parts, "-"+e.describeKeys(r.Removed))
	}
	if r.Action == secret.Rotated {
		parts = append(parts, "new data key")
	}
	return joinNonEmpty(parts)
}

func (e *Engine) planEncrypt(en files.Entry, opts EncryptOptions) encryptPlan {
	p := encryptPlan{entry: en}
	plain, err := files.ReadOptional(e.abs(en.Plain))
	if err != nil {
		p.err = err
		return p
	}
	enc, err := files.ReadOptional(e.abs(en.Enc))
	if err != nil || (plain == nil && enc == nil) {
		p.err = err
		return p
	}
	rule, _, ks, err := e.rule(en)
	if err != nil {
		p.err = err
		return p
	}
	req := secret.Request{
		Format:   en.Format(),
		Plain:    plain,
		Keys:     ks,
		Options:  rule.Options,
		FilePath: e.abs(en.Plain),
		Services: e.Services,
	}
	if enc != nil {
		f, err := secret.Load(en.Format(), enc)
		if err != nil {
			p.err = fmt.Errorf("%s: %w", en.Enc, err)
			return p
		}
		stale := !slices.Equal(f.KeyIDs(), secret.KeyIDsOf(ks)) || !f.OptionsMatch(rule.Options)
		if plain == nil && !stale {
			// Nothing to encrypt and nothing to re-key.
			return p
		}
		decrypted, err := f.Decrypt(e.Services)
		if err != nil {
			var nk *secret.NoKeyError
			switch {
			case !errors.As(err, &nk):
				p.err = fmt.Errorf("%s: %w", en.Enc, err)
			case plain != nil:
				p.warning = "plaintext present but " + e.noKeyDetail(err) + "; not encrypted"
			default:
				p.warning = "recipients or options changed but " + e.noKeyDetail(err) + "; not re-keyed"
			}
			return p
		}
		if plain == nil {
			// Re-key or rotate from the decrypted content.
			req.Plain = decrypted
		} else if !opts.Force && !equalNormalized(en, plain, decrypted) {
			info, err := os.Stat(e.abs(en.Plain))
			if err != nil {
				p.err = err
				return p
			}
			if f.LastModified().After(info.ModTime()) {
				p.stale = true
				return p
			}
		}
		req.Existing = f
	}
	p.result, p.err = secret.Encrypt(req)
	return p
}

func joinNonEmpty(parts []string) string {
	out := ""
	for _, s := range parts {
		if s == "" {
			continue
		}
		if out != "" {
			out += ", "
		}
		out += s
	}
	return out
}
