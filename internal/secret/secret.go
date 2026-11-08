// Package secret adapts the sops library to sopsman's encrypt and decrypt
// operations.
//
// sops exposes decryption publicly but keeps its encrypt command in package
// main, so encryption is assembled here from the library's public building
// blocks: stores, sops.Tree, sops.Metadata and aes.Cipher.
//
// Minimal diffs come from reusingCipher: values whose plaintext and path are
// unchanged keep their previous ciphertext, as long as the data key is kept.
package secret

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/aes"
	"github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/azkv"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	sopsconfig "github.com/getsops/sops/v3/config"
	"github.com/getsops/sops/v3/gcpkms"
	"github.com/getsops/sops/v3/hckms"
	"github.com/getsops/sops/v3/hcvault"
	"github.com/getsops/sops/v3/keys"
	"github.com/getsops/sops/v3/keyservice"
	"github.com/getsops/sops/v3/kms"
	"github.com/getsops/sops/v3/pgp"
	"github.com/getsops/sops/v3/stores/dotenv"
	"github.com/getsops/sops/v3/stores/ini"
	"github.com/getsops/sops/v3/stores/json"
	"github.com/getsops/sops/v3/stores/yaml"
	"github.com/getsops/sops/v3/version"

	"github.com/sun-asterisk-research/sopsman/internal/config"
)

// Indent is the YAML and JSON indentation of emitted files, matching
// `sops --indent 2`.
const Indent = 2

// NewStore returns the sops store for a format, configured with Indent.
func NewStore(f formats.Format) sops.Store {
	c := sopsconfig.StoresConfig{
		YAML:       sopsconfig.YAMLStoreConfig{Indent: Indent},
		JSON:       sopsconfig.JSONStoreConfig{Indent: Indent},
		JSONBinary: sopsconfig.JSONBinaryStoreConfig{Indent: Indent},
	}
	switch f {
	case formats.Yaml:
		return yaml.NewStore(&c.YAML)
	case formats.Json:
		return json.NewStore(&c.JSON)
	case formats.Dotenv:
		return dotenv.NewStore(&c.Dotenv)
	case formats.Ini:
		return ini.NewStore(&c.INI)
	default:
		return json.NewBinaryStore(&c.JSONBinary)
	}
}

// BuildKeys turns per-type key specs into sops master keys, ordered by
// config.KeyTypes.
func BuildKeys(specs map[string][]string) ([]keys.MasterKey, error) {
	var out []keys.MasterKey
	for _, typ := range config.KeyTypes {
		for _, v := range specs[typ] {
			ks, err := buildKey(typ, v)
			if err != nil {
				return nil, fmt.Errorf("%s key %q: %w", typ, v, err)
			}
			out = append(out, ks...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no keys")
	}
	return out, nil
}

func buildKey(typ, v string) ([]keys.MasterKey, error) {
	var out []keys.MasterKey
	switch typ {
	case "age":
		ks, err := age.MasterKeysFromRecipients(v)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			out = append(out, k)
		}
	case "pgp":
		for _, k := range pgp.MasterKeysFromFingerprintString(v) {
			out = append(out, k)
		}
	case "kms":
		for _, k := range kms.MasterKeysFromArnString(v, nil, "") {
			out = append(out, k)
		}
	case "gcp_kms":
		for _, k := range gcpkms.MasterKeysFromResourceIDString(v) {
			out = append(out, k)
		}
	case "azure_kv":
		ks, err := azkv.MasterKeysFromURLs(v)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			out = append(out, k)
		}
	case "hc_vault":
		ks, err := hcvault.NewMasterKeysFromURIs(v)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			out = append(out, k)
		}
	case "hckms":
		ks, err := hckms.NewMasterKeyFromKeyIDString(v)
		if err != nil {
			return nil, err
		}
		for _, k := range ks {
			out = append(out, k)
		}
	default:
		return nil, fmt.Errorf("unknown key type %q", typ)
	}
	return out, nil
}

// KeyID identifies a master key independently of its encrypted data key.
func KeyID(k keys.MasterKey) string { return k.TypeToIdentifier() + ":" + k.ToString() }

// KeyIDs returns the sorted, de-duplicated ids of all keys in the groups.
func KeyIDs(groups []sops.KeyGroup) []string {
	var out []string
	for _, g := range groups {
		for _, k := range g {
			if id := KeyID(k); !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// KeyIDsOf returns the sorted, de-duplicated ids of the given keys.
func KeyIDsOf(ks []keys.MasterKey) []string { return KeyIDs([]sops.KeyGroup{ks}) }

// effectiveOptions returns the encryption options sops actually applies:
// when no encrypt/unencrypt rule is set, sops leaves keys ending in
// "_unencrypted" in cleartext and records that suffix in the metadata
// (except for single-value stores such as binary files, which omit it on
// encryption and get it back as a default on load).
func effectiveOptions(o config.Options) config.Options {
	if o.EncryptedRegex == "" && o.UnencryptedRegex == "" && o.EncryptedSuffix == "" &&
		o.UnencryptedSuffix == "" && o.EncryptedCommentRegex == "" && o.UnencryptedCommentRegex == "" {
		o.UnencryptedSuffix = sops.DefaultUnencryptedSuffix
	}
	return o
}

func optionsOf(m sops.Metadata) config.Options {
	return config.Options{
		EncryptedRegex:          m.EncryptedRegex,
		UnencryptedRegex:        m.UnencryptedRegex,
		EncryptedSuffix:         m.EncryptedSuffix,
		UnencryptedSuffix:       m.UnencryptedSuffix,
		EncryptedCommentRegex:   m.EncryptedCommentRegex,
		UnencryptedCommentRegex: m.UnencryptedCommentRegex,
		MACOnlyEncrypted:        m.MACOnlyEncrypted,
	}
}

// applyOptions records the options in the metadata the way the sops CLI does.
func applyOptions(m *sops.Metadata, o config.Options, store sops.Store) {
	if svs, ok := store.(interface{ IsSingleValueStore() bool }); !ok || !svs.IsSingleValueStore() {
		o = effectiveOptions(o)
	}
	m.EncryptedRegex = o.EncryptedRegex
	m.UnencryptedRegex = o.UnencryptedRegex
	m.EncryptedSuffix = o.EncryptedSuffix
	m.UnencryptedSuffix = o.UnencryptedSuffix
	m.EncryptedCommentRegex = o.EncryptedCommentRegex
	m.UnencryptedCommentRegex = o.UnencryptedCommentRegex
	m.MACOnlyEncrypted = o.MACOnlyEncrypted
}

// NoKeyError reports that no available key could decrypt a file's data key.
type NoKeyError struct {
	// Cloud is true when the file has keys of a type other than age or pgp,
	// whose failures may be transient (expired credentials, network).
	Cloud bool
	Err   error
}

func (e *NoKeyError) Error() string { return "no key: " + e.Err.Error() }
func (e *NoKeyError) Unwrap() error { return e.Err }

// File is a loaded encrypted file.
type File struct {
	store sops.Store
	tree  sops.Tree
	// decrypted state, set by Decrypt
	cipher  *reusingCipher
	dataKey []byte
	plain   []byte
}

// Load parses an encrypted file without decrypting it. Recipients and options
// are readable without any key.
func Load(f formats.Format, data []byte) (*File, error) {
	store := NewStore(f)
	tree, err := store.LoadEncryptedFile(data)
	if err != nil {
		return nil, fmt.Errorf("parse encrypted file: %w", err)
	}
	return &File{store: store, tree: tree}, nil
}

// LastModified returns when the file's content was last encrypted, as
// recorded in its cleartext sops metadata.
func (f *File) LastModified() time.Time { return f.tree.Metadata.LastModified }

// KeyIDs returns the ids of the keys the file is encrypted to.
func (f *File) KeyIDs() []string { return KeyIDs(f.tree.Metadata.KeyGroups) }

// OptionsMatch reports whether the file was encrypted with the given options.
func (f *File) OptionsMatch(o config.Options) bool {
	return effectiveOptions(optionsOf(f.tree.Metadata)) == effectiveOptions(o)
}

// Decrypt decrypts the file and verifies its MAC. It returns a *NoKeyError
// when no available key can decrypt the data key; any other error means the
// file is corrupt or tampered with.
func (f *File) Decrypt(svcs []keyservice.KeyServiceClient) ([]byte, error) {
	if f.plain != nil {
		return f.plain, nil
	}
	key, err := f.tree.Metadata.GetDataKeyWithKeyServices(svcs, nil)
	if err != nil {
		cloud := false
		for _, g := range f.tree.Metadata.KeyGroups {
			for _, k := range g {
				if t := k.TypeToIdentifier(); t != age.KeyTypeIdentifier && t != pgp.KeyTypeIdentifier {
					cloud = true
				}
			}
		}
		return nil, &NoKeyError{Cloud: cloud, Err: err}
	}
	c := newReusingCipher()
	mac, err := f.tree.Decrypt(key, c)
	if err != nil {
		return nil, fmt.Errorf("decrypt values: %w", err)
	}
	fileMac, err := c.Decrypt(f.tree.Metadata.MessageAuthenticationCode, key, f.tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("decrypt MAC: %w", err)
	}
	if fileMac != mac {
		return nil, fmt.Errorf("MAC mismatch: file has %s, computed %s", fileMac, mac)
	}
	plain, err := f.store.EmitPlainFile(f.tree.Branches)
	if err != nil {
		return nil, fmt.Errorf("emit plaintext: %w", err)
	}
	f.cipher, f.dataKey, f.plain = c, key, plain
	return plain, nil
}

// Normalize parses plaintext and re-emits it, so that two plaintexts with the
// same content but different formatting compare equal.
func Normalize(f formats.Format, plain []byte) ([]byte, []sops.TreeBranch, error) {
	store := NewStore(f)
	branches, err := store.LoadPlainFile(plain)
	if err != nil {
		return nil, nil, fmt.Errorf("parse plaintext: %w", err)
	}
	if len(branches) < 1 {
		return nil, nil, errors.New("file cannot be completely empty, it must contain at least one document")
	}
	if store.HasSopsTopLevelKey(branches[0]) {
		return nil, nil, errors.New("plaintext contains a top-level 'sops' key; is it already encrypted?")
	}
	out, err := store.EmitPlainFile(withoutInlineComments(branches))
	if err != nil {
		return nil, nil, fmt.Errorf("emit plaintext: %w", err)
	}
	return out, branches, nil
}

// withoutInlineComments returns a copy of the branches in which every comment
// is a standalone comment. sops decryption loses the inline position of
// comments (it emits them on the line above), so comparisons must ignore it.
func withoutInlineComments(branches []sops.TreeBranch) []sops.TreeBranch {
	out := make([]sops.TreeBranch, len(branches))
	for i, b := range branches {
		out[i] = stripInline(b).(sops.TreeBranch)
	}
	return out
}

func stripInline(v interface{}) interface{} {
	switch v := v.(type) {
	case sops.Comment:
		return sops.Comment{Value: v.Value}
	case sops.TreeBranch:
		out := make(sops.TreeBranch, len(v))
		for i, item := range v {
			out[i] = sops.TreeItem{Key: stripInline(item.Key), Value: stripInline(item.Value)}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, x := range v {
			out[i] = stripInline(x)
		}
		return out
	default:
		return v
	}
}

// Action describes what Encrypt did.
type Action string

const (
	Unchanged Action = "unchanged"
	Created   Action = "created"
	Updated   Action = "updated"
	Rekeyed   Action = "rekeyed"
	Rotated   Action = "rotated"
)

// Request is the input to Encrypt.
type Request struct {
	Format formats.Format
	Plain  []byte
	// Existing is the current encrypted file, or nil if it does not exist.
	// If set, it must already be decrypted with the same key services.
	Existing *File
	Keys     []keys.MasterKey
	Options  config.Options
	// FilePath is recorded in the tree for sops audit events only.
	FilePath string
	Services []keyservice.KeyServiceClient
}

// Result is the output of Encrypt.
type Result struct {
	Action Action
	// Output is the new encrypted file content; nil when Action is Unchanged.
	Output []byte
	// Added and Removed list recipient key ids that changed.
	Added, Removed []string
}

// Encrypt produces the encrypted file for req, changing as little of the
// existing encrypted file as possible:
//
//   - content, recipients and options unchanged: nothing is written;
//   - a recipient removed: a new data key is generated (full re-encryption),
//     so the removed recipient cannot read future versions;
//   - recipients only added: the data key is kept and only the new recipients'
//     stanzas are added;
//   - content or options changed: the data key is kept and unchanged values
//     keep their ciphertext.
func Encrypt(req Request) (*Result, error) {
	normalized, branches, err := Normalize(req.Format, req.Plain)
	if err != nil {
		return nil, err
	}
	store := NewStore(req.Format)
	want := KeyIDsOf(req.Keys)

	if req.Existing == nil || req.Existing.dataKey == nil {
		if req.Existing != nil {
			return nil, errors.New("existing encrypted file must be decrypted before re-encryption")
		}
		out, err := encryptFresh(store, branches, req)
		if err != nil {
			return nil, err
		}
		return &Result{Action: Created, Output: out}, nil
	}

	old := req.Existing
	have := old.KeyIDs()
	added := diff(want, have)
	removed := diff(have, want)
	contentChanged := !bytes.Equal(normalized, old.plain)
	optionsChanged := !old.OptionsMatch(req.Options)

	if !contentChanged && !optionsChanged && len(added) == 0 && len(removed) == 0 {
		return &Result{Action: Unchanged}, nil
	}

	if len(removed) > 0 || len(old.tree.Metadata.KeyGroups) != 1 {
		out, err := encryptFresh(store, branches, req)
		if err != nil {
			return nil, err
		}
		return &Result{Action: Rotated, Output: out, Added: added, Removed: removed}, nil
	}

	meta := old.tree.Metadata
	group := slices.Clone(meta.KeyGroups[0])
	for _, k := range req.Keys {
		if slices.Contains(added, KeyID(k)) {
			if err := k.Encrypt(old.dataKey); err != nil {
				return nil, fmt.Errorf("encrypt data key for %s: %w", KeyID(k), err)
			}
			group = append(group, k)
		}
	}
	meta.KeyGroups = []sops.KeyGroup{group}
	applyOptions(&meta, req.Options, store)

	tree := sops.Tree{Metadata: meta, FilePath: req.FilePath, Branches: old.tree.Branches}
	action := Rekeyed
	if contentChanged || optionsChanged {
		tree.Branches = branches
		tree.Metadata.LastModified = time.Now().UTC()
		action = Updated
	}
	// When only recipients were added, LastModified is unchanged, so every
	// value and the MAC keep their ciphertext byte for byte.
	out, err := encryptTree(store, &tree, old.dataKey, old.cipher)
	if err != nil {
		return nil, err
	}
	return &Result{Action: action, Output: out, Added: added}, nil
}

func encryptFresh(store sops.Store, branches []sops.TreeBranch, req Request) ([]byte, error) {
	meta := sops.Metadata{KeyGroups: []sops.KeyGroup{req.Keys}, Version: version.Version}
	applyOptions(&meta, req.Options, store)
	tree := sops.Tree{Branches: branches, Metadata: meta, FilePath: req.FilePath}
	dataKey, errs := tree.GenerateDataKeyWithKeyServices(req.Services)
	if len(errs) > 0 {
		return nil, fmt.Errorf("encrypt data key: %w", errors.Join(errs...))
	}
	tree.Metadata.LastModified = time.Now().UTC()
	return encryptTree(store, &tree, dataKey, aes.NewCipher())
}

// encryptTree encrypts the tree's values and MAC with the given cipher, using
// tree.Metadata.LastModified as the MAC's additional data, and emits the file
// with exactly one trailing newline.
func encryptTree(store sops.Store, tree *sops.Tree, dataKey []byte, c sops.Cipher) ([]byte, error) {
	mac, err := tree.Encrypt(dataKey, c)
	if err != nil {
		return nil, fmt.Errorf("encrypt values: %w", err)
	}
	tree.Metadata.MessageAuthenticationCode, err = c.Encrypt(mac, dataKey, tree.Metadata.LastModified.Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("encrypt MAC: %w", err)
	}
	out, err := store.EmitEncryptedFile(*tree)
	if err != nil {
		return nil, fmt.Errorf("emit encrypted file: %w", err)
	}
	return append(bytes.TrimRight(out, "\n"), '\n'), nil
}

// diff returns the elements of a not in b.
func diff(a, b []string) []string {
	var out []string
	for _, v := range a {
		if !slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
