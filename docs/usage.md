# sopsman

sopsman manages sops-encrypted secret files declared in `sopsman.yml`. It is a
single Go binary that embeds [sops](https://github.com/getsops/sops), so the
`sops` CLI does not need to be installed.

- `encrypt` rewrites an `.enc` file only when its content, recipients or
  options changed, and keeps the ciphertext of unchanged values, so git diffs
  show only what changed.
- `decrypt` decrypts only the files you have a key for and never silently
  overwrites local edits.

## Install

Download a binary for Linux or macOS (amd64 or arm64) from the
[releases page](https://github.com/sun-asterisk-research/sopsman/releases),
for example:

```sh
curl -sSfL -o sopsman https://github.com/sun-asterisk-research/sopsman/releases/download/v0.1.0/sopsman_linux_amd64
chmod +x sopsman
```

Each release has a `checksums.txt` with the SHA-256 checksums of its binaries.
Or build from source:

```sh
CGO_ENABLED=0 go install github.com/sun-asterisk-research/sopsman@latest
```

## Configuration

Place `sopsman.yml` at the root of the tree it manages. Commands search for it
upward from the current directory; `--config` overrides that. Rule globs are
relative to the config's directory.

```yaml
recipients:
  alice: { age: age1... }
  bob:
    age: age1...
    pgp: 85D77543B3D624B63CEA9E6DBC17301B491B3F21
  fluxcd-production: { age: age1... }
  ci: { kms: "arn:aws:kms:eu-west-1:111111111111:key/..." }

groups:                          # groups may contain recipients or groups
  operators: [alice, bob]
  prod: [operators, fluxcd-production]

rules:                           # the first rule matching a file wins
  - files: ["{apps,infrastructure}/production/**/{secret,values}*.*"]
    recipients: [prod]
  - files: ["apps/**/secret*.yaml"]
    recipients: [operators, ci]
    encrypted_regex: ^(data|stringData)$
```

**Recipients.** Each recipient has one or more keys. Supported key types:
`age`, `pgp`, `kms`, `gcp_kms`, `azure_kv`, `hc_vault`, `hckms`. A key type
takes either a string (comma-separated values allowed) or a list.

**Rules.** `files` lists [doublestar](https://github.com/bmatcuk/doublestar)
globs (`**`, `{a,b}`, `[...]`). A rule matches a secret if a glob matches
either its plaintext path or its encrypted path, so a rule naming
`app/secret.yaml` also manages a fresh clone that has only
`app/secret.enc.yaml`. Rules may set one sops option:
`encrypted_regex`, `unencrypted_regex`, `encrypted_suffix`,
`unencrypted_suffix`, `encrypted_comment_regex` or `unencrypted_comment_regex`.
They may also set `mac_only_encrypted: true`. Without an option, keys ending in
`_unencrypted` stay in cleartext, as with the sops CLI.

**File names.** `dir/secret.yaml` is encrypted to `dir/secret.enc.yaml`. A
file with no extension, such as `dir/htpasswd`, is encrypted to
`dir/htpasswd.enc`. Add the plaintext names to `.gitignore`; `sopsman check`
verifies that you did.

**Formats.** The format comes from the file extension only, exactly as in the
sops CLI, Flux and helm-secrets. `.yaml`/`.yml`, `.json`, `.env` and `.ini` are
encrypted value by value; every other file is encrypted as one binary blob. To
encrypt a structured file as a blob (for example a templated `values.yaml`
that is not valid YAML), rename it, for example to `values.yaml.tmpl`.

## Commands

Every command accepts paths (files or directories) that narrow it to the
matching secrets.

| Command | What it does |
|---|---|
| `sopsman encrypt [paths] [--force]` | Encrypts plaintexts whose content, recipients or options changed. |
| `sopsman decrypt [paths] [--force]` | Decrypts every file you have a key for, writing plaintext with mode 0600. |
| `sopsman check [paths]` | Writes nothing; exits 1 on any problem (see below). |
| `sopsman status [paths]` | Shows each file's rule, recipients, plaintext and encrypted state, and whether you can decrypt it. |
| `sopsman recipient add NAME --age KEY [-g GROUP]...` | Adds a recipient to the config, and to the given groups. |
| `sopsman recipient remove NAME` | Removes a recipient and every reference to it. |

Global flags: `-c/--config`, `-j/--jobs` (concurrency, default 8),
`-v/--verbose` (full key errors and sops debug logs). Paths that match no
managed file are an error. The config file itself is never managed, even when
a glob matches it.

sops loads your keys separately for every file. With a passphrase-protected
age identity, `SOPS_AGE_KEY_CMD`, an age plugin or a hardware token, use
`-j 1` so that prompts and devices are used one file at a time.

Pin `azure_kv` keys to a version (`https://vault/keys/name/version`). Without
a version, every run asks Azure for the latest version, which needs
credentials even for `check`, and a new key version re-keys every file.

### encrypt

```text
$ sopsman encrypt
  unchanged  apps/production/grafana/secret.yaml
  updated    apps/production/loki/values.yaml
  rekeyed    apps/production/app/secret.env (+carol)
  rotated    tg/clusters/terraform.tfvars (-dave, new data key)
  warning    apps/staging/x/secret.yaml (plaintext present but no key; not encrypted)
```

| Status | Meaning |
|---|---|
| `created` | No encrypted file existed. |
| `unchanged` | Nothing to do. Formatting-only changes count as unchanged. |
| `updated` | Content or options changed. The data key is kept, and unchanged values keep their ciphertext. |
| `rekeyed` | Recipients were only added. Only their key stanzas are added. |
| `rotated` | A recipient was removed. A new data key is generated so the removed recipient cannot read future versions. |
| `warning` | You have no key for the existing encrypted file, so your local plaintext was not encrypted. |
| `skipped` | The encrypted file was encrypted after your plaintext was last modified, and their contents differ. Typically you pulled a teammate's newer version. Run `sopsman decrypt` first, or `sopsman encrypt --force` to encrypt your plaintext anyway. The command exits 1. |

Files you have no key for are skipped; the exit code is still 0. When the
config's recipients or options changed but the plaintext is absent, encrypt
re-keys or rotates the file from its decrypted content without writing a
plaintext.

### decrypt

When a local plaintext differs from the encrypted content, decrypt asks
`Overwrite? [y]es / [n]o / [d]iff`. Without a terminal it skips the file and
exits 1; `--force` overwrites without asking. A local file that differs only in
formatting is overwritten without asking.

### check

Exits 1 when any of these is true:

- a plaintext has no encrypted file;
- an encrypted file's recipients or options do not match the config;
- a plaintext you can decrypt differs from its encrypted file;
- a plaintext path is tracked by git or not covered by `.gitignore`.

`check` also works in git hooks, including in linked worktrees. If git is
missing or fails, `check` prints a warning that the gitignore checks were
skipped.

CI usually has neither keys nor plaintexts. There, `check` still verifies
recipients, options and `.gitignore` coverage, because sops metadata is
readable without a key.

### Changing recipients

```sh
sopsman recipient add carol --age age1... -g operators
sopsman encrypt     # adds carol's key stanza to every file she can now read
sopsman recipient remove dave
sopsman encrypt     # rotates the data key of every file dave could read
```

Re-keying needs to decrypt each file, so run it as someone who can decrypt all
affected files.

## Files written by other sops versions

When sopsman next rewrites a file written by an older sops version, the
metadata block may be reformatted once, for example by key-stanza field order
or by dropped empty key lists. The current sops CLI does the same; values are
not affected.

## Development

```sh
CGO_ENABLED=0 go test ./...          # unit, CLI and end-to-end tests
CGO_ENABLED=0 go test -short ./...   # skip the end-to-end suite
```

The end-to-end suite (`e2e/`) builds the binary and drives it against a
fixture project (`e2e/testdata/project`). The project has every supported
format, three generated age identities (two operators and a cluster key) and
real git repositories. It never reads your own keys or git config. When the
`sops` binary is installed, it also checks that sops decrypts sopsman's
output.

To publish a release, push a tag such as `v0.1.0`. The release workflow
(`.github/workflows/release.yml`) runs the tests, builds the binaries and
attaches them to a GitHub release with generated notes.
