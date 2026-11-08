// Package cli wires sopsman's commands.
package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/getsops/sops/v3/logging"
	sopsversion "github.com/getsops/sops/v3/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sun-asterisk-research/sopsman/internal/config"
	"github.com/sun-asterisk-research/sopsman/internal/engine"
	"github.com/sun-asterisk-research/sopsman/internal/files"
	"github.com/sun-asterisk-research/sopsman/internal/secret"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=...".
var Version = "dev"

type globals struct {
	configPath string
	jobs       int
	verbose    bool
}

// Execute runs the CLI and returns the process exit code.
func Execute(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := newRoot(stdin, stdout)
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.Execute(); err != nil {
		if !errors.Is(err, engine.ErrFailed) {
			fmt.Fprintln(stderr, "sopsman:", err)
		}
		return 1
	}
	return 0
}

func newRoot(stdin io.Reader, stdout io.Writer) *cobra.Command {
	g := &globals{}
	root := &cobra.Command{
		Use:           "sopsman",
		Short:         "Manage sops-encrypted secret files declared in sopsman.yml",
		Version:       fmt.Sprintf("%s (sops %s)", Version, sopsversion.Version),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			level := logrus.ErrorLevel
			if g.verbose {
				level = logrus.DebugLevel
			}
			logging.SetLevel(level)
		},
	}
	root.PersistentFlags().StringVarP(&g.configPath, "config", "c", "", "path to sopsman.yml (default: search upward from the current directory)")
	root.PersistentFlags().IntVarP(&g.jobs, "jobs", "j", 8, "number of files processed concurrently")
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "show sops debug logs")

	var force bool
	decrypt := &cobra.Command{
		Use:   "decrypt [paths...]",
		Short: "Decrypt every encrypted file you have a key for",
		Long: `Decrypt every encrypted file you have a key for, writing plaintext with mode 0600.
Files you have no key for are skipped. When a local plaintext has changes that
the encrypted file does not, you are asked whether to overwrite it; without a
terminal the file is skipped and the command fails, unless --force is given.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, entries, err := g.setup(stdout, args)
			if err != nil {
				return err
			}
			opts := engine.DecryptOptions{Force: force}
			if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				opts.Prompter = &linePrompter{in: bufio.NewReader(stdin), out: stdout}
			}
			return e.Decrypt(entries, opts)
		},
	}
	decrypt.Flags().BoolVarP(&force, "force", "f", false, "overwrite locally modified plaintexts without asking")

	var forceEncrypt bool
	encrypt := &cobra.Command{
		Use:   "encrypt [paths...]",
		Short: "Encrypt plaintext files whose content or recipients changed",
		Long: `Encrypt every plaintext matched by a rule into its .enc counterpart.
A file is rewritten only when its content, recipients or options changed, and
unchanged values keep their ciphertext so git diffs stay minimal. Files you
have no key for are skipped with a warning. A plaintext older than a differing
encrypted file (for example after pulling a newer version) is refused unless
--force is given.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			e, entries, err := g.setup(stdout, args)
			if err != nil {
				return err
			}
			return e.Encrypt(entries, engine.EncryptOptions{Force: forceEncrypt})
		},
	}
	encrypt.Flags().BoolVarP(&forceEncrypt, "force", "f", false, "encrypt plaintexts even when the encrypted file is newer")

	root.AddCommand(
		encrypt,
		decrypt,
		&cobra.Command{
			Use:   "check [paths...]",
			Short: "Fail if any encrypted file is missing or stale, or a plaintext could leak into git",
			RunE: func(cmd *cobra.Command, args []string) error {
				e, entries, err := g.setup(stdout, args)
				if err != nil {
					return err
				}
				return e.Check(entries)
			},
		},
		&cobra.Command{
			Use:   "status [paths...]",
			Short: "List managed files with their rule, recipients and state",
			RunE: func(cmd *cobra.Command, args []string) error {
				e, entries, err := g.setup(stdout, args)
				if err != nil {
					return err
				}
				return e.Status(entries)
			},
		},
		newRecipientCmd(g, stdout),
	)
	return root
}

func (g *globals) load() (*config.Config, error) {
	path := g.configPath
	if path == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		if path, err = config.Find(cwd); err != nil {
			return nil, err
		}
	}
	return config.Load(path)
}

func (g *globals) setup(out io.Writer, args []string) (*engine.Engine, []files.Entry, error) {
	cfg, err := g.load()
	if err != nil {
		return nil, nil, err
	}
	e := engine.New(cfg, out)
	e.Jobs = g.jobs
	e.Verbose = g.verbose
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, err
	}
	entries, err := e.Entries(cwd, args)
	if err != nil {
		return nil, nil, err
	}
	if len(entries) == 0 {
		fmt.Fprintln(out, "no managed files found")
	}
	return e, entries, nil
}

func newRecipientCmd(g *globals, stdout io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recipient",
		Short: "Add or remove recipients in sopsman.yml",
	}
	keys := map[string]*[]string{}
	var groups []string
	add := &cobra.Command{
		Use:   "add NAME",
		Short: "Add a recipient, optionally to groups; run encrypt afterwards to re-key files",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path, err := g.path()
			if err != nil {
				return err
			}
			spec := map[string][]string{}
			for typ, v := range keys {
				spec[typ] = *v
			}
			if _, err := secret.BuildKeys(spec); err != nil {
				return fmt.Errorf("invalid key: %w", err)
			}
			if err := config.AddRecipient(path, args[0], spec, groups); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "added recipient %s; run `sopsman encrypt` to re-key affected files\n", args[0])
			return nil
		},
	}
	for _, typ := range config.KeyTypes {
		v := []string{}
		keys[typ] = &v
		add.Flags().StringSliceVar(&v, strings.ReplaceAll(typ, "_", "-"), nil, typ+" key (repeatable)")
	}
	add.Flags().StringSliceVarP(&groups, "group", "g", nil, "group to add the recipient to (repeatable)")

	remove := &cobra.Command{
		Use:   "remove NAME",
		Short: "Remove a recipient and its group and rule references; run encrypt afterwards to rotate keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			path, err := g.path()
			if err != nil {
				return err
			}
			if err := config.RemoveRecipient(path, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(stdout, "removed recipient %s; run `sopsman encrypt` to rotate data keys of affected files\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(add, remove)
	return cmd
}

func (g *globals) path() (string, error) {
	if g.configPath != "" {
		return g.configPath, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return config.Find(cwd)
}

type linePrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *linePrompter) Confirm(q string) (engine.Choice, error) {
	for {
		fmt.Fprint(p.out, q)
		line, err := p.in.ReadString('\n')
		if err != nil && line == "" {
			return engine.ChoiceNo, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			return engine.ChoiceYes, nil
		case "n", "no", "":
			return engine.ChoiceNo, nil
		case "d", "diff":
			return engine.ChoiceDiff, nil
		}
	}
}
