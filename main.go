// Command sopsman manages sops-encrypted secret files declared in sopsman.yml.
package main

import (
	"os"

	"github.com/sun-asterisk-research/sopsman/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
