package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldif"
)

var importLdifStopOnError bool

var importLdifCmd = &cobra.Command{
	Use:   "import-ldif <file>",
	Short: "Add entries from an LDIF file (changetype: add)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		entries, err := ldif.Parse(f)
		if err != nil {
			return fmt.Errorf("parse ldif: %w", err)
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		var res importResult
		for _, e := range entries {
			attrs := map[string][]string{}
			for _, a := range e.Attrs {
				attrs[a.Name] = a.Values
			}
			if err := cli.AddEntry(e.DN, attrs); err != nil {
				res.Failed = append(res.Failed, importIssue{e.DN, err.Error()})
				if importLdifStopOnError {
					return fmt.Errorf("add %s: %w", e.DN, err)
				}
				continue
			}
			res.Created = append(res.Created, e.DN)
		}
		log.Info().Int("created", len(res.Created)).Int("failed", len(res.Failed)).Msg("ldif import done")
		return out.Emit(res)
	},
}

func init() {
	importLdifCmd.Flags().BoolVar(&importLdifStopOnError, "stop-on-error", false, "abort on the first failing entry")
	rootCmd.AddCommand(importLdifCmd)
}
