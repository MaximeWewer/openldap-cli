package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var ouCmd = &cobra.Command{
	Use:   "ou",
	Short: "Manage organizational units",
}

var ouCreateParent string

var ouCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an organizationalUnit",
	Long:  "Creates ou=<name> under --parent (a DN), or directly under the base DN.",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli ou create contractors\n" +
		"  openldap-cli ou create eu --parent ou=users,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		parent := strings.TrimSpace(ouCreateParent)
		if parent == "" {
			parent = cfg.BaseDN
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := "ou=" + name + "," + parent
		attrs := map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {name},
		}
		if err := cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("create ou %s: %w", name, err)
		}
		log.Info().Str("dn", dn).Msg("ou created")
		return out.Emit(okResult{Action: "created", DN: dn})
	},
}

var ouListCmd = &cobra.Command{
	Use:   "list",
	Short: "List organizational units",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		entries, err := cli.Search(cli.Config().BaseDN, "(objectClass=organizationalUnit)", []string{"ou"})
		if err != nil {
			return fmt.Errorf("search ous: %w", err)
		}
		return out.Emit(entriesToItems("ous", "ou", entries))
	},
}

var ouDeleteParent string

var ouDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete an organizational unit (must be empty)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		parent := strings.TrimSpace(ouDeleteParent)
		if parent == "" {
			parent = cfg.BaseDN
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		dn := "ou=" + strings.TrimSpace(args[0]) + "," + parent
		if err := cli.Delete(dn); err != nil {
			return fmt.Errorf("delete %s: %w", dn, err)
		}
		log.Info().Str("dn", dn).Msg("ou deleted")
		return out.Emit(okResult{Action: "deleted", DN: dn})
	},
}

func init() {
	ouCreateCmd.Flags().StringVar(&ouCreateParent, "parent", "", "parent DN (default: base DN)")
	ouDeleteCmd.Flags().StringVar(&ouDeleteParent, "parent", "", "parent DN (default: base DN)")
	ouCmd.AddCommand(ouCreateCmd, ouListCmd, ouDeleteCmd)
	rootCmd.AddCommand(ouCmd)
}
