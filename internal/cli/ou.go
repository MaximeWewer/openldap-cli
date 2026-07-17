package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	dnpkg "github.com/MaximeWewer/openldap-cli/internal/dn"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

var ouCmd = &cobra.Command{
	Use:   "ou",
	Short: "Manage organizational units",
}

// ouParent backs the --parent flag of every ou subcommand (only one ever runs).
var ouParent string

// ouDN builds ou=<name>,<parent>, defaulting the parent to the base DN.
func ouDN(name string) (string, error) {
	parent := strings.TrimSpace(ouParent)
	if parent == "" {
		cfg, err := loadConfig()
		if err != nil {
			return "", err
		}
		parent = cfg.BaseDN
	}
	return "ou=" + dnpkg.EscapeValue(strings.TrimSpace(name)) + "," + parent, nil
}

// ---- create -------------------------------------------------------------

var ouCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an organizationalUnit",
	Long:  "Creates ou=<name> under --parent (a DN), or directly under the base DN.",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli ou create contractors\n" +
		"  openldap-cli ou create eu --parent ou=users,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		dn, err := ouDN(name)
		if err != nil {
			return err
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		attrs := map[string][]string{
			"objectClass": {"top", "organizationalUnit"},
			"ou":          {name},
		}
		if err := cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("create ou %s: %w", name, err)
		}
		log.Debug().Str("dn", dn).Msg("ou created")
		return out.Emit(okResult{Action: "created", DN: dn})
	},
}

// ---- list / info --------------------------------------------------------

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

var ouInfoCmd = &cobra.Command{
	Use:     "info <name>",
	Aliases: []string{"show", "get"},
	Short:   "Show an organizational unit",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli ou info users\n" +
		"  openldap-cli ou info eu --parent ou=users,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, err := ouDN(args[0])
		if err != nil {
			return err
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		e, err := cli.ReadEntry(dn, nil)
		if err != nil {
			return fmt.Errorf("read %s: %w", dn, err)
		}
		return out.Emit(newEntryResult(e))
	},
}

// ---- set ----------------------------------------------------------------

var ouSetForce bool

var ouSetCmd = &cobra.Command{
	Use:   "set <name> <attr> [value...]",
	Short: "Replace (or delete, if no value) a single attribute on an OU",
	Args:  cobra.MinimumNArgs(2),
	Example: "  openldap-cli ou set contractors description 'External staff'\n" +
		"  openldap-cli ou set contractors description                    # delete attribute",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, err := ouDN(args[0])
		if err != nil {
			return err
		}
		attr, values := args[1], args[2:]
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		if len(values) == 0 {
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		// a replace drops the values it was not shown — see guardReplace
		if !ouSetForce {
			if err := guardReplace(cli, dn, attr, values); err != nil {
				return err
			}
		}
		if err := cli.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Str("attr", attr).Msg("ou attribute modified")
		return out.Emit(okResult{Action: action, DN: dn})
	},
}

// ---- rename -------------------------------------------------------------

var ouRenameCmd = &cobra.Command{
	Use:   "rename <name> <new-name>",
	Short: "Rename an OU (modrdn); entries below it follow",
	Long: "Renames ou=<name> to ou=<new-name> under the same parent. The entries\n" +
		"below it keep their place and their DNs follow the new name.\n\n" +
		"The olcAccess rules naming the old DN — its own, or the entries under it —\n" +
		"are re-pointed at the new one, because slapd rewrites none of them and such\n" +
		"a rule silently stops matching. Needs the config bind; --no-fix-acl skips it.\n\n" +
		"To move an OU under a different parent, use `entry rename --newsuperior`.",
	Args:    cobra.ExactArgs(2),
	Example: "  openldap-cli ou rename contractors externals",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, err := ouDN(args[0])
		if err != nil {
			return err
		}
		newName := strings.TrimSpace(args[1])
		if newName == "" {
			return fmt.Errorf("the new name is empty")
		}
		newDN, err := ouDN(newName)
		if err != nil {
			return err
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		// deleteOldRDN: the old ou value must go, or the entry keeps both names
		if err := cli.Rename(dn, "ou="+dnpkg.EscapeValue(newName), true, ""); err != nil {
			return fmt.Errorf("rename %s: %w", dn, err)
		}
		log.Debug().Str("from", dn).Str("to", newDN).Msg("ou renamed")
		if err := fixACLRefs(dn, newDN); err != nil {
			return err
		}
		return out.Emit(okResult{Action: "renamed to", DN: newDN})
	},
}

// ---- delete -------------------------------------------------------------

var ouDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete an organizational unit (must be empty)",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, err := ouDN(args[0])
		if err != nil {
			return err
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		if err := cli.Delete(dn); err != nil {
			return fmt.Errorf("delete %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("ou deleted")
		return out.Emit(okResult{Action: "deleted", DN: dn})
	},
}

func init() {
	for _, c := range []*cobra.Command{ouCreateCmd, ouInfoCmd, ouSetCmd, ouRenameCmd, ouDeleteCmd} {
		c.Flags().StringVar(&ouParent, "parent", "", "parent DN (default: base DN)")
	}
	ouSetCmd.Flags().BoolVar(&ouSetForce, "force", false, "replace even if it drops values of a multi-valued attribute")
	withFixACLFlag(ouRenameCmd)
	ouCmd.AddCommand(ouCreateCmd, ouListCmd, ouInfoCmd, ouSetCmd, ouRenameCmd, ouDeleteCmd)
	rootCmd.AddCommand(ouCmd)
}
