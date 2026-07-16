package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// entry is the generic write/read escape hatch: it operates on ANY DN (the
// counterpart of `search` on the write side), for entries the typed commands
// (user/group/ou/svc/config) don't cover. --config-bind targets cn=config.

var entryConfigBind bool

var entryCmd = &cobra.Command{
	Use:   "entry",
	Short: "Generic operations on any entry by DN (add/get/set/rename/delete)",
	Long: "Escape hatch for entries the typed commands don't cover — the write-side\n" +
		"counterpart of `search`. Uses the data bind; pass --config-bind to act on\n" +
		"cn=config with the config identity.",
}

// entryConnect opens the client for entry commands (data or config bind).
func entryConnect() (*ldapx.Client, error) {
	if entryConfigBind {
		return connectConfig()
	}
	return connect()
}

// ---- get ----------------------------------------------------------------

var entryGetCmd = &cobra.Command{
	Use:     "get <dn> [attr...]",
	Short:   "Read one entry by DN (base scope; all attributes if none named)",
	Args:    cobra.MinimumNArgs(1),
	Example: "  openldap-cli entry get 'cn=admins,ou=groups,dc=example,dc=org' member",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := entryConnect()
		if err != nil {
			return err
		}
		defer cli.Close()
		e, err := cli.ReadEntry(strings.TrimSpace(args[0]), args[1:])
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

// ---- add ----------------------------------------------------------------

var entryAddCmd = &cobra.Command{
	Use:   "add <dn> <attr=value>...",
	Short: "Create an entry from attr=value pairs (repeat a name for multi-values)",
	Long: "Generic add (the inline ldapadd). Pass every attribute as attr=value,\n" +
		"including objectClass. Repeat a name for multiple values.",
	Args: cobra.MinimumNArgs(2),
	Example: "  openldap-cli entry add 'cn=printer1,ou=devices,dc=example,dc=org' \\\n" +
		"    objectClass=device objectClass=top cn=printer1 serialNumber=XZ-42",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn := strings.TrimSpace(args[0])
		attrs := map[string][]string{}
		for _, kv := range args[1:] {
			name, val, ok := strings.Cut(kv, "=")
			if !ok || name == "" {
				return fmt.Errorf("expected attr=value, got %q", kv)
			}
			attrs[name] = append(attrs[name], val)
		}
		cli, err := entryConnect()
		if err != nil {
			return err
		}
		defer cli.Close()
		if err := cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("add %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Int("attrs", len(attrs)).Msg("entry added")
		return out.Emit(okResult{Action: "added", DN: dn})
	},
}

// ---- set ----------------------------------------------------------------

var entrySetAdd bool

var entrySetCmd = &cobra.Command{
	Use:   "set <dn> <attr> [value...]",
	Short: "Replace an attribute on any entry (delete it if no value; --add appends)",
	Long: "Replaces <attr> with the given value(s). With no value it deletes the\n" +
		"attribute. With --add it appends the value(s) instead of replacing\n" +
		"(e.g. add a group member).",
	Args: cobra.MinimumNArgs(2),
	Example: "  openldap-cli entry set 'cn=team,ou=groups,dc=example,dc=org' description 'Core team'\n" +
		"  openldap-cli entry set 'cn=team,ou=groups,dc=example,dc=org' member 'cn=x,ou=users,dc=example,dc=org' --add",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, attr, values := strings.TrimSpace(args[0]), args[1], args[2:]
		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		switch {
		case entrySetAdd:
			if len(values) == 0 {
				return fmt.Errorf("--add needs at least one value")
			}
			mod.Op = ldapx.ModAdd
			action = "added " + attr + " on"
		case len(values) == 0:
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		cli, err := entryConnect()
		if err != nil {
			return err
		}
		defer cli.Close()
		if err := cli.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Str("attr", attr).Msg("entry modified")
		return out.Emit(okResult{Action: action, DN: dn})
	},
}

// ---- rename -------------------------------------------------------------

var (
	entryNewSuperior string
	entryKeepOldRDN  bool
)

var entryRenameCmd = &cobra.Command{
	Use:   "rename <dn> <new-rdn>",
	Short: "Rename/move an entry (modrdn); --newsuperior moves it under another parent",
	Args:  cobra.ExactArgs(2),
	Example: "  openldap-cli entry rename 'cn=old,ou=groups,dc=example,dc=org' cn=new\n" +
		"  openldap-cli entry rename 'cn=x,ou=a,dc=example,dc=org' cn=x --newsuperior 'ou=b,dc=example,dc=org'",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, newRDN := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
		cli, err := entryConnect()
		if err != nil {
			return err
		}
		defer cli.Close()
		if err := cli.Rename(dn, newRDN, !entryKeepOldRDN, strings.TrimSpace(entryNewSuperior)); err != nil {
			return fmt.Errorf("rename %s: %w", dn, err)
		}
		parent := strings.TrimSpace(entryNewSuperior)
		if parent == "" {
			if i := strings.IndexByte(dn, ','); i >= 0 { // keep the original parent
				parent = dn[i+1:]
			}
		}
		newDN := newRDN
		if parent != "" {
			newDN += "," + parent
		}
		log.Debug().Str("from", dn).Str("rdn", newRDN).Msg("entry renamed")
		return out.Emit(okResult{Action: "renamed to", DN: newDN})
	},
}

// ---- delete -------------------------------------------------------------

var entryDeleteCmd = &cobra.Command{
	Use:     "delete <dn>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete any entry by DN (must be a leaf)",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli entry delete 'cn=printer1,ou=devices,dc=example,dc=org'",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn := strings.TrimSpace(args[0])
		cli, err := entryConnect()
		if err != nil {
			return err
		}
		defer cli.Close()
		if err := cli.Delete(dn); err != nil {
			return fmt.Errorf("delete %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("entry deleted")
		return out.Emit(okResult{Action: "deleted", DN: dn})
	},
}

func init() {
	entryCmd.PersistentFlags().BoolVar(&entryConfigBind, "config-bind", false, "bind as the config identity (for cn=config DNs)")
	entrySetCmd.Flags().BoolVar(&entrySetAdd, "add", false, "append the value(s) instead of replacing the attribute")
	entryRenameCmd.Flags().StringVar(&entryNewSuperior, "newsuperior", "", "new parent DN (move the entry)")
	entryRenameCmd.Flags().BoolVar(&entryKeepOldRDN, "keep-old-rdn", false, "keep the old RDN value as an attribute (deleteOldRDN=false)")

	entryCmd.AddCommand(entryGetCmd, entryAddCmd, entrySetCmd, entryRenameCmd, entryDeleteCmd)
	rootCmd.AddCommand(entryCmd)
}
