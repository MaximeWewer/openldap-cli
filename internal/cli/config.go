package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect/modify cn=config (limits, databases, overlays, ACLs)",
	Long:  "Reads and writes the dynamic configuration. Needs the config bind\n(config_bind_dn, e.g. cn=adminconfig,cn=config).",
}

// ---- limits -------------------------------------------------------------

var configLimitsCmd = &cobra.Command{Use: "limits", Short: "Show or set search limits"}

var limitsDB string

var configLimitsGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show olcSizeLimit / olcTimeLimit / olcLimits on a database",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		e, err := cc.ReadEntry(limitsDB, []string{"olcSizeLimit", "olcTimeLimit", "olcLimits"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

var (
	limitsSize string
	limitsTime string
	limitsFor  string
)

var configLimitsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set global size/time limits, or a per-identity olcLimits with --for",
	Long: "Without --for: replaces the database's global olcSizeLimit/olcTimeLimit.\n" +
		"With --for <selector>: adds an olcLimits rule for that identity (e.g.\n" +
		"--for 'dn.exact=cn=admin,ou=users,dc=example,dc=org' --size unlimited).",
	Args: cobra.NoArgs,
	Example: "  openldap-cli --profile test config limits set --size 5000\n" +
		"  openldap-cli --profile test config limits set --for 'dn.exact=cn=admin,ou=users,dc=example,dc=org' --size unlimited --db 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		if limitsSize == "" && limitsTime == "" {
			return fmt.Errorf("pass --size and/or --time")
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		var mods []ldapx.Mod
		var detail string
		if limitsFor != "" {
			val := limitsFor
			if limitsSize != "" {
				val += " size=" + limitsSize
			}
			if limitsTime != "" {
				val += " time=" + limitsTime
			}
			mods = append(mods, ldapx.Mod{Op: ldapx.ModAdd, Name: "olcLimits", Values: []string{val}})
			detail = "olcLimits += " + val
		} else {
			if limitsSize != "" {
				mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "olcSizeLimit", Values: []string{limitsSize}})
			}
			if limitsTime != "" {
				mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "olcTimeLimit", Values: []string{limitsTime}})
			}
			detail = fmt.Sprintf("size=%s time=%s", limitsSize, limitsTime)
		}
		if err := cc.Modify(limitsDB, mods); err != nil {
			return fmt.Errorf("set limits on %s: %w", limitsDB, err)
		}
		log.Info().Str("db", limitsDB).Msg("limits updated")
		return out.Emit(okResult{Action: "limits set", DN: limitsDB, Detail: detail})
	},
}

// ---- db / overlay / acl introspection -----------------------------------

var configDBCmd = &cobra.Command{Use: "db", Short: "Databases"}

var configDBListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured databases (olcDatabase + suffix)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		entries, err := cc.Search("cn=config", "(objectClass=olcDatabaseConfig)",
			[]string{"olcDatabase", "olcSuffix"})
		if err != nil {
			return err
		}
		return out.Emit(toEntryList(entries))
	},
}

var configOverlayCmd = &cobra.Command{Use: "overlay", Short: "Overlays"}

var configOverlayListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured overlays",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		entries, err := cc.Search("cn=config", "(objectClass=olcOverlayConfig)", []string{"olcOverlay"})
		if err != nil {
			return err
		}
		return out.Emit(toEntryList(entries))
	},
}

var configACLCmd = &cobra.Command{Use: "acl", Short: "Access control"}

var configACLListCmd = &cobra.Command{
	Use:     "list <database-dn>",
	Short:   "List olcAccess rules on a database",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config acl list 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		e, err := cc.ReadEntry(strings.TrimSpace(args[0]), []string{"olcAccess"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

// toEntryList builds an entryList from raw entries.
func toEntryList(entries []*ldapx.Entry) entryList {
	var l entryList
	for _, e := range entries {
		l.Entries = append(l.Entries, newEntryResult(e))
	}
	return l
}

func init() {
	configLimitsGetCmd.Flags().StringVar(&limitsDB, "db", "olcDatabase={-1}frontend,cn=config", "database entry to read")
	configLimitsSetCmd.Flags().StringVar(&limitsDB, "db", "olcDatabase={-1}frontend,cn=config", "database entry to modify")
	configLimitsSetCmd.Flags().StringVar(&limitsSize, "size", "", "olcSizeLimit value (number or unlimited)")
	configLimitsSetCmd.Flags().StringVar(&limitsTime, "time", "", "olcTimeLimit value (seconds or unlimited)")
	configLimitsSetCmd.Flags().StringVar(&limitsFor, "for", "", "apply as olcLimits for this selector (e.g. dn.exact=...)")

	configLimitsCmd.AddCommand(configLimitsGetCmd, configLimitsSetCmd)
	configDBCmd.AddCommand(configDBListCmd)
	configOverlayCmd.AddCommand(configOverlayListCmd)
	configACLCmd.AddCommand(configACLListCmd)
	configCmd.AddCommand(configLimitsCmd, configDBCmd, configOverlayCmd, configACLCmd)
	rootCmd.AddCommand(configCmd)
}
