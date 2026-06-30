package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/humanize"
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

var configDBResizeCmd = &cobra.Command{
	Use:   "resize <database-dn> <size>",
	Short: "Set olcDbMaxSize on an mdb database (accepts 4GiB, 512MiB, or raw bytes)",
	Long: "Sets olcDbMaxSize (the LMDB map size). <size> takes a human value\n" +
		"(4GiB, 512MiB, 2G) or a plain byte count. Grow only — LMDB cannot shrink\n" +
		"below the data in use.\n\n" +
		"WARNING: changing olcDbMaxSize remaps the LMDB env. On a live, busy server\n" +
		"this can briefly interrupt or even restart slapd (the remap races with\n" +
		"active transactions). The change is persisted to cn=config and applied\n" +
		"regardless — prefer a quiet window.",
	Args:    cobra.ExactArgs(2),
	Example: "  openldap-cli config db resize 'olcDatabase={1}mdb,cn=config' 4GiB",
	RunE: func(cmd *cobra.Command, args []string) error {
		size, err := humanize.ParseBytes(args[1])
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		dn := strings.TrimSpace(args[0])

		// olcDbMaxSize remaps the LMDB env; on a busy server this can briefly
		// interrupt or restart slapd. The change still persists either way.
		log.Warn().Str("dn", dn).Msg("resizing olcDbMaxSize remaps the LMDB env and may briefly interrupt or restart slapd under load; the new size is persisted")

		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: "olcDbMaxSize", Values: []string{strconv.FormatInt(size, 10)}}
		if err := cc.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("resize %s: %w", dn, err)
		}
		log.Info().Str("dn", dn).Int64("bytes", size).Msg("olcDbMaxSize updated")
		return out.Emit(okResult{Action: "olcDbMaxSize set to " + humanize.Bytes(size) + " on", DN: dn})
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

// ---- set (generic cn=config attribute) ----------------------------------

var configSetCmd = &cobra.Command{
	Use:   "set <dn> <attr> [value...]",
	Short: "Set (or delete, if no value) an attribute on a cn=config entry",
	Long: "Generic cn=config writer (the config-tree counterpart of `user set`).\n" +
		"Replaces <attr> with the given value(s), or deletes it when none are given.",
	Args: cobra.MinimumNArgs(2),
	Example: "  # enable logging of successful operations in the accesslog overlay\n" +
		"  openldap-cli config set 'olcOverlay={4}accesslog,olcDatabase={1}mdb,cn=config' olcAccessLogSuccess TRUE\n" +
		"  openldap-cli config set 'olcDatabase={1}mdb,cn=config' olcDbMaxSize 2147483648",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, attr, values := args[0], args[1], args[2:]
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		if len(values) == 0 {
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		if err := cc.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", dn, err)
		}
		log.Info().Str("dn", dn).Str("attr", attr).Msg("config attribute modified")
		return out.Emit(okResult{Action: action, DN: dn})
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
	configDBCmd.AddCommand(configDBListCmd, configDBResizeCmd)
	configOverlayCmd.AddCommand(configOverlayListCmd)
	configACLCmd.AddCommand(configACLListCmd)
	configCmd.AddCommand(configLimitsCmd, configDBCmd, configOverlayCmd, configACLCmd, configSetCmd)
	rootCmd.AddCommand(configCmd)
}
