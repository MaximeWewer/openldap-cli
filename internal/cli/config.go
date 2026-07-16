package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/acl"
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
		log.Debug().Str("db", limitsDB).Msg("limits updated")
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
		log.Debug().Str("dn", dn).Int64("bytes", size).Msg("olcDbMaxSize updated")
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

var configACLMoveCmd = &cobra.Command{
	Use:   "move <database-dn> <from> <to>",
	Short: "Reorder an olcAccess rule (move rule {from} to position {to})",
	Long: "olcAccess is evaluated in index order and STOPS at the first rule whose\n" +
		"`to` target matches, so a specific rule placed below a broad one never\n" +
		"fires. This moves rule {from} to position {to} and renumbers the rest in\n" +
		"one atomic replace.\n\n" +
		"CAUTION: raising a narrow rule that ends in `by * none` above a broader\n" +
		"rule will block every identity the broader rule used to serve on that\n" +
		"entry (rootDN excepted). Give the narrow rule a `by * break` (or the\n" +
		"needed `by ... ` clauses) first — edit it with `config set` if so.",
	Args: cobra.ExactArgs(3),
	Example: "  # raise the vcf-admin rule {8} above the broad ou=groups rule {5}\n" +
		"  openldap-cli config acl move 'olcDatabase={1}mdb,cn=config' 8 5",
	RunE: func(cmd *cobra.Command, args []string) error {
		from, err := strconv.Atoi(strings.Trim(args[1], "{}"))
		if err != nil {
			return fmt.Errorf("from index %q: not a number", args[1])
		}
		to, err := strconv.Atoi(strings.Trim(args[2], "{}"))
		if err != nil {
			return fmt.Errorf("to index %q: not a number", args[2])
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		dn := strings.TrimSpace(args[0])
		e, err := cc.ReadEntry(dn, []string{"olcAccess"})
		if err != nil {
			return err
		}
		reordered, err := acl.Reorder(e.GetAll("olcAccess"), from, to)
		if err != nil {
			return err
		}
		if err := cc.Modify(dn, []ldapx.Mod{{Op: ldapx.ModReplace, Name: "olcAccess", Values: reordered}}); err != nil {
			return fmt.Errorf("reorder olcAccess on %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Int("from", from).Int("to", to).Msg("olcAccess reordered")
		return out.Emit(okResult{Action: fmt.Sprintf("moved olcAccess {%d} to {%d} on", from, to), DN: dn})
	},
}

// ---- grant / revoke (olcAccess by-clause on a subtree) ------------------

var (
	aclGrantGroup  string
	aclGrantDN     string
	aclGrantAccess string
	aclGrantScope  string
	aclGrantFilter string
	aclGrantAt     int
	aclGrantTerm   string
	aclRevokeGroup string
	aclRevokeDN    string
)

// validAccess reports whether a is a recognized olcAccess level.
func validAccess(a string) bool {
	switch a {
	case "none", "disclose", "auth", "compare", "search", "read", "write", "manage":
		return true
	}
	return false
}

// aclWho resolves a --group/--dn pair to an olcAccess who-token. A --group value
// containing "=" is used as a DN as-is; otherwise it is resolved by name under
// the group OU (via the data bind).
func aclWho(group, dn string) (string, error) {
	if (group == "") == (dn == "") {
		return "", fmt.Errorf("pass exactly one of --group or --dn")
	}
	if dn != "" {
		return acl.DNWho(strings.TrimSpace(dn)), nil
	}
	g := strings.TrimSpace(group)
	if !strings.Contains(g, "=") { // a bare name -> resolve to its DN
		cli, err := connect()
		if err != nil {
			return "", err
		}
		defer cli.Close()
		e, ferr := cli.FindGroup(g, []string{"cn"})
		if ferr != nil {
			return "", ferr
		}
		g = e.DN
	}
	return acl.GroupWho(g), nil
}

var configACLGrantCmd = &cobra.Command{
	Use:   "grant <database-dn> <subtree> --access <a> (--group <g> | --dn <d>)",
	Short: "Add a `by <who> <access>` clause to the rule protecting <subtree>",
	Long: "Grants access on <target> to a group (--group, all its members share the\n" +
		"right) or a single DN (--dn). The clause is inserted into the EXISTING rule\n" +
		"with the same selector, so multiple grantees coexist; a second rule with the\n" +
		"same `to` would be dead.\n\n" +
		"An app that must SEARCH a tree usually needs two grants: --scope base on the\n" +
		"container (to base/traverse the search) and a subtree grant to read entries,\n" +
		"optionally narrowed with --filter for least privilege. Use --at to place a\n" +
		"new rule ABOVE the broader rule that would otherwise shadow it.",
	Args: cobra.ExactArgs(2),
	Example: "  # let an app search ou=users and read ONLY members of a group\n" +
		"  openldap-cli config acl grant <db> 'ou=users,dc=example,dc=org' \\\n" +
		"      --dn 'cn=app,ou=service-accounts,dc=example,dc=org' --access search --scope base --at 6\n" +
		"  openldap-cli config acl grant <db> 'ou=users,dc=example,dc=org' \\\n" +
		"      --dn 'cn=app,ou=service-accounts,dc=example,dc=org' --access read \\\n" +
		"      --filter '(memberOf=cn=admins,ou=groups,dc=example,dc=org)' --at 7",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, target := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
		if !validAccess(aclGrantAccess) {
			return fmt.Errorf("--access must be one of none|disclose|auth|compare|search|read|write|manage")
		}
		scope := strings.TrimSpace(aclGrantScope)
		switch scope {
		case "sub", "subtree":
			scope = "subtree"
		case "base":
		default:
			return fmt.Errorf("--scope must be sub or base")
		}
		if aclGrantTerm != "break" && aclGrantTerm != "none" {
			return fmt.Errorf("--terminator must be break or none")
		}
		if f := strings.TrimSpace(aclGrantFilter); f != "" && !strings.HasPrefix(f, "(") {
			return fmt.Errorf("--filter must be an LDAP filter, e.g. '(memberOf=cn=g,dc=x)'")
		}
		who, err := aclWho(aclGrantGroup, aclGrantDN)
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		rule, appended, err := cc.InjectAccess(db, acl.InjectOpts{
			Target: target, Scope: scope, Filter: strings.TrimSpace(aclGrantFilter),
			Who: who, Access: aclGrantAccess, Terminator: aclGrantTerm, At: aclGrantAt,
		})
		if err != nil {
			return fmt.Errorf("grant on %s: %w", db, err)
		}
		log.Debug().Str("db", db).Str("who", who).Bool("new_rule", appended).Msg("olcAccess grant")
		res := okResult{Action: "granted " + aclGrantAccess + " to " + who + " on", DN: db, Detail: rule}
		if appended && aclGrantAt < 0 {
			res.Detail = rule + "\n  (new rule appended at the end — place it with --at, or move it with `config acl move`, so a broader rule above doesn't shadow it)"
		}
		return out.Emit(res)
	},
}

var configACLRevokeCmd = &cobra.Command{
	Use:     "revoke <database-dn> (--group <g> | --dn <d>)",
	Short:   "Remove every `by <who> …` clause referencing a group or DN",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config acl revoke 'olcDatabase={1}mdb,cn=config' --group readers",
	RunE: func(cmd *cobra.Command, args []string) error {
		db := strings.TrimSpace(args[0])
		who, err := aclWho(aclRevokeGroup, aclRevokeDN)
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		removed, err := cc.RemoveAccessGrantee(db, who)
		if err != nil {
			return fmt.Errorf("revoke on %s: %w", db, err)
		}
		log.Debug().Str("db", db).Str("who", who).Int("removed", removed).Msg("olcAccess revoke")
		return out.Emit(okResult{Action: fmt.Sprintf("revoked %d clause(s) for %s on", removed, who), DN: db})
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
		log.Debug().Str("dn", dn).Str("attr", attr).Msg("config attribute modified")
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
	configACLGrantCmd.Flags().StringVar(&aclGrantGroup, "group", "", "grant to all members of this group (name or DN)")
	configACLGrantCmd.Flags().StringVar(&aclGrantDN, "dn", "", "grant to this exact DN")
	configACLGrantCmd.Flags().StringVar(&aclGrantAccess, "access", "read", "access level: none|disclose|auth|compare|search|read|write|manage")
	configACLGrantCmd.Flags().StringVar(&aclGrantScope, "scope", "sub", "rule scope: sub (the tree) or base (the container entry only, to traverse/search)")
	configACLGrantCmd.Flags().StringVar(&aclGrantFilter, "filter", "", "narrow the rule to entries matching this LDAP filter, e.g. '(memberOf=cn=g,dc=x)'")
	configACLGrantCmd.Flags().IntVar(&aclGrantAt, "at", -1, "index to insert a NEW rule at (default -1: append at the end)")
	configACLGrantCmd.Flags().StringVar(&aclGrantTerm, "terminator", "break", "trailing `by *` of a NEW rule: break (additive) or none (blocks others)")
	configACLRevokeCmd.Flags().StringVar(&aclRevokeGroup, "group", "", "the group (name or DN) to revoke")
	configACLRevokeCmd.Flags().StringVar(&aclRevokeDN, "dn", "", "the exact DN to revoke")
	configACLCmd.AddCommand(configACLListCmd, configACLMoveCmd, configACLGrantCmd, configACLRevokeCmd)
	configCmd.AddCommand(configLimitsCmd, configDBCmd, configOverlayCmd, configACLCmd, configSetCmd)
	rootCmd.AddCommand(configCmd)
}
