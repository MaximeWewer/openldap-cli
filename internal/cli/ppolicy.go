package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	dnpkg "github.com/MaximeWewer/openldap-cli/internal/dn"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

var ppolicyCmd = &cobra.Command{
	Use:     "ppolicy",
	Aliases: []string{"policy"},
	Short:   "Manage password policies (writes to ou=policies require a rootDN bind)",
}

// ---- set (create/update a named policy) ---------------------------------

var ppolicyFlags struct {
	minLength       int
	maxAge          int
	expireWarning   int
	inHistory       int
	maxFailure      int
	lockoutDuration int
	checkQuality    int
	lockout         bool
	mustChange      bool
	allowUserChange bool
}

// flagToAttr maps each --flag to its pwdPolicy attribute and string value.
func policyAttrEdits(cmd *cobra.Command) map[string]string {
	edits := map[string]string{}
	add := func(flag, attr, val string) {
		if cmd.Flags().Changed(flag) {
			edits[attr] = val
		}
	}
	f := ppolicyFlags
	add("min-length", "pwdMinLength", strconv.Itoa(f.minLength))
	add("max-age", "pwdMaxAge", strconv.Itoa(f.maxAge))
	add("expire-warning", "pwdExpireWarning", strconv.Itoa(f.expireWarning))
	add("in-history", "pwdInHistory", strconv.Itoa(f.inHistory))
	add("max-failure", "pwdMaxFailure", strconv.Itoa(f.maxFailure))
	add("lockout-duration", "pwdLockoutDuration", strconv.Itoa(f.lockoutDuration))
	add("check-quality", "pwdCheckQuality", strconv.Itoa(f.checkQuality))
	add("lockout", "pwdLockout", strings.ToUpper(strconv.FormatBool(f.lockout)))
	add("must-change", "pwdMustChange", strings.ToUpper(strconv.FormatBool(f.mustChange)))
	add("allow-user-change", "pwdAllowUserChange", strings.ToUpper(strconv.FormatBool(f.allowUserChange)))
	return edits
}

var ppolicySetCmd = &cobra.Command{
	Use:   "set <name>",
	Short: "Create or update a named password policy",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli --profile test-root ppolicy set strict \\\n" +
		"      --min-length 20 --max-failure 3 --lockout --lockout-duration 1800",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		edits := policyAttrEdits(cmd)

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := "cn=" + dnpkg.EscapeValue(name) + "," + cli.PolicyBase()
		existing, err := cli.Search(cli.PolicyBase(),
			fmt.Sprintf("(&(objectClass=pwdPolicy)(cn=%s))", ldapx.EscapeFilter(name)), []string{"cn"})
		if err != nil {
			return fmt.Errorf("lookup policy %s: %w", name, err)
		}

		if len(existing) > 0 {
			if len(edits) == 0 {
				return fmt.Errorf("policy %q exists; pass at least one setting to update", name)
			}
			mods := make([]ldapx.Mod, 0, len(edits))
			for attr, val := range edits {
				mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: []string{val}})
			}
			if err := cli.Modify(dn, mods); err != nil {
				return fmt.Errorf("update policy %s: %w", dn, err)
			}
			log.Debug().Str("dn", dn).Int("attrs", len(edits)).Msg("policy updated")
			return out.Emit(okResult{Action: "updated", DN: dn, Detail: fmt.Sprintf("%d setting(s)", len(edits))})
		}

		attrs := map[string][]string{
			"objectClass":  {"top", "applicationProcess", "pwdPolicy"},
			"cn":           {name},
			"pwdAttribute": {"userPassword"},
		}
		for attr, val := range edits {
			attrs[attr] = []string{val}
		}
		if err := cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("create policy %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("policy created")
		return out.Emit(okResult{Action: "created", DN: dn})
	},
}

// ---- assign -------------------------------------------------------------

var ppolicyAssignClear bool

var ppolicyAssignCmd = &cobra.Command{
	Use:   "assign <login> [policy-name]",
	Short: "Assign a password policy to a user (pwdPolicySubentry), or clear it",
	Long: "Sets pwdPolicySubentry on the user, overriding the default policy.\n" +
		"Use --clear (no policy-name) to revert the user to the default policy.\n\n" +
		"The policy must exist: a pwdPolicySubentry that does not resolve makes slapd\n" +
		"apply no policy at all to the user, rather than fall back to the default.",
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		if ppolicyAssignClear && len(args) > 1 {
			return fmt.Errorf("--clear takes no policy-name (got %q): pass one or the other", args[1])
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}
		mod := ldapx.Mod{Op: ldapx.ModDelete, Name: "pwdPolicySubentry"}
		action := "policy cleared on"
		if !ppolicyAssignClear {
			if len(args) < 2 {
				return fmt.Errorf("provide a policy-name, or use --clear")
			}
			// resolve rather than build: a name with a typo would otherwise be
			// written verbatim and silently disable policy for this user
			policyDN, rerr := resolvePolicy(cli, strings.TrimSpace(args[1]))
			if rerr != nil {
				return fmt.Errorf("%w\n\nRefused: assigning a policy that does not resolve does NOT fall back to\n"+
					"the default — slapd applies no policy at all to the user (no minimum\n"+
					"length, no lockout, no history) and the bind still succeeds.", rerr)
			}
			mod = ldapx.Mod{Op: ldapx.ModReplace, Name: "pwdPolicySubentry", Values: []string{policyDN}}
			action = "assigned " + policyDN + " to"
		}
		if err := cli.Modify(entry.DN, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("assign policy to %s: %w", entry.DN, err)
		}
		log.Debug().Str("dn", entry.DN).Bool("clear", ppolicyAssignClear).Msg("policy assignment changed")
		return out.Emit(okResult{Action: action, DN: entry.DN})
	},
}

// ---- list / show / delete ----------------------------------------------

var ppolicyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List password policies",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		entries, err := cli.Search(cli.PolicyBase(), "(objectClass=pwdPolicy)", []string{"cn"})
		if err != nil {
			return fmt.Errorf("search policies: %w", err)
		}
		return out.Emit(entriesToItems("policies", "cn", entries))
	},
}

var ppolicyShowCmd = &cobra.Command{
	Use:     "show <name>",
	Aliases: []string{"get", "info"},
	Short:   "Show a password policy's settings",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		dn := "cn=" + dnpkg.EscapeValue(strings.TrimSpace(args[0])) + "," + cli.PolicyBase()
		e, err := cli.ReadEntry(dn, []string{"cn", "pwdAttribute", "pwdMinLength", "pwdMaxAge",
			"pwdExpireWarning", "pwdInHistory", "pwdMaxFailure", "pwdLockout", "pwdLockoutDuration",
			"pwdCheckQuality", "pwdMustChange", "pwdAllowUserChange"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

var ppolicyDeleteForce bool

var ppolicyDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a password policy (needs a rootDN bind)",
	Long: "Refuses while users are still assigned to the policy, or while it is the\n" +
		"overlay default: slapd applies no policy at all to a user whose\n" +
		"pwdPolicySubentry does not resolve, so deleting a policy in use turns\n" +
		"password enforcement off for its users instead of reverting them to the\n" +
		"default. --force deletes anyway.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		dn, err := resolvePolicy(cli, strings.TrimSpace(args[0]))
		if err != nil {
			return err
		}
		if !ppolicyDeleteForce {
			if err := checkPolicyUnreferenced(cli, dn); err != nil {
				return err
			}
		}
		if err := cli.Delete(dn); err != nil {
			return fmt.Errorf("delete %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Bool("force", ppolicyDeleteForce).Msg("policy deleted")
		return out.Emit(okResult{Action: "deleted", DN: dn})
	},
}

var ppolicyCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Find policy references that do not resolve (such users have NO policy)",
	Long: "Scans every pwdPolicySubentry, and the overlay default, for references to a\n" +
		"missing entry or to one that is not a pwdPolicy. slapd applies no policy at\n" +
		"all to those users — it does not fall back to the default — so this state is\n" +
		"invisible until someone sets a weak password and the server takes it.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		res, err := checkPolicyRefs(cli)
		if err != nil {
			return err
		}
		log.Debug().Int("scanned", res.Scanned).Int("dangling", len(res.Dangling)).Msg("policy refs checked")
		return out.Emit(res)
	},
}

func init() {
	f := ppolicySetCmd.Flags()
	f.IntVar(&ppolicyFlags.minLength, "min-length", 0, "pwdMinLength")
	f.IntVar(&ppolicyFlags.maxAge, "max-age", 0, "pwdMaxAge (seconds)")
	f.IntVar(&ppolicyFlags.expireWarning, "expire-warning", 0, "pwdExpireWarning (seconds)")
	f.IntVar(&ppolicyFlags.inHistory, "in-history", 0, "pwdInHistory")
	f.IntVar(&ppolicyFlags.maxFailure, "max-failure", 0, "pwdMaxFailure")
	f.IntVar(&ppolicyFlags.lockoutDuration, "lockout-duration", 0, "pwdLockoutDuration (seconds)")
	f.IntVar(&ppolicyFlags.checkQuality, "check-quality", 0, "pwdCheckQuality (0-2)")
	f.BoolVar(&ppolicyFlags.lockout, "lockout", false, "pwdLockout")
	f.BoolVar(&ppolicyFlags.mustChange, "must-change", false, "pwdMustChange")
	f.BoolVar(&ppolicyFlags.allowUserChange, "allow-user-change", false, "pwdAllowUserChange")

	ppolicyAssignCmd.Flags().BoolVar(&ppolicyAssignClear, "clear", false, "revert user to the default policy")
	ppolicyDeleteCmd.Flags().BoolVar(&ppolicyDeleteForce, "force", false,
		"delete even if users are still assigned to it (they end up with no policy at all)")

	ppolicyCmd.AddCommand(ppolicySetCmd, ppolicyAssignCmd, ppolicyListCmd, ppolicyShowCmd,
		ppolicyDeleteCmd, ppolicyCheckCmd)
	rootCmd.AddCommand(ppolicyCmd)
}
