package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/pwd"
)

// Plural command scopes (users/groups/svcs) = bulk actions, distinct from the
// singular user/group/svc commands which act on one target.

// userSelectors holds the target-selection flags for one bulk command. Each
// command owns its own instance — no shared global state.
type userSelectors struct {
	group     string
	filter    string
	allLocked bool
	yes       bool
	stopOnErr bool
}

func (s *userSelectors) bind(c *cobra.Command, withLocked bool) {
	f := c.Flags()
	f.StringVar(&s.group, "group", "", "target all members of this group")
	f.StringVar(&s.filter, "filter", "", "target users matching this LDAP filter")
	if withLocked {
		f.BoolVar(&s.allLocked, "all-locked", false, "target all ppolicy-locked users")
	}
	f.BoolVar(&s.yes, "yes", false, "confirm acting on a selector's matches")
	f.BoolVar(&s.stopOnErr, "stop-on-error", false, "abort on the first failure")
}

func (s *userSelectors) used() bool { return s.group != "" || s.filter != "" || s.allLocked }

// resolveUserTargets gathers user entries from explicit logins and the selectors,
// de-duplicated by DN. Explicit logins that don't resolve are returned as
// `missing` (per-item failures) rather than aborting; a selector that can't run
// (group/filter error) is a hard error.
func resolveUserTargets(cli *ldapx.Client, logins []string, sel *userSelectors) (targets []*ldapx.Entry, missing []importIssue, err error) {
	attrs := []string{"uid", "pwdAccountLockedTime", "pwdFailureTime"}
	seen := map[string]bool{}
	add := func(e *ldapx.Entry) {
		if !seen[e.DN] {
			seen[e.DN] = true
			targets = append(targets, e)
		}
	}

	for _, l := range logins {
		login := strings.ToLower(strings.TrimSpace(l))
		e, ferr := cli.FindUser(login, attrs)
		if ferr != nil {
			missing = append(missing, importIssue{login, ferr.Error()})
			continue
		}
		add(e)
	}
	if sel.group != "" {
		g, gerr := cli.FindGroup(sel.group, []string{"cn"})
		if gerr != nil {
			return nil, nil, gerr
		}
		es, serr := cli.SearchPaged(cli.UserBase(),
			"(&(objectClass=inetOrgPerson)(memberOf="+ldapx.EscapeFilter(g.DN)+"))", attrs, 250)
		if serr != nil {
			return nil, nil, serr
		}
		for _, e := range es {
			add(e)
		}
	}
	if sel.filter != "" {
		es, serr := cli.SearchPaged(cli.UserBase(), sel.filter, attrs, 250)
		if serr != nil {
			return nil, nil, fmt.Errorf("filter search: %w", serr)
		}
		for _, e := range es {
			add(e)
		}
	}
	if sel.allLocked {
		es, serr := cli.SearchPaged(cli.UserBase(), "(pwdAccountLockedTime=*)", attrs, 250)
		if serr != nil {
			return nil, nil, serr
		}
		for _, e := range es {
			add(e)
		}
	}
	return targets, missing, nil
}

type batchResult struct {
	Action string        `json:"action" yaml:"action"`
	OK     []string      `json:"ok" yaml:"ok"`
	Failed []importIssue `json:"failed,omitempty" yaml:"failed,omitempty"`
}

func (r batchResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d ok, %d failed\n", r.Action, len(r.OK), len(r.Failed))
	for _, dn := range r.OK {
		fmt.Fprintf(&b, "  + %s\n", dn)
	}
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "  ! %s: %s\n", f.Login, f.Error)
	}
	return strings.TrimRight(b.String(), "\n")
}

// runUserBatch resolves targets, enforces the --yes guard, applies fn to each.
func runUserBatch(action string, logins []string, sel *userSelectors, fn func(*ldapx.Client, *ldapx.Entry) error) error {
	cli, err := connect()
	if err != nil {
		return err
	}
	defer cli.Close()

	targets, missing, err := resolveUserTargets(cli, logins, sel)
	if err != nil {
		return err
	}
	if len(targets) == 0 && len(missing) == 0 {
		return fmt.Errorf("no matching users")
	}
	if sel.used() && !sel.yes {
		return fmt.Errorf("selector matched %d user(s) — pass --yes to apply %q", len(targets), action)
	}

	res := batchResult{Action: action, Failed: missing}
	for _, t := range targets {
		if err := fn(cli, t); err != nil {
			res.Failed = append(res.Failed, importIssue{t.DN, err.Error()})
			if sel.stopOnErr {
				_ = out.Emit(res)
				return fmt.Errorf("stopped at %s: %w", t.DN, err)
			}
			continue
		}
		res.OK = append(res.OK, t.DN)
	}
	log.Info().Str("action", action).Int("ok", len(res.OK)).Int("failed", len(res.Failed)).Msg("bulk done")
	return out.Emit(res)
}

// unlockEntry clears the lock (always deletable) and best-effort clears the
// failure counter via the Relax control. Shared by bulk unlock.
func unlockEntry(cli *ldapx.Client, e *ldapx.Entry) error {
	if e.Get("pwdAccountLockedTime") != "" {
		if err := cli.Modify(e.DN, []ldapx.Mod{{Op: ldapx.ModDelete, Name: "pwdAccountLockedTime"}}); err != nil {
			return err
		}
	}
	if len(e.GetAll("pwdFailureTime")) > 0 {
		err := cli.ModifyRelax(e.DN, []ldapx.Mod{{Op: ldapx.ModDelete, Name: "pwdFailureTime"}})
		if err != nil && !ldapx.IsNoSuchAttribute(err) {
			log.Debug().Err(err).Str("dn", e.DN).Msg("could not clear pwdFailureTime")
		}
	}
	return nil
}

// ---- users --------------------------------------------------------------

var usersCmd = &cobra.Command{Use: "users", Short: "Bulk actions on users"}

var (
	usersDeleteSel     userSelectors
	usersUnlockSel     userSelectors
	usersForceResetSel userSelectors
	usersSetSel        userSelectors
	usersPasswdSel     userSelectors
)

var usersDeleteCmd = &cobra.Command{
	Use:     "delete [login...]",
	Aliases: []string{"del", "rm"},
	Short:   "Delete many users (by login and/or --group/--filter)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUserBatch("deleted", args, &usersDeleteSel, func(cli *ldapx.Client, e *ldapx.Entry) error {
			return cli.Delete(e.DN)
		})
	},
}

var usersUnlockCmd = &cobra.Command{
	Use:   "unlock [login...]",
	Short: "Unlock many users (by login and/or --group/--filter/--all-locked)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUserBatch("unlocked", args, &usersUnlockSel, unlockEntry)
	},
}

var usersForceResetCmd = &cobra.Command{
	Use:   "force-reset [login...]",
	Short: "Require password change at next login for many users",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUserBatch("force-reset", args, &usersForceResetSel, func(cli *ldapx.Client, e *ldapx.Entry) error {
			return cli.Modify(e.DN, []ldapx.Mod{{Op: ldapx.ModReplace, Name: "pwdReset", Values: []string{"TRUE"}}})
		})
	},
}

var usersSetCmd = &cobra.Command{
	Use:   "set <attr> <value> [login...]",
	Short: "Set (or clear, if value empty) an attribute on many users",
	Args:  cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		attr, value, logins := args[0], args[1], args[2:]
		return runUserBatch("set "+attr, logins, &usersSetSel, func(cli *ldapx.Client, e *ldapx.Entry) error {
			mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: []string{value}}
			if value == "" {
				mod = ldapx.Mod{Op: ldapx.ModDelete, Name: attr}
			}
			return cli.Modify(e.DN, []ldapx.Mod{mod})
		})
	},
}

// passwd needs its own result to carry the generated passwords.
type passwdItem struct {
	DN       string `json:"dn" yaml:"dn"`
	Password string `json:"password" yaml:"password"`
}

type passwdBatchResult struct {
	Results []passwdItem  `json:"results" yaml:"results"`
	Failed  []importIssue `json:"failed,omitempty" yaml:"failed,omitempty"`
}

func (r passwdBatchResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "passwords set: %d ok, %d failed\n", len(r.Results), len(r.Failed))
	for _, it := range r.Results {
		fmt.Fprintf(&b, "  %s  %s\n", it.DN, it.Password)
	}
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "  ! %s: %s\n", f.Login, f.Error)
	}
	return strings.TrimRight(b.String(), "\n")
}

var usersPasswdCmd = &cobra.Command{
	Use:   "passwd [login...]",
	Short: "Generate and set a fresh password for many users",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		targets, missing, err := resolveUserTargets(cli, args, &usersPasswdSel)
		if err != nil {
			return err
		}
		if len(targets) == 0 && len(missing) == 0 {
			return fmt.Errorf("no matching users")
		}
		if usersPasswdSel.used() && !usersPasswdSel.yes {
			return fmt.Errorf("selector matched %d user(s) — pass --yes to reset their passwords", len(targets))
		}

		res := passwdBatchResult{Failed: missing}
		for _, t := range targets {
			p, gerr := pwd.Strong(20)
			if gerr != nil {
				return gerr
			}
			if _, serr := cli.SetPassword(t.DN, p); serr != nil {
				res.Failed = append(res.Failed, importIssue{t.DN, serr.Error()})
				if usersPasswdSel.stopOnErr {
					_ = out.Emit(res)
					return fmt.Errorf("stopped at %s: %w", t.DN, serr)
				}
				continue
			}
			res.Results = append(res.Results, passwdItem{DN: t.DN, Password: p})
		}
		log.Info().Int("ok", len(res.Results)).Int("failed", len(res.Failed)).Msg("bulk passwd done")
		return out.Emit(res)
	},
}

// ---- groups / svcs (bulk delete by name) --------------------------------

var groupsCmd = &cobra.Command{Use: "groups", Short: "Bulk actions on groups"}

var groupsDeleteCmd = &cobra.Command{
	Use:     "delete <name...>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete many groups",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		res := batchResult{Action: "deleted"}
		for _, name := range args {
			g, ferr := cli.FindGroup(strings.TrimSpace(name), []string{"cn"})
			if ferr != nil {
				res.Failed = append(res.Failed, importIssue{name, ferr.Error()})
				continue
			}
			if derr := cli.Delete(g.DN); derr != nil {
				res.Failed = append(res.Failed, importIssue{g.DN, derr.Error()})
				continue
			}
			res.OK = append(res.OK, g.DN)
		}
		return out.Emit(res)
	},
}

var svcsCmd = &cobra.Command{Use: "svcs", Short: "Bulk actions on service accounts"}

var svcsDeleteCmd = &cobra.Command{
	Use:     "delete <name...>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete many service accounts (entry only; ACL cleanup via singular svc delete)",
	Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		res := batchResult{Action: "deleted"}
		for _, name := range args {
			dn := svcDN(cli, strings.TrimSpace(name))
			if derr := cli.Delete(dn); derr != nil {
				res.Failed = append(res.Failed, importIssue{dn, derr.Error()})
				continue
			}
			res.OK = append(res.OK, dn)
		}
		return out.Emit(res)
	},
}

func init() {
	usersDeleteSel.bind(usersDeleteCmd, false)
	usersUnlockSel.bind(usersUnlockCmd, true)
	usersForceResetSel.bind(usersForceResetCmd, false)
	usersSetSel.bind(usersSetCmd, false)
	usersPasswdSel.bind(usersPasswdCmd, false)
	usersCmd.AddCommand(usersDeleteCmd, usersUnlockCmd, usersForceResetCmd, usersSetCmd, usersPasswdCmd)

	groupsCmd.AddCommand(groupsDeleteCmd)
	svcsCmd.AddCommand(svcsDeleteCmd)

	rootCmd.AddCommand(usersCmd, groupsCmd, svcsCmd)
}
