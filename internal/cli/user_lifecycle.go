package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/domain"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// ---- delete -------------------------------------------------------------

var userDeleteCmd = &cobra.Command{
	Use:     "delete <login>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a user by login (uid or cn)",
	Long: "Delete a user. The refint overlay removes the user's group memberships\n" +
		"automatically; a group left with no members violates groupOfNames and may\n" +
		"need separate cleanup.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}
		if err := cli.Delete(entry.DN); err != nil {
			return fmt.Errorf("delete %s: %w", entry.DN, err)
		}
		log.Debug().Str("dn", entry.DN).Msg("user deleted")

		return out.Emit(deleteResult{DN: entry.DN})
	},
}

type deleteResult struct {
	DN string `json:"dn" yaml:"dn"`
}

func (r deleteResult) Text() string { return "deleted " + r.DN }

// ---- info ---------------------------------------------------------------

var userInfoCmd = &cobra.Command{
	Use:     "info <login>",
	Aliases: []string{"show", "get"},
	Short:   "Show a user's attributes and group memberships",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		attrs := []string{"uid", "cn", "sn", "givenName", "displayName", "mail", "memberOf",
			"pwdAccountLockedTime", "pwdFailureTime", "pwdReset", "pwdChangedTime", "pwdPolicySubentry"}
		entry, err := cli.FindUser(login, attrs)
		if err != nil {
			return err
		}

		lockedSince := entry.Get("pwdAccountLockedTime")
		return out.Emit(userInfo{
			DN:           entry.DN,
			UID:          entry.Get("uid"),
			CN:           entry.Get("cn"),
			SN:           entry.Get("sn"),
			GivenName:    entry.Get("givenName"),
			DisplayName:  entry.Get("displayName"),
			Mail:         entry.Get("mail"),
			Groups:       entry.GetAll("memberOf"),
			Locked:       lockedSince != "",
			LockedSince:  lockedSince,
			Failures:     len(entry.GetAll("pwdFailureTime")),
			MustChange:   strings.EqualFold(entry.Get("pwdReset"), "TRUE"),
			PwdChangedAt: entry.Get("pwdChangedTime"),
			Policy:       entry.Get("pwdPolicySubentry"),
		})
	},
}

type userInfo struct {
	DN           string   `json:"dn" yaml:"dn"`
	UID          string   `json:"uid,omitempty" yaml:"uid,omitempty"`
	CN           string   `json:"cn,omitempty" yaml:"cn,omitempty"`
	SN           string   `json:"sn,omitempty" yaml:"sn,omitempty"`
	GivenName    string   `json:"givenName,omitempty" yaml:"givenName,omitempty"`
	DisplayName  string   `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Mail         string   `json:"mail,omitempty" yaml:"mail,omitempty"`
	Groups       []string `json:"groups,omitempty" yaml:"groups,omitempty"`
	Locked       bool     `json:"locked" yaml:"locked"`
	LockedSince  string   `json:"lockedSince,omitempty" yaml:"lockedSince,omitempty"`
	Failures     int      `json:"failures" yaml:"failures"`
	MustChange   bool     `json:"mustChange" yaml:"mustChange"`
	PwdChangedAt string   `json:"pwdChangedAt,omitempty" yaml:"pwdChangedAt,omitempty"`
	Policy       string   `json:"policy,omitempty" yaml:"policy,omitempty"`
}

func (r userInfo) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.DN)
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %-12s %s\n", k+":", v)
		}
	}
	line("uid", r.UID)
	line("cn", r.CN)
	line("displayName", r.DisplayName)
	line("givenName", r.GivenName)
	line("sn", r.SN)
	line("mail", r.Mail)
	line("policy", r.Policy)
	line("pwdChanged", r.PwdChangedAt)
	status := "active"
	if r.Locked {
		status = "LOCKED"
		if r.LockedSince != "" {
			status += " since " + r.LockedSince
		}
	}
	line("status", status)
	if r.Failures > 0 {
		line("failures", strconv.Itoa(r.Failures))
	}
	if r.MustChange {
		line("mustChange", "yes (pwdReset)")
	}
	if len(r.Groups) > 0 {
		fmt.Fprintf(&b, "  %-12s %s", "groups:", strings.Join(r.Groups, "\n               "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- set (modify single attribute) -------------------------------------

var userSetCmd = &cobra.Command{
	Use:   "set <login> <attr> [value...]",
	Short: "Replace (or delete, if no value) a single attribute on a user",
	Args:  cobra.MinimumNArgs(2),
	Example: "  openldap-cli user set toto.titi title Engineer\n" +
		"  openldap-cli user set toto.titi telephoneNumber          # delete attribute",
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		attr, values := args[1], args[2:]

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}
		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		if len(values) == 0 {
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		if err := cli.Modify(entry.DN, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", entry.DN, err)
		}
		log.Debug().Str("dn", entry.DN).Str("attr", attr).Msg("attribute modified")
		return out.Emit(okResult{Action: action, DN: entry.DN})
	},
}

// ---- rename (modrdn + refresh derived attrs) ---------------------------

var userRenameCmd = &cobra.Command{
	Use:   "rename <old-login> <new-firstname.lastname>",
	Short: "Rename a user (cn modrdn) and refresh derived attributes",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		oldLogin := strings.ToLower(strings.TrimSpace(args[0]))
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		nu, err := domain.ParseUser(args[1], cfg.MailDomain)
		if err != nil {
			return err
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(oldLogin, []string{"uid"})
		if err != nil {
			return err
		}

		// modrdn cn=<old> -> cn=<new>, dropping the old cn value.
		newRDN := "cn=" + nu.UID
		if err := cli.Rename(entry.DN, newRDN, true, ""); err != nil {
			return fmt.Errorf("rename %s: %w", entry.DN, err)
		}
		newDN := nu.DN(cfg.UserOU, cfg.BaseDN)

		// refresh derived attrs on the new DN (cn is handled by the modrdn)
		mods := []ldapx.Mod{
			{Op: ldapx.ModReplace, Name: "uid", Values: []string{nu.UID}},
			{Op: ldapx.ModReplace, Name: "sn", Values: []string{nu.SN}},
		}
		if nu.GivenName != "" {
			mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "givenName", Values: []string{nu.GivenName}})
		}
		if nu.DisplayName != "" {
			mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "displayName", Values: []string{nu.DisplayName}})
		}
		if nu.Mail != "" {
			mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "mail", Values: []string{nu.Mail}})
		}
		if err := cli.Modify(newDN, mods); err != nil {
			return fmt.Errorf("refresh attrs on %s: %w", newDN, err)
		}
		log.Debug().Str("from", entry.DN).Str("to", newDN).Msg("user renamed")
		return out.Emit(okResult{Action: "renamed to", DN: newDN})
	},
}

// ---- move ---------------------------------------------------------------

var userMoveCmd = &cobra.Command{
	Use:     "move <login> <new-parent-dn>",
	Short:   "Move a user to another OU (modrdn, same RDN, new superior)",
	Args:    cobra.ExactArgs(2),
	Example: "  openldap-cli user move toto.titi ou=contractors,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		newParent := strings.TrimSpace(args[1])

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}
		rdn := strings.SplitN(entry.DN, ",", 2)[0] // keep the existing RDN
		if err := cli.Rename(entry.DN, rdn, false, newParent); err != nil {
			return fmt.Errorf("move %s: %w", entry.DN, err)
		}
		newDN := rdn + "," + newParent
		log.Debug().Str("from", entry.DN).Str("to", newDN).Msg("user moved")
		return out.Emit(okResult{Action: "moved to", DN: newDN})
	},
}

func init() {
	userCmd.AddCommand(userDeleteCmd, userInfoCmd, userSetCmd, userRenameCmd, userMoveCmd)
}
