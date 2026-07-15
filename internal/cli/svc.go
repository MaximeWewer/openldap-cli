package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/acl"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/pwd"
)

var svcCmd = &cobra.Command{
	Use:     "svc",
	Aliases: []string{"service-account"},
	Short:   "Manage service accounts (entry + cn=config ACL)",
}

var (
	svcOU    string
	svcACLDB string
)

func svcDN(cli *ldapx.Client, name string) string {
	return "cn=" + name + "," + svcOU + "," + cli.Config().BaseDN
}

// ---- add ----------------------------------------------------------------

var (
	svcAddSubtree  string
	svcAddAccess   string
	svcAddPassword string
)

var svcAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Create a service account and grant it access via a cn=config ACL",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli --profile test svc add backup-agent \\\n" +
		"      --subtree ou=users,dc=example,dc=org --access read",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if svcAddSubtree == "" {
			return fmt.Errorf("--subtree is required (the DN this account may access)")
		}
		if svcAddAccess != "read" && svcAddAccess != "write" {
			return fmt.Errorf("--access must be read or write")
		}
		password := svcAddPassword
		generated := false
		if password == "" {
			p, err := pwd.Hex(16)
			if err != nil {
				return err
			}
			password, generated = p, true
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := svcDN(cli, name)
		attrs := map[string][]string{
			"objectClass":  {"top", "inetOrgPerson"},
			"cn":           {name},
			"sn":           {name},
			"uid":          {name},
			"userPassword": {password},
		}
		if err = cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("create %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("service account created")

		// ACL injection needs the config bind.
		cc, err := connectConfig()
		if err != nil {
			return fmt.Errorf("account created, but ACL injection skipped: %w", err)
		}
		defer cc.Close()

		newACL, appended, err := cc.InjectAccess(svcACLDB, svcAddSubtree, acl.DNWho(dn), svcAddAccess)
		if err != nil {
			return fmt.Errorf("account created, but ACL injection failed: %w", err)
		}
		log.Debug().Str("acl", newACL).Bool("appended", appended).Msg("acl updated")

		res := svcResult{Action: "created", DN: dn, ACL: newACL}
		if generated {
			res.Password = password
		}
		if appended {
			res.Note = "ACL appended at end of the list — verify it evaluates before any broad catch-all rule"
		}
		return out.Emit(res)
	},
}

// ---- passwd -------------------------------------------------------------

var svcPasswdValue string

var svcPasswdCmd = &cobra.Command{
	Use:   "passwd <name>",
	Short: "Set a service account's password",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		password := svcPasswdValue
		generated := false
		if password == "" {
			p, err := pwd.Hex(16)
			if err != nil {
				return err
			}
			password, generated = p, true
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := svcDN(cli, name)
		if _, err := cli.SetPassword(dn, password); err != nil {
			return fmt.Errorf("set password for %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("service account password set")
		res := svcResult{Action: "password set", DN: dn}
		if generated {
			res.Password = password
		}
		return out.Emit(res)
	},
}

// ---- delete -------------------------------------------------------------

var svcDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a service account and remove its cn=config ACL clauses",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := svcDN(cli, name)
		if err = cli.Delete(dn); err != nil {
			return fmt.Errorf("delete %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Msg("service account deleted")

		res := svcResult{Action: "deleted", DN: dn}
		cc, err := connectConfig()
		if err != nil {
			res.Note = "entry deleted, but ACL cleanup skipped: " + err.Error()
			return out.Emit(res)
		}
		defer cc.Close()

		removed, err := cc.RemoveAccessGrantee(svcACLDB, acl.DNWho(dn))
		if err != nil {
			return fmt.Errorf("entry deleted, but ACL cleanup failed: %w", err)
		}
		log.Debug().Int("clauses", removed).Msg("acl cleaned")
		res.Note = fmt.Sprintf("removed %d ACL clause(s)", removed)
		return out.Emit(res)
	},
}

// ---- result -------------------------------------------------------------

type svcResult struct {
	Action   string `json:"action" yaml:"action"`
	DN       string `json:"dn" yaml:"dn"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
	ACL      string `json:"acl,omitempty" yaml:"acl,omitempty"`
	Note     string `json:"note,omitempty" yaml:"note,omitempty"`
}

func (r svcResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", r.Action, r.DN)
	if r.Password != "" {
		fmt.Fprintf(&b, "\n  password: %s", r.Password)
	}
	if r.ACL != "" {
		fmt.Fprintf(&b, "\n  acl: %s", r.ACL)
	}
	if r.Note != "" {
		fmt.Fprintf(&b, "\n  note: %s", r.Note)
	}
	return b.String()
}

// ---- list / info --------------------------------------------------------

var svcListCmd = &cobra.Command{
	Use:   "list",
	Short: "List service accounts",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		base := svcOU + "," + cli.Config().BaseDN
		entries, err := cli.Search(base, "(objectClass=inetOrgPerson)", []string{"cn"})
		if err != nil {
			return fmt.Errorf("search service accounts: %w", err)
		}
		return out.Emit(entriesToItems("service accounts", "cn", entries))
	},
}

var svcInfoCmd = &cobra.Command{
	Use:     "info <name>",
	Aliases: []string{"show", "get"},
	Short:   "Show a service account and the ACL clauses referencing it",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		dn := svcDN(cli, strings.TrimSpace(args[0]))
		e, err := cli.ReadEntry(dn, []string{"cn", "uid", "description"})
		if err != nil {
			return err
		}
		res := svcInfoResult{DN: e.DN, UID: e.Get("uid"),
			Description: e.Get("description")}

		// ACL clauses are best-effort (need the config bind).
		if cc, cerr := connectConfig(); cerr == nil {
			defer cc.Close()
			if dbs, serr := cc.Search("cn=config", "(olcAccess=*)", []string{"olcAccess"}); serr == nil {
				for _, db := range dbs {
					for _, v := range db.GetAll("olcAccess") {
						if strings.Contains(v, acl.DNWho(dn)) {
							res.ACLRules = append(res.ACLRules, db.DN+" :: "+v)
						}
					}
				}
			}
		}
		return out.Emit(res)
	},
}

type svcInfoResult struct {
	DN          string   `json:"dn" yaml:"dn"`
	UID         string   `json:"uid,omitempty" yaml:"uid,omitempty"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	ACLRules    []string `json:"aclRules,omitempty" yaml:"aclRules,omitempty"`
}

func (r svcInfoResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.DN)
	if r.UID != "" {
		fmt.Fprintf(&b, "  uid: %s\n", r.UID)
	}
	if r.Description != "" {
		fmt.Fprintf(&b, "  description: %s\n", r.Description)
	}
	if len(r.ACLRules) == 0 {
		fmt.Fprintf(&b, "  acl: (none)")
	} else {
		fmt.Fprintf(&b, "  acl:\n")
		for _, rule := range r.ACLRules {
			fmt.Fprintf(&b, "    %s\n", rule)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func init() {
	pf := svcCmd.PersistentFlags()
	pf.StringVar(&svcOU, "ou", "ou=service-accounts", "service-accounts OU (relative to base DN)")
	pf.StringVar(&svcACLDB, "acl-db", "olcDatabase={1}mdb,cn=config", "cn=config database entry holding olcAccess")

	svcAddCmd.Flags().StringVar(&svcAddSubtree, "subtree", "", "DN the account may access (required)")
	svcAddCmd.Flags().StringVar(&svcAddAccess, "access", "read", "access level: read|write")
	svcAddCmd.Flags().StringVar(&svcAddPassword, "password", "", "password (default: generate a 32-char one)")
	svcPasswdCmd.Flags().StringVar(&svcPasswdValue, "password", "", "password (default: generate a 32-char one)")

	svcCmd.AddCommand(svcAddCmd, svcPasswdCmd, svcDeleteCmd, svcInfoCmd)
	rootCmd.AddCommand(svcCmd)

	svcsCmd.AddCommand(svcListCmd) // listing is plural

}
