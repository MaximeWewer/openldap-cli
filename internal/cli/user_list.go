package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// ---- list ---------------------------------------------------------------

var (
	userListGroup  string
	userListLocked bool
	userListPosix  bool
)

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List users, optionally filtered by group / lockout / posix",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		filters := []string{"(objectClass=inetOrgPerson)"}
		if userListGroup != "" {
			g, gerr := cli.FindGroup(userListGroup, []string{"cn"})
			if gerr != nil {
				return gerr
			}
			filters = append(filters, "(memberOf="+ldapx.EscapeFilter(g.DN)+")")
		}
		if userListLocked {
			filters = append(filters, "(pwdAccountLockedTime=*)")
		}
		if userListPosix {
			filters = append(filters, "(objectClass=posixAccount)")
		}
		filter := "(&" + strings.Join(filters, "") + ")"

		entries, err := searchAll(cli, cli.UserBase(), filter, []string{"uid", "cn", "displayName", "mail"})
		if err != nil {
			return fmt.Errorf("search users: %w", err)
		}
		list := userListResult{}
		for _, e := range entries {
			uid := e.Get("uid")
			if uid == "" {
				uid = e.Get("cn")
			}
			list.Users = append(list.Users, userBrief{
				UID: uid, DisplayName: e.Get("displayName"),
				Mail: e.Get("mail"), DN: e.DN,
			})
		}
		// Only report the type gap on an unfiltered listing: with --group/--locked
		// /--posix the caller asked for a subset, so a smaller count is the point.
		// It goes in the RESULT, not a log line, so `-o json` sees it too.
		if len(filters) == 1 {
			list.Skipped = cli.CountSkippedByType(cli.UserBase(), "inetOrgPerson")
		}
		return out.Emit(list)
	},
}

type userBrief struct {
	UID         string `json:"uid" yaml:"uid"`
	DisplayName string `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Mail        string `json:"mail,omitempty" yaml:"mail,omitempty"`
	DN          string `json:"dn" yaml:"dn"`
}

type userListResult struct {
	Users []userBrief `json:"users" yaml:"users"`
	// Skipped counts the entries under the user base that are not
	// inetOrgPerson, so the count cannot be read as "every user".
	Skipped int `json:"skippedNotInetOrgPerson,omitempty" yaml:"skippedNotInetOrgPerson,omitempty"`
}

func (r userListResult) Text() string {
	var b strings.Builder
	for _, u := range r.Users {
		fmt.Fprintf(&b, "%-24s %s\n", u.UID, u.DisplayName)
	}
	if len(r.Users) == 0 {
		b.WriteString("no users\n")
	} else {
		fmt.Fprintf(&b, "(%d users)\n", len(r.Users))
	}
	if r.Skipped > 0 {
		fmt.Fprintf(&b, "%d more entrie(s) under the user base are not inetOrgPerson and are not listed"+
			" — `search` shows them", r.Skipped)
	}
	return strings.TrimRight(b.String(), "\n")
}

func init() {
	userListCmd.Flags().StringVar(&userListGroup, "group", "", "only members of this group")
	userListCmd.Flags().BoolVar(&userListLocked, "locked", false, "only ppolicy-locked users")
	userListCmd.Flags().BoolVar(&userListPosix, "posix", false, "only posixAccount users")
	usersCmd.AddCommand(userListCmd)
}
