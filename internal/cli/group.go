package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage groups (groupOfNames)",
}

// ---- create -------------------------------------------------------------

var groupCreateMembers []string

var groupCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a groupOfNames with at least one member",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli group create devs --member toto.titi\n" +
		"  openldap-cli group create devs --member toto.titi --member jean.dupont",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if len(groupCreateMembers) == 0 {
			return fmt.Errorf("groupOfNames requires at least one --member")
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		members, err := resolveMembers(cli, groupCreateMembers)
		if err != nil {
			return err
		}
		dn := "cn=" + name + "," + cli.GroupBase()
		attrs := map[string][]string{
			"objectClass": {"top", "groupOfNames"},
			"cn":          {name},
			"member":      members,
		}
		if err := cli.AddEntry(dn, attrs); err != nil {
			return fmt.Errorf("create group %s: %w", name, err)
		}
		log.Debug().Str("dn", dn).Int("members", len(members)).Msg("group created")
		return out.Emit(okResult{Action: "created", DN: dn,
			Detail: fmt.Sprintf("%d member(s)", len(members))})
	},
}

// ---- list ---------------------------------------------------------------

var groupListMembers bool

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List groups, optionally with members",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		attrs := []string{"cn"}
		if groupListMembers {
			attrs = append(attrs, "member")
		}
		entries, err := searchAll(cli, cli.GroupBase(), "(objectClass=groupOfNames)", attrs)
		if err != nil {
			return fmt.Errorf("search groups: %w", err)
		}
		res := groupListResult{}
		for _, e := range entries {
			g := groupBrief{CN: e.Get("cn"), DN: e.DN}
			if groupListMembers {
				g.Members = e.GetAll("member")
			}
			res.Groups = append(res.Groups, g)
		}
		return out.Emit(res)
	},
}

type groupBrief struct {
	CN      string   `json:"cn" yaml:"cn"`
	DN      string   `json:"dn" yaml:"dn"`
	Members []string `json:"members,omitempty" yaml:"members,omitempty"`
}

type groupListResult struct {
	Groups []groupBrief `json:"groups" yaml:"groups"`
}

func (r groupListResult) Text() string {
	if len(r.Groups) == 0 {
		return "no groups"
	}
	var b strings.Builder
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "%s\n", g.CN)
		for _, m := range g.Members {
			fmt.Fprintf(&b, "    %s\n", m)
		}
	}
	fmt.Fprintf(&b, "(%d groups)", len(r.Groups))
	return strings.TrimRight(b.String(), "\n")
}

// ---- add-member / remove-member ----------------------------------------

var groupAddMemberCmd = &cobra.Command{
	Use:   "add-member <group> <login...>",
	Short: "Add one or more users to a group",
	Args:  cobra.MinimumNArgs(2),
	RunE:  groupMemberRunE(true),
}

var groupRemoveMemberCmd = &cobra.Command{
	Use:     "remove-member <group> <login...>",
	Aliases: []string{"rm-member"},
	Short:   "Remove one or more users from a group",
	Long:    "Removing the last member of a groupOfNames violates the schema and will be rejected.",
	Args:    cobra.MinimumNArgs(2),
	RunE:    groupMemberRunE(false),
}

func groupMemberRunE(add bool) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		g, err := cli.FindGroup(name, []string{"cn"})
		if err != nil {
			return err
		}
		members, err := resolveMembers(cli, args[1:])
		if err != nil {
			return err
		}
		mod := ldapx.Mod{Op: ldapx.ModAdd, Name: "member", Values: members}
		action := "added to"
		if !add {
			mod.Op = ldapx.ModDelete
			action = "removed from"
		}
		if err := cli.Modify(g.DN, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify group %s: %w", g.DN, err)
		}
		log.Debug().Str("dn", g.DN).Int("members", len(members)).Bool("add", add).Msg("group membership changed")
		return out.Emit(okResult{Action: fmt.Sprintf("%d member(s) %s", len(members), action), DN: g.DN})
	}
}

// ---- set ----------------------------------------------------------------

var groupSetCmd = &cobra.Command{
	Use:   "set <name> <attr> [value...]",
	Short: "Replace (or delete, if no value) a single attribute on a group",
	Long: "Use `add-member`/`remove-member` for membership: this replaces the whole\n" +
		"attribute, so `set <g> member <dn>` would drop every other member.",
	Args: cobra.MinimumNArgs(2),
	Example: "  openldap-cli group set devs description 'Core team'\n" +
		"  openldap-cli group set devs description                    # delete attribute",
	RunE: func(cmd *cobra.Command, args []string) error {
		attr, values := args[1], args[2:]
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		g, err := cli.FindGroup(strings.TrimSpace(args[0]), []string{"cn"})
		if err != nil {
			return err
		}
		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		if len(values) == 0 {
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		if err := cli.Modify(g.DN, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", g.DN, err)
		}
		log.Debug().Str("dn", g.DN).Str("attr", attr).Msg("group attribute modified")
		return out.Emit(okResult{Action: action, DN: g.DN})
	},
}

// ---- rename -------------------------------------------------------------

var groupRenameCmd = &cobra.Command{
	Use:   "rename <name> <new-name>",
	Short: "Rename a group (cn modrdn)",
	Long: "Renames cn=<name> to cn=<new-name>. Members are untouched, and their\n" +
		"memberOf follows the new DN (the memberof overlay maintains it).\n\n" +
		"The olcAccess rules granting `group.exact=\"cn=<name>,…\"` are re-pointed at\n" +
		"the new DN: slapd rewrites none of them, so such a rule would keep naming a\n" +
		"DN that no longer exists and every member would silently lose that access.\n" +
		"Needs the config bind; --no-fix-acl skips it.",
	Args:    cobra.ExactArgs(2),
	Example: "  openldap-cli group rename devs engineers",
	RunE: func(cmd *cobra.Command, args []string) error {
		newName := strings.TrimSpace(args[1])
		if newName == "" {
			return fmt.Errorf("the new name is empty")
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		g, err := cli.FindGroup(strings.TrimSpace(args[0]), []string{"cn"})
		if err != nil {
			return err
		}
		// deleteOldRDN: the old cn must go, or the group answers to both names
		if err := cli.Rename(g.DN, "cn="+newName, true, ""); err != nil {
			return fmt.Errorf("rename %s: %w", g.DN, err)
		}
		newDN := "cn=" + newName + "," + cli.GroupBase()
		log.Debug().Str("from", g.DN).Str("to", newDN).Msg("group renamed")
		if err := fixACLRefs(g.DN, newDN); err != nil {
			return err
		}
		return out.Emit(okResult{Action: "renamed to", DN: newDN})
	},
}

// ---- delete / info ------------------------------------------------------

var groupDeleteCmd = &cobra.Command{
	Use:     "delete <name>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete a group",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		g, err := cli.FindGroup(strings.TrimSpace(args[0]), []string{"cn"})
		if err != nil {
			return err
		}
		if err := cli.Delete(g.DN); err != nil {
			return fmt.Errorf("delete %s: %w", g.DN, err)
		}
		log.Debug().Str("dn", g.DN).Msg("group deleted")
		return out.Emit(okResult{Action: "deleted", DN: g.DN})
	},
}

var groupInfoCmd = &cobra.Command{
	Use:     "info <name>",
	Aliases: []string{"show", "get"},
	Short:   "Show a group and its members",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		g, err := cli.FindGroup(strings.TrimSpace(args[0]), []string{"cn", "member", "description"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(g))
	},
}

func init() {
	groupCreateCmd.Flags().StringArrayVar(&groupCreateMembers, "member", nil, "member login (repeatable)")
	groupListCmd.Flags().BoolVar(&groupListMembers, "members", false, "include member DNs")
	withFixACLFlag(groupRenameCmd)
	groupCmd.AddCommand(groupCreateCmd, groupAddMemberCmd, groupRemoveMemberCmd,
		groupSetCmd, groupRenameCmd, groupDeleteCmd, groupInfoCmd)
	rootCmd.AddCommand(groupCmd)

	groupsCmd.AddCommand(groupListCmd) // listing is plural

}
