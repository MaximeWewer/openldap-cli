package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// A groupOfNames names its members by DN, and nothing in LDAP keeps those DNs
// honest. Delete a user and every group still carries `member: cn=<gone>,…`;
// rename one and the groups keep naming the DN it no longer has, so the user
// silently loses every group-derived access. Worse the other way round: re-create
// a login that was deleted and it walks straight back into the groups its
// predecessor was in.
//
// slapd CAN maintain those references, but only if it was configured to, and
// there are TWO independent mechanisms — both verified here against a live 2.6:
//
//	refint    olcRefintAttribute: member          (slapo-refint)
//	memberof  olcMemberOfRefInt: TRUE             (slapo-memberof)
//
// Either one fixes `member` on BOTH delete and modrdn. Neither is on in a stock
// install, and an enabled refint with NO olcRefintAttribute maintains nothing at
// all — an overlay that looks configured and is inert. Checking only refint would
// therefore cry wolf on a directory that memberof already keeps straight, which
// is why both are consulted.
//
// The CLI used to state the cleanup as fact ("The refint overlay removes the
// user's group memberships automatically") and never look. So when the server
// does not do it, this does — the same call as fixACLRefs, for the same reason:
// left to the operator, it is left undone.

// noFixRefs backs --no-fix-refs.
var noFixRefs bool

// withFixRefsFlag registers --no-fix-refs on a command that removes or moves an
// entry other entries may name.
func withFixRefsFlag(cmds ...*cobra.Command) {
	for _, c := range cmds {
		c.Flags().BoolVar(&noFixRefs, "no-fix-refs", false,
			"do not repair the group memberships naming the old DN (they will name a DN that does not exist)")
	}
}

// memberRefsMaintainedBy names the overlay that keeps `member` references
// straight across a delete or rename, or "" when nothing does.
//
// Needs the config bind: the answer is in cn=config, not in the data tree.
func memberRefsMaintainedBy(cc *ldapx.Client) (string, error) {
	db, err := cc.DataDatabaseDN(cc.Config().BaseDN)
	if err != nil {
		return "", err
	}

	// memberof maintains `member` itself when olcMemberOfRefInt is on — but only
	// for the attribute it was told to treat as membership.
	if e, err := cc.FindOverlay(db, "memberof"); err == nil && !isDisabled(e) {
		full, ferr := cc.ReadEntry(e.DN, []string{"olcMemberOfRefInt", "olcMemberOfMemberAD"})
		if ferr == nil && strings.EqualFold(full.Get("olcMemberOfRefInt"), "TRUE") {
			ad := full.Get("olcMemberOfMemberAD")
			if ad == "" || strings.EqualFold(ad, "member") {
				return "the memberof overlay (olcMemberOfRefInt: TRUE)", nil
			}
		}
	}

	if e, err := cc.FindOverlay(db, "refint"); err == nil && !isDisabled(e) {
		full, ferr := cc.ReadEntry(e.DN, []string{"olcRefintAttribute"})
		if ferr == nil {
			for _, v := range full.GetAll("olcRefintAttribute") {
				// the value is a space-separated list in slapd.conf form, and one
				// attribute per value in cn=config form — handle both
				for _, a := range strings.Fields(v) {
					if strings.EqualFold(a, "member") {
						return "the refint overlay (olcRefintAttribute: member)", nil
					}
				}
			}
		}
	}
	return "", nil
}

// isDisabled reports whether an overlay entry is turned off.
func isDisabled(e *ldapx.Entry) bool { return strings.EqualFold(e.Get("olcDisabled"), "TRUE") }

// groupsNaming returns the groups whose `member` is dn.
func groupsNaming(cli *ldapx.Client, dn string) ([]*ldapx.Entry, error) {
	return searchAll(cli, cli.Config().BaseDN,
		fmt.Sprintf("(member=%s)", ldapx.EscapeFilter(dn)), []string{"member"})
}

// refFix is what fixMemberRefs did to one group.
type refFix struct {
	Group  string `json:"group" yaml:"group"`
	Action string `json:"action" yaml:"action"` // repointed | removed | STUCK
	Reason string `json:"reason,omitempty" yaml:"reason,omitempty"`
}

// fixMemberRefs re-points every `member: oldDN` at newDN, or removes it when
// newDN is empty (the entry is gone).
//
// A groupOfNames must keep at least one member, so removing the last one is
// refused by the schema rather than by us: that group is reported STUCK, with
// what to do about it. slapd's own refint has the same problem and answers it
// with olcRefintNothing — a placeholder we will not invent on the operator's
// behalf.
func fixMemberRefs(cli *ldapx.Client, oldDN, newDN string) ([]refFix, error) {
	groups, err := groupsNaming(cli, oldDN)
	if err != nil {
		return nil, fmt.Errorf("find the groups naming %s: %w", oldDN, err)
	}
	var fixes []refFix
	for _, g := range groups {
		if newDN != "" {
			mods := []ldapx.Mod{
				{Op: ldapx.ModAdd, Name: "member", Values: []string{newDN}},
				{Op: ldapx.ModDelete, Name: "member", Values: []string{oldDN}},
			}
			if err := cli.Modify(g.DN, mods); err != nil {
				fixes = append(fixes, refFix{Group: g.DN, Action: "STUCK", Reason: err.Error()})
				continue
			}
			fixes = append(fixes, refFix{Group: g.DN, Action: "repointed"})
			continue
		}
		if len(g.GetAll("member")) == 1 {
			fixes = append(fixes, refFix{Group: g.DN, Action: "STUCK",
				Reason: "it was the group's only member, and a groupOfNames must keep one — " +
					"delete the group, or add another member first"})
			continue
		}
		if err := cli.Modify(g.DN, []ldapx.Mod{{Op: ldapx.ModDelete, Name: "member", Values: []string{oldDN}}}); err != nil {
			fixes = append(fixes, refFix{Group: g.DN, Action: "STUCK", Reason: err.Error()})
			continue
		}
		fixes = append(fixes, refFix{Group: g.DN, Action: "removed"})
	}
	return fixes, nil
}

// fixMemberRefsIfNeeded repairs the group memberships naming oldDN, unless the
// server already maintains them. newDN empty means oldDN is gone.
//
// Called AFTER the delete/rename: the caller's intent has already succeeded, so
// a repair problem is reported rather than rolled back.
//
// It runs only when the server does NOT maintain references, because slapd does
// it better than this can: inside the operation, atomically, and for every
// attribute it was given rather than `member` alone. This is the fallback, not
// the preferred path — which is why it also says how to stop needing it.
func fixMemberRefsIfNeeded(cli *ldapx.Client, oldDN, newDN string) ([]refFix, error) {
	if noFixRefs {
		log.Debug().Str("dn", oldDN).Msg("--no-fix-refs: leaving group memberships alone")
		return nil, nil
	}
	cc, err := connectConfig()
	if err != nil {
		// We cannot tell whether the server maintains them, so we cannot claim it
		// does — but repairing on a server that also repairs is harmless (the
		// search simply finds nothing), so try, and say why we had to.
		log.Debug().Msg("no config bind: cannot tell whether the server maintains member refs; checking by hand")
		return fixMemberRefs(cli, oldDN, newDN)
	}
	defer cc.Close()

	by, err := memberRefsMaintainedBy(cc)
	if err != nil {
		return nil, fmt.Errorf("check whether the server maintains group memberships: %w", err)
	}
	if by != "" {
		log.Debug().Str("by", by).Msg("member references are maintained server-side")
		return nil, nil
	}
	fixes, ferr := fixMemberRefs(cli, oldDN, newDN)
	if len(fixes) > 0 {
		log.Warn().Int("groups", len(fixes)).Msg(
			"this server maintains no group memberships (no refint olcRefintAttribute: member, no memberof olcMemberOfRefInt: TRUE), " +
				"so they were repaired from here — one operation per group, not atomic with the change. " +
				"Turn it on server-side: `config overlay enable refint`")
	}
	return fixes, ferr
}

// refFixDetail renders the repairs for an okResult, and errors when a group is
// stuck: a membership naming a DN that no longer exists is exactly the silent
// state this exists to prevent, so it must not be reported as success.
func refFixDetail(fixes []refFix) (detail string, err error) {
	var lines, stuck []string
	for _, f := range fixes {
		switch f.Action {
		case "STUCK":
			stuck = append(stuck, fmt.Sprintf("    %s: %s", f.Group, f.Reason))
		default:
			lines = append(lines, fmt.Sprintf("    %s (%s)", f.Group, f.Action))
		}
	}
	if len(lines) > 0 {
		detail = "group memberships repaired:\n" + strings.Join(lines, "\n")
	}
	if len(stuck) > 0 {
		return detail, errors.New("done, but a group still names the old DN and nothing will fix it on its own:\n" +
			strings.Join(stuck, "\n"))
	}
	return detail, nil
}
