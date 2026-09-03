package ldapx

import (
	"errors"
	"fmt"

	"github.com/MaximeWewer/openldap-cli/internal/acl"
)

// ErrACLRaced is returned when olcAccess changed between the read the new rule
// list was computed from and the write that would have applied it.
var ErrACLRaced = errors.New("olcAccess changed on the server while this edit was being computed")

// replaceAccess swaps the whole olcAccess list for bodies, as a compare-and-swap:
// one Modify that first deletes the exact values we read, then adds the new ones.
//
// A plain replace would be a lost update. These edits renumber every rule, so
// they have to rewrite the list wholesale, and a rule added by a concurrent
// operator (or a hand-run ldapmodify) between our read and our write would be
// erased without a trace - on the server's access-control list. Naming the old
// values in the delete makes the server refuse instead: it answers noSuchValue
// and applies nothing, a single Modify being atomic.
//
// The assertion control (RFC 4528) would be the textbook way to do this, but
// slapd's back-config rejects it: "critical control unavailable in context".
func (c *Client) ReplaceAccess(dbDN string, seen, bodies []string) error {
	// an empty list would DELETE olcAccess and drop the database back to
	// slapd's built-in default, which is wider than anything being revoked
	if len(bodies) == 0 {
		return fmt.Errorf("refusing to leave %s with no olcAccess rule at all: the database "+
			"would fall back to slapd's default access, which is wider than what you are "+
			"revoking. Keep one rule, or edit olcAccess directly", dbDN)
	}
	mods := []Mod{
		{Op: ModDelete, Name: "olcAccess", Values: seen},
		{Op: ModAdd, Name: "olcAccess", Values: bodies},
	}
	if err := c.modify(dbDN, mods, nil); err != nil {
		if IsNoSuchAttribute(err) {
			return fmt.Errorf("%w: nothing was applied, re-run to work from the current rules", ErrACLRaced)
		}
		return err
	}
	return nil
}

// InjectAccess applies an acl.InjectOpts grant by editing olcAccess on dbDN (an
// ordered attribute). Returns the resulting rule and whether a NEW rule was
// created (vs a `by` clause added to an existing one).
func (c *Client) InjectAccess(dbDN string, o acl.InjectOpts) (rule string, appended bool, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return "", false, err
	}
	edit, appended := acl.Inject(e.GetAll("olcAccess"), o)
	if edit.Add == "" && edit.Delete == "" {
		return "", false, nil // the clause is already present — nothing to change
	}
	var mods []Mod
	if edit.Delete != "" {
		mods = append(mods, Mod{Op: ModDelete, Name: "olcAccess", Values: []string{edit.Delete}})
	}
	mods = append(mods, Mod{Op: ModAdd, Name: "olcAccess", Values: []string{edit.Add}})
	return edit.Add, appended, c.Modify(dbDN, mods)
}

// RenameAccessDN re-points every olcAccess rule naming oldDN (or an entry
// beneath it) at newDN, so a rename does not silently orphan its ACLs. Returns
// how many DNs were rewritten and the rules that need manual review.
func (c *Client) RenameAccessDN(dbDN, oldDN, newDN string) (rewritten int, skipped []string, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return 0, nil, err
	}
	seen := e.GetAll("olcAccess")
	bodies, rewritten, skipped := acl.RenameDN(seen, oldDN, newDN)
	if rewritten == 0 {
		return 0, skipped, nil
	}
	// one rewrite of the whole ordered attribute: see acl.RemoveGrantee.
	return rewritten, skipped, c.ReplaceAccess(dbDN, seen, bodies)
}

// RemoveAccessGrantee strips every clause referencing who (a full who-token)
// from olcAccess on dbDN, dropping any rule left with nothing to say. Reports
// how many clauses were removed and how many rules that emptied out.
func (c *Client) RemoveAccessGrantee(dbDN, who string) (removed, dropped int, err error) {
	return c.removeAccessGrantee(dbDN, who, "")
}

// RemoveAccessGranteeOn strips who's clauses only from the rules protecting
// target, leaving its access to other trees intact.
func (c *Client) RemoveAccessGranteeOn(dbDN, who, target string) (removed, dropped int, err error) {
	return c.removeAccessGrantee(dbDN, who, target)
}

// removeAccessGrantee applies the revoke; target "" means every rule.
func (c *Client) removeAccessGrantee(dbDN, who, target string) (removed, dropped int, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return 0, 0, err
	}
	values := e.GetAll("olcAccess")
	var bodies []string
	if target == "" {
		bodies, removed, dropped = acl.RemoveGrantee(values, who)
	} else {
		bodies, removed, dropped = acl.RemoveGranteeOn(values, who, target)
	}
	if removed == 0 {
		return 0, 0, nil
	}
	// one rewrite of the whole ordered attribute: see acl.RemoveGrantee.
	return removed, dropped, c.ReplaceAccess(dbDN, values, bodies)
}
