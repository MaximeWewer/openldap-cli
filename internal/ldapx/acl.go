package ldapx

import "github.com/MaximeWewer/openldap-cli/internal/acl"

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
	bodies, rewritten, skipped := acl.RenameDN(e.GetAll("olcAccess"), oldDN, newDN)
	if rewritten == 0 {
		return 0, skipped, nil
	}
	// one replace of the whole ordered attribute: see acl.RemoveGrantee.
	return rewritten, skipped, c.Modify(dbDN, []Mod{{Op: ModReplace, Name: "olcAccess", Values: bodies}})
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
	// one replace of the whole ordered attribute: see acl.RemoveGrantee.
	return removed, dropped, c.Modify(dbDN, []Mod{{Op: ModReplace, Name: "olcAccess", Values: bodies}})
}
