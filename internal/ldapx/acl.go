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

// RemoveAccessGrantee strips every clause referencing who (a full who-token)
// from olcAccess on dbDN, dropping any rule left with nothing to say. Reports
// how many clauses were removed and how many rules that emptied out.
func (c *Client) RemoveAccessGrantee(dbDN, who string) (removed, dropped int, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return 0, 0, err
	}
	bodies, removed, dropped := acl.RemoveGrantee(e.GetAll("olcAccess"), who)
	if removed == 0 {
		return 0, 0, nil
	}
	// one replace of the whole ordered attribute: see acl.RemoveGrantee.
	return removed, dropped, c.Modify(dbDN, []Mod{{Op: ModReplace, Name: "olcAccess", Values: bodies}})
}
