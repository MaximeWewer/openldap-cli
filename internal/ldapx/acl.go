package ldapx

import "github.com/MaximeWewer/openldap-cli/internal/acl"

// InjectAccess grants svc the given access to subtree by editing olcAccess on
// dbDN (an ordered attribute). Returns the resulting rule and whether it was
// appended at the end (vs inserted into an existing rule).
func (c *Client) InjectAccess(dbDN, subtree, svc, access string) (rule string, appended bool, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return "", false, err
	}
	edit, appended := acl.Inject(e.GetAll("olcAccess"), subtree, svc, access)
	var mods []Mod
	if edit.Delete != "" {
		mods = append(mods, Mod{Op: ModDelete, Name: "olcAccess", Values: []string{edit.Delete}})
	}
	mods = append(mods, Mod{Op: ModAdd, Name: "olcAccess", Values: []string{edit.Add}})
	return edit.Add, appended, c.Modify(dbDN, mods)
}

// RemoveAccessGrantee strips every clause referencing svc from olcAccess on dbDN.
func (c *Client) RemoveAccessGrantee(dbDN, svc string) (removed int, err error) {
	e, err := c.ReadEntry(dbDN, []string{"olcAccess"})
	if err != nil {
		return 0, err
	}
	edits, removed := acl.RemoveGrantee(e.GetAll("olcAccess"), svc)
	if removed == 0 {
		return 0, nil
	}
	var mods []Mod
	for _, ed := range edits {
		mods = append(mods,
			Mod{Op: ModDelete, Name: "olcAccess", Values: []string{ed.Delete}},
			Mod{Op: ModAdd, Name: "olcAccess", Values: []string{ed.Add}})
	}
	return removed, c.Modify(dbDN, mods)
}
