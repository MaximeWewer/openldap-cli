package cli

import (
	"fmt"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// A `backup data` dump goes through an ordinary LDAP search bound as the
// profile's identity, so slapd applies that identity's ACLs to it — dropping
// whole entries it may not see, and individual attributes (userPassword above
// all) it may not read. The count then reads as a complete backup when it is a
// filtered subset, and restoring it recreates users who cannot authenticate,
// minus whatever entries were invisible.
//
// Only the rootDN bypasses access control, so only a rootDN dump is complete by
// construction. This checks which case a dump is, and quantifies the gap when it
// can: the true entry count is one monitor read away (olmMDBEntries), the same
// figure `ops db-stats` reports.

// backupAudit is what could be established about a dump's completeness.
type backupAudit struct {
	// Verified is true when the dump was taken by the database's rootDN, so
	// nothing was filtered.
	Verified bool `json:"verified" yaml:"verified"`
	// Bind is the identity the dump was taken as.
	Bind string `json:"bind,omitempty" yaml:"bind,omitempty"`
	// Total is the database's real entry count (olmMDBEntries), or -1 when it
	// could not be read.
	Total int `json:"total,omitempty" yaml:"total,omitempty"`
	// Missing is Total minus the number dumped, when both are known and the dump
	// is short.
	Missing int `json:"missing,omitempty" yaml:"missing,omitempty"`
	// Note explains what could not be checked, so a quiet result is never read as
	// a clean bill of health.
	Note string `json:"note,omitempty" yaml:"note,omitempty"`
}

// auditBackup assesses a just-written dump of base that produced `dumped`
// entries. It never fails the backup — the file is already written; it reports
// what the file is.
func auditBackup(cli *ldapx.Client, base string, dumped int) backupAudit {
	a := backupAudit{Total: -1}

	bound, err := cli.WhoAmI()
	if err == nil {
		a.Bind = strings.TrimPrefix(bound, "dn:")
	}

	cc, err := connectConfig()
	if err != nil {
		a.Note = "completeness NOT verified: no config bind to read the database's rootDN. " +
			"Unless this dump was taken by the rootDN, ACL-filtered entries and attributes " +
			"(userPassword) are silently absent."
		return a
	}
	defer cc.Close()

	db, err := cc.DataDatabaseDN(base)
	if err != nil {
		a.Note = "completeness NOT verified: could not locate the database for " + base + ": " + err.Error()
		return a
	}

	a.Verified = boundIsRootDN(cc, db, a.Bind)
	a.Total = databaseEntryCount(cc, base)
	if !a.Verified && a.Total > dumped {
		a.Missing = a.Total - dumped
	}
	return a
}

// boundIsRootDN reports whether bound is the rootDN of the database at dbDN.
// The comparison is left to slapd: olcRootDN is DN-syntax with an equality
// match, so a server-side filter normalizes case and spacing that a string
// compare would get wrong. An empty bind (anonymous, or WhoAmI unsupported) is
// never the rootDN.
func boundIsRootDN(cc *ldapx.Client, dbDN, bound string) bool {
	if bound == "" {
		return false
	}
	es, err := cc.Search(dbDN, fmt.Sprintf("(olcRootDN=%s)", ldapx.EscapeFilter(bound)), []string{"olcRootDN"})
	return err == nil && len(es) > 0
}

// databaseEntryCount returns the database's real entry count from the monitor
// backend, or -1 when it cannot be read (monitor not enabled, or no match).
func databaseEntryCount(cc *ldapx.Client, suffix string) int {
	es, err := cc.Search("cn=Databases,cn=Monitor", "(olmMDBEntries=*)",
		[]string{"namingContexts", "olmMDBEntries"})
	if err != nil {
		return -1
	}
	for _, e := range es {
		if strings.EqualFold(strings.TrimSpace(e.Get("namingContexts")), strings.TrimSpace(suffix)) {
			return atoi(e.Get("olmMDBEntries"))
		}
	}
	return -1
}

// Warning renders the completeness caveat for the text output, or "" when the
// dump is verified complete.
func (a backupAudit) Warning() string {
	if a.Verified {
		return ""
	}
	var b strings.Builder
	if a.Missing > 0 {
		fmt.Fprintf(&b, "INCOMPLETE: %d of the database's %d entries are missing — this bind cannot\n"+
			"  read them, and the dump does not include what it cannot see.", a.Missing, a.Total)
	} else {
		b.WriteString("NOT a verified-complete backup: it reflects only what this bind can read.")
	}
	if a.Bind != "" {
		fmt.Fprintf(&b, "\n  Taken as %s, not the database's rootDN.", a.Bind)
	}
	b.WriteString("\n  ACL-filtered ATTRIBUTES are dropped silently too — userPassword most of all,\n" +
		"  so a restore can recreate accounts that cannot authenticate. Take backups as\n" +
		"  the rootDN, whose reads bypass every ACL.")
	if a.Note != "" {
		fmt.Fprintf(&b, "\n  %s", a.Note)
	}
	return b.String()
}
