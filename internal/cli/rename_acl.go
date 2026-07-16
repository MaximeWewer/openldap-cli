package cli

import (
	"strings"

	"github.com/rs/zerolog/log"
)

// warnStaleACLRefs reports olcAccess rules that still name oldDN after a rename.
//
// slapd rewrites nothing in olcAccess when an entry is renamed: a rule saying
// `by group.exact="cn=old,…"` or `to dn.subtree="ou=old,…"` keeps pointing at a
// DN that no longer exists, so it silently stops matching — the access is gone
// with no error anywhere. (memberOf, by contrast, IS maintained by the memberof
// overlay, so group membership survives a rename.)
//
// Rules are matched on the DN as a substring, which also catches the rules
// naming entries BELOW a renamed container — those moved too.
//
// Checking needs the config bind. Without it we say so rather than imply the
// rename was clean; a failed check is never fatal, the rename already happened.
func warnStaleACLRefs(oldDN string) {
	cc, err := connectConfig()
	if err != nil {
		log.Warn().Str("dn", oldDN).Msg("could not check olcAccess for rules naming the old DN (no config bind): review them by hand")
		return
	}
	defer cc.Close()

	db, err := cc.DataDatabaseDN(cc.Config().BaseDN)
	if err != nil {
		log.Warn().Err(err).Msg("could not locate the database to check olcAccess for the old DN")
		return
	}
	e, err := cc.ReadEntry(db, []string{"olcAccess"})
	if err != nil {
		log.Warn().Err(err).Msg("could not read olcAccess to check for the old DN")
		return
	}

	needle := strings.ToLower(oldDN)
	var stale []string
	for _, v := range e.GetAll("olcAccess") {
		if strings.Contains(strings.ToLower(v), needle) {
			stale = append(stale, v)
		}
	}
	if len(stale) == 0 {
		return
	}
	log.Warn().Int("rules", len(stale)).Str("old_dn", oldDN).Str("db", db).
		Msg("olcAccess still names the OLD DN — those rules no longer match anything and their access is silently lost; re-grant them against the new DN")
	for _, v := range stale {
		log.Warn().Msg("  " + v)
	}
}
