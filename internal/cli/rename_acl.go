package cli

import (
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// noFixACL backs the --no-fix-acl flag on every command that changes a DN.
var noFixACL bool

// withFixACLFlag registers --no-fix-acl on a command that moves an entry.
func withFixACLFlag(cmds ...*cobra.Command) {
	for _, c := range cmds {
		c.Flags().BoolVar(&noFixACL, "no-fix-acl", false,
			"do not re-point the olcAccess rules naming the old DN (they will silently stop matching)")
	}
}

// fixACLRefs re-points the olcAccess rules naming oldDN at newDN, after a
// rename has moved the entry.
//
// slapd rewrites nothing on its own: a rule saying `by group.exact="cn=old,…"`
// or `to dn.subtree="ou=old,…"` keeps naming a DN that no longer exists, so it
// stops matching and the access it granted is silently lost. Leaving that to the
// operator means leaving it undone, so this runs by default.
//
// Group MEMBERSHIP is a separate reference with its own repair — see refint.go.
// It is not automatic either: `member` follows a rename only when the server was
// configured to maintain it.
//
// It is called AFTER the rename: repairing first would point the rules at a DN
// that does not exist yet if the rename then failed. The rename is the caller's
// intent and has already succeeded, so a repair failure is reported (the caller
// surfaces it) rather than rolled back.
//
// Needs the config bind. Without it we cannot even read olcAccess, so we say so
// instead of implying the rename was clean.
func fixACLRefs(oldDN, newDN string) error {
	if noFixACL {
		log.Debug().Str("old_dn", oldDN).Msg("--no-fix-acl: leaving olcAccess alone")
		return nil
	}
	cc, err := connectConfig()
	if err != nil {
		log.Warn().Str("old_dn", oldDN).
			Msg("renamed, but olcAccess was NOT checked (no config bind): any rule naming the old DN now matches nothing — review by hand, or set config_bind_dn")
		return nil
	}
	defer cc.Close()

	db, err := cc.DataDatabaseDN(cc.Config().BaseDN)
	if err != nil {
		return fmt.Errorf("renamed, but the database holding olcAccess could not be located to repair it: %w", err)
	}
	rewritten, skipped, err := cc.RenameAccessDN(db, oldDN, newDN)
	if err != nil {
		return fmt.Errorf("renamed, but repairing olcAccess on %s FAILED — rules still name %q and grant nothing: %w", db, oldDN, err)
	}
	if rewritten > 0 {
		log.Info().Int("dns", rewritten).Str("db", db).Msg("olcAccess re-pointed at the new DN")
	}
	for _, s := range skipped {
		log.Warn().Msg("olcAccess rule names the old DN but uses regex=/set=, which cannot be rewritten safely — fix it by hand: " + s)
	}
	return nil
}
