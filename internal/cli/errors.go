package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// LDAP's two most misleading refusals get a sentence of context here, once, on
// the way out — rather than at every call site.

// explain adds what the raw LDAP error does not say. It never hides the
// original: the hint is appended, so the result code stays greppable.
func explain(err error) error {
	switch {
	case errors.Is(err, ldapx.ErrAccountLocked):
		return fmt.Errorf("%w\n  unlock it with a rootDN bind: openldap-cli --profile <root-profile> user unlock <login>\n"+
			"  (it unlocks by itself after pwdLockoutDuration, if the policy sets one)", err)

	case ldapx.IsInvalidCredentials(err):
		// The server did not say why. A lockout looks exactly like a typo, and
		// retrying costs another attempt — so name the possibility rather than
		// let the password get the blame.
		return fmt.Errorf("%w\n  the password may simply be wrong — but a password-policy lockout looks identical,\n"+
			"  and this server did not say which (it discloses lockout only when the ppolicy\n"+
			"  overlay has olcPPolicyUseLockout: TRUE). `user info <login>`, run as an admin,\n"+
			"  reports LOCKED — and each retry can extend the lockout", err)

	case ldapx.IsInsufficientAccess(err):
		return fmt.Errorf("%w%s", err, rootDNHint())
	}
	return err
}

// rootDNHint names the rootDN to bind as, looked up from cn=config when we can.
// A rootDN bypasses the ACLs entirely, which is what writes like `ppolicy set`
// or an OU under the base need — the data admin has write only inside the
// subtrees the ACLs name.
func rootDNHint() string {
	const generic = "\n  your bind lacks write access there. Writes the ACLs do not grant need the\n" +
		"  database's rootDN (which bypasses ACLs); cn=config writes need config_bind_dn."

	cfg, err := loadConfig()
	if err != nil {
		return generic
	}
	cc, err := connectConfig()
	if err != nil {
		return generic // no config bind: we cannot look the rootDN up
	}
	defer cc.Close()

	db, err := cc.DataDatabaseDN(cfg.BaseDN)
	if err != nil {
		return generic
	}
	e, err := cc.ReadEntry(db, []string{"olcRootDN"})
	if err != nil {
		return generic
	}
	rootDN := strings.TrimSpace(e.Get("olcRootDN"))
	if rootDN == "" {
		return generic
	}
	return fmt.Sprintf("\n  your bind (%s) lacks write access there. Writes the ACLs do not grant need\n"+
		"  the rootDN of %s, which is %s — bind as it with a profile of its own.\n"+
		"  (cn=config writes use config_bind_dn instead.)", cfg.BindDN, cfg.BaseDN, rootDN)
}
