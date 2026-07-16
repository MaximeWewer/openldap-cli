package ldapx

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// A ppolicy lockout is indistinguishable from a typo: slapd answers both with
// `Invalid Credentials`, so the natural reaction — retry the password — burns
// another attempt. The password-policy control is the only way to tell, and the
// server only fills it in when olcPPolicyUseLockout is TRUE (it defaults to
// FALSE, deliberately: disclosing lockout tells an attacker the account exists
// and that its state can be probed). So we ask, report what we are told, and
// say we do not know when we are told nothing.

// ErrAccountLocked reports a bind refused because the password policy locked the
// account — the password itself may well be right.
var ErrAccountLocked = errors.New("the account is locked by the password policy (too many failed binds)")

// ErrPasswordExpired reports a bind refused because the password has expired.
var ErrPasswordExpired = errors.New("the password has expired")

// ErrMustChangePassword reports a bind refused until the password is reset.
var ErrMustChangePassword = errors.New("the password must be changed before binding")

// bindWithPolicy binds and, when the server says why it refused, wraps the error
// with that reason. Empty passwords stay rejected client-side, as conn.Bind does.
func bindWithPolicy(conn *ldap.Conn, dn, pw string) error {
	res, err := conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: dn,
		Password: pw,
		Controls: []ldap.Control{ldap.NewControlBeheraPasswordPolicy()},
	})
	if err == nil {
		return nil
	}
	// SimpleBind fills the controls before returning the error, so a refused
	// bind still carries the policy's verdict.
	if res != nil {
		for _, c := range res.Controls {
			p, ok := c.(*ldap.ControlBeheraPasswordPolicy)
			if !ok {
				continue
			}
			// Error is -1 when the server declines to say (the default)
			switch p.Error {
			case ldap.BeheraAccountLocked:
				return fmt.Errorf("%w\n  %w", err, ErrAccountLocked)
			case ldap.BeheraPasswordExpired:
				return fmt.Errorf("%w\n  %w", err, ErrPasswordExpired)
			case ldap.BeheraChangeAfterReset:
				return fmt.Errorf("%w\n  %w", err, ErrMustChangePassword)
			}
		}
	}
	return err
}

// IsInvalidCredentials reports the bind refusal that means "wrong password —
// or something the server would rather not name".
func IsInvalidCredentials(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials)
}

// IsInsufficientAccess reports a write the bound identity's ACLs do not allow.
func IsInsufficientAccess(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights)
}
