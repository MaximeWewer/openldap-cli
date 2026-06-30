package cli

import (
	"fmt"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/pwd"
)

// genMinLength is the floor for generated passwords, regardless of policy.
const genMinLength = 20

// genPasswordRetries caps how many times a generated password is regenerated
// (each time longer) when the server rejects it on quality grounds.
const genPasswordRetries = 4

// setGeneratedPassword generates a strong password sized to dn's effective
// policy and sets it via Password Modify, returning the accepted password. It
// retries with a longer one on a constraint violation, covering policies whose
// pwdMinLength/quality the resolver could not introspect.
func setGeneratedPassword(cli *ldapx.Client, dn string) (string, error) {
	return setGeneratedPasswordLen(cli, dn, genLength(cli, dn))
}

// setGeneratedPasswordLen is setGeneratedPassword with an explicit starting
// length (so bulk callers resolve the policy once and reuse it).
func setGeneratedPasswordLen(cli *ldapx.Client, dn string, startLen int) (string, error) {
	n := startLen
	var err error
	for range genPasswordRetries {
		var p string
		if p, err = pwd.Strong(n); err != nil {
			return "", err
		}
		if _, serr := cli.SetPassword(dn, p); serr != nil {
			if ldapx.IsConstraintViolation(serr) {
				err = serr
				n += 8 // rejected as too weak/short — strengthen and retry
				continue
			}
			return "", serr
		}
		return p, nil
	}
	return "", fmt.Errorf("password rejected by the policy after %d attempts (last length %d) — pass --password explicitly: %w",
		genPasswordRetries, n-8, err)
}

// genLength returns the length to generate a password at: the larger of
// genMinLength and the effective pwdMinLength for userDN.
func genLength(cli *ldapx.Client, userDN string) int {
	if n := policyMinLength(cli, userDN); n > genMinLength {
		return n
	}
	return genMinLength
}

// policyMinLength resolves the effective pwdMinLength for userDN, returning 0
// when it cannot be determined. Best-effort and side-effect-free: it tries, in
// order, the user's own assigned policy (pwdPolicySubentry), the ppolicy overlay
// default (olcPPolicyDefault, read via the config bind), then the sole policy if
// exactly one exists under the policy OU. Any error short-circuits to the next
// source; the caller falls back to genMinLength.
func policyMinLength(cli *ldapx.Client, userDN string) int {
	readMin := func(policyDN string) int {
		if policyDN == "" {
			return 0
		}
		e, err := cli.ReadEntry(policyDN, []string{"pwdMinLength"})
		if err != nil {
			return 0
		}
		return atoi(e.Get("pwdMinLength"))
	}

	// 1. the user's assigned policy (operational attribute on the entry)
	if userDN != "" {
		if e, err := cli.ReadEntry(userDN, []string{"pwdPolicySubentry"}); err == nil {
			if n := readMin(e.Get("pwdPolicySubentry")); n > 0 {
				return n
			}
		}
	}

	// 2. the ppolicy overlay default (olcPPolicyDefault lives in cn=config)
	if cc, err := connectConfig(); err == nil {
		defer cc.Close()
		if ov, err := cc.Search("cn=config", "(objectClass=olcPPolicyConfig)", []string{"olcPPolicyDefault"}); err == nil {
			for _, e := range ov {
				if n := readMin(e.Get("olcPPolicyDefault")); n > 0 {
					return n
				}
			}
		}
	}

	// 3. exactly one policy under the policy OU
	if pols, err := cli.Search(cli.PolicyBase(), "(objectClass=pwdPolicy)", []string{"pwdMinLength"}); err == nil && len(pols) == 1 {
		return atoi(pols[0].Get("pwdMinLength"))
	}
	return 0
}
