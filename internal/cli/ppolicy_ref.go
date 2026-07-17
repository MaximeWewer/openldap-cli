package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// Password policy is attached by reference: pwdPolicySubentry on a user,
// olcPPolicyDefault on the overlay. Nothing in LDAP enforces that either DN
// resolves, and slapd's behavior when one does not is the dangerous one — from
// ppolicy_get():
//
//	rc = be_entry_get_rw( op, vals, oc_pwdPolicy, NULL, 0, &pe );
//	if ( rc ) goto defaultpol;
//	...
//	defaultpol:
//	    Debug( ..., "policy subentry %s missing or invalid at '%s', "
//	                "no policy will be applied!\n", ... );
//	    ppolicy_get_default( pp );
//
// `defaultpol` is NOT olcPPolicyDefault — it is the empty policy: no minimum
// length, no lockout, no history, no expiry. The bind still succeeds. So a
// dangling reference does not fail closed, it switches password policy OFF for
// whoever carries it, silently. A typo in `assign` is a security downgrade, and
// deleting a policy still in use is the same downgrade for every user on it.
//
// Note the objectClass filter in that fetch: an entry that exists but is not a
// pwdPolicy lands on `defaultpol` exactly like a missing one. Existence alone is
// not enough to check.
//
// Both checks below are plain searches. pwdPolicySubentry and olcPPolicyDefault
// are DN-syntax with EQUALITY distinguishedNameMatch, so slapd normalizes the
// comparison itself and finds the references whatever the spelling — no
// client-side DN comparison to get wrong.

// resolvePolicy returns the DN of the policy named name, erroring unless it
// exists and is a pwdPolicy.
func resolvePolicy(cli *ldapx.Client, name string) (string, error) {
	found, err := cli.Search(cli.PolicyBase(),
		fmt.Sprintf("(&(objectClass=pwdPolicy)(cn=%s))", ldapx.EscapeFilter(name)), []string{"cn"})
	if err != nil {
		return "", fmt.Errorf("lookup policy %q: %w", name, err)
	}
	if len(found) == 0 {
		return "", noSuchPolicy(cli, name)
	}
	// the server's own DN, already normalized
	return found[0].DN, nil
}

// noSuchPolicy names the policies that do exist: what this catches is a typo.
func noSuchPolicy(cli *ldapx.Client, name string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "no password policy named %q under %s", name, cli.PolicyBase())
	if strings.Contains(name, "=") {
		b.WriteString("\n\nThis takes a policy name (e.g. `strict`), not a DN.")
	}
	if pols, err := cli.Search(cli.PolicyBase(), "(objectClass=pwdPolicy)", []string{"cn"}); err == nil {
		if len(pols) == 0 {
			fmt.Fprintf(&b, "\n\nNo policy exists yet — create one with `ppolicy set %s …`.", name)
		} else {
			b.WriteString("\n\nExisting policies:")
			for _, p := range pols {
				fmt.Fprintf(&b, "\n    %s", p.Get("cn"))
			}
		}
	}
	return errors.New(b.String())
}

// policyAssignees returns the DNs of the entries whose pwdPolicySubentry names
// policyDN.
func policyAssignees(cli *ldapx.Client, policyDN string) ([]string, error) {
	entries, err := searchAll(cli, cli.Config().BaseDN,
		fmt.Sprintf("(pwdPolicySubentry=%s)", ldapx.EscapeFilter(policyDN)), []string{"cn"})
	if err != nil {
		return nil, err
	}
	dns := make([]string, 0, len(entries))
	for _, e := range entries {
		dns = append(dns, e.DN)
	}
	return dns, nil
}

// policyIsDefault reports whether policyDN is some ppolicy overlay's
// olcPPolicyDefault, and which overlay entry names it. Deleting that policy
// disables password policy for every user carrying no pwdPolicySubentry of their
// own — i.e. the whole directory.
//
// Needs the config bind; the caller decides what being unable to check means.
func policyIsDefault(policyDN string) (bool, string, error) {
	cc, err := connectConfig()
	if err != nil {
		return false, "", err
	}
	defer cc.Close()
	ov, err := cc.Search("cn=config",
		fmt.Sprintf("(&(objectClass=olcPPolicyConfig)(olcPPolicyDefault=%s))", ldapx.EscapeFilter(policyDN)),
		[]string{"olcPPolicyDefault"})
	if err != nil {
		return false, "", err
	}
	if len(ov) == 0 {
		return false, "", nil
	}
	return true, ov[0].DN, nil
}

// policyRefReason returns why policyDN would land slapd on `defaultpol`, or ""
// if the reference is sound.
func policyRefReason(cli *ldapx.Client, policyDN string) string {
	e, err := cli.ReadEntry(policyDN, []string{"objectClass"})
	if err != nil {
		if ldapx.IsNoSuchObject(err) {
			return "no such entry"
		}
		// unreadable is not the same as absent, and slapd reads it as itself,
		// not as this bind — say what we actually know
		return "could not be read (" + err.Error() + ")"
	}
	for _, oc := range e.GetAll("objectClass") {
		if strings.EqualFold(oc, "pwdPolicy") {
			return ""
		}
	}
	return "exists but is not a pwdPolicy entry"
}

// danglingRef is one reference that does not resolve to a usable policy.
type danglingRef struct {
	Entry  string `json:"entry" yaml:"entry"`
	Policy string `json:"policy" yaml:"policy"`
	Reason string `json:"reason" yaml:"reason"`
}

type policyCheckResult struct {
	Scanned  int           `json:"scanned" yaml:"scanned"`
	Dangling []danglingRef `json:"dangling,omitempty" yaml:"dangling,omitempty"`
	// Note carries what could not be checked, so a clean report cannot be read
	// as "everything resolves" when a check was skipped.
	Note string `json:"note,omitempty" yaml:"note,omitempty"`
}

func (r policyCheckResult) Text() string {
	var b strings.Builder
	if len(r.Dangling) == 0 {
		fmt.Fprintf(&b, "%d policy reference(s) checked, all resolve\n", r.Scanned)
	} else {
		fmt.Fprintf(&b, "%d of %d policy reference(s) do NOT resolve — these carry NO password\n"+
			"policy at all (no minimum length, no lockout, no history). slapd does not\n"+
			"fall back to the default for them.\n\n", len(r.Dangling), r.Scanned)
		for _, d := range r.Dangling {
			fmt.Fprintf(&b, "  %s\n      -> %s (%s)\n", d.Entry, d.Policy, d.Reason)
		}
		b.WriteString("\nRepair: `ppolicy assign <login> <policy>` to re-point, or `--clear` to fall\n" +
			"back to the overlay default.\n")
	}
	if r.Note != "" {
		fmt.Fprintf(&b, "\n%s\n", r.Note)
	}
	return strings.TrimRight(b.String(), "\n")
}

// checkPolicyRefs finds every pwdPolicySubentry, plus the overlay default, that
// does not resolve to a pwdPolicy entry. Distinct policy DNs are resolved once.
func checkPolicyRefs(cli *ldapx.Client) (policyCheckResult, error) {
	res := policyCheckResult{}
	entries, err := searchAll(cli, cli.Config().BaseDN, "(pwdPolicySubentry=*)", []string{"pwdPolicySubentry"})
	if err != nil {
		return res, fmt.Errorf("search assigned policies: %w", err)
	}
	seen := map[string]string{}
	reason := func(dn string) string {
		if r, ok := seen[dn]; ok {
			return r
		}
		r := policyRefReason(cli, dn)
		seen[dn] = r
		return r
	}
	for _, e := range entries {
		p := e.Get("pwdPolicySubentry")
		res.Scanned++
		if r := reason(p); r != "" {
			res.Dangling = append(res.Dangling, danglingRef{Entry: e.DN, Policy: p, Reason: r})
		}
	}

	// The overlay default is a reference too, and the one whose failure covers
	// every user who has no policy of their own.
	cc, err := connectConfig()
	if err != nil {
		res.Note = "The overlay default (olcPPolicyDefault) was NOT checked: no config bind. " +
			"If it dangles, every user without a policy of their own has none."
		return res, nil
	}
	defer cc.Close()
	ov, err := cc.Search("cn=config", "(objectClass=olcPPolicyConfig)", []string{"olcPPolicyDefault"})
	if err != nil {
		res.Note = "The overlay default (olcPPolicyDefault) could not be read: " + err.Error()
		return res, nil
	}
	for _, e := range ov {
		d := e.Get("olcPPolicyDefault")
		if d == "" {
			continue
		}
		res.Scanned++
		if r := reason(d); r != "" {
			res.Dangling = append(res.Dangling, danglingRef{Entry: e.DN + " (overlay default)", Policy: d, Reason: r})
		}
	}
	return res, nil
}

// checkPolicyUnreferenced refuses a delete that would leave a dangling
// reference, spelling out what the deletion would actually switch off.
func checkPolicyUnreferenced(cli *ldapx.Client, dn string) error {
	assignees, aerr := policyAssignees(cli, dn)
	isDefault, overlayDN, derr := policyIsDefault(dn)

	// Being unable to check is not the same as being clean, and this is the one
	// place that distinction decides whether policy stays on.
	if aerr != nil {
		return fmt.Errorf("refusing to delete %s: could not check who is assigned to it (%w)\n\n"+
			"A user left pointing at a deleted policy gets NO policy at all.\n"+
			"Re-run with --force to delete anyway.", dn, aerr)
	}
	if len(assignees) == 0 && !isDefault && derr == nil {
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "refusing to delete %s: it is still in use", dn)
	if isDefault {
		fmt.Fprintf(&b, "\n\nIt is the ppolicy overlay's default (olcPPolicyDefault on %s).\n"+
			"Deleting it turns password policy OFF for every user who has no policy of\n"+
			"their own — the whole directory.", overlayDN)
	}
	if len(assignees) > 0 {
		fmt.Fprintf(&b, "\n\n%d entrie(s) are assigned to it (pwdPolicySubentry):", len(assignees))
		for _, a := range assignees {
			fmt.Fprintf(&b, "\n    %s", a)
		}
		b.WriteString("\n\nEach would keep pointing at a DN that no longer resolves, and slapd\n" +
			"applies NO policy to such a user — no minimum length, no lockout, no\n" +
			"history. It does not fall back to the default.")
	}
	if derr != nil {
		fmt.Fprintf(&b, "\n\nCould not check whether it is the overlay default (%v) — assuming it is not.", derr)
	}

	b.WriteString("\n\nTo delete it, first move the users off it:")
	if len(assignees) > 0 {
		fmt.Fprintf(&b, "\n    openldap-cli ppolicy assign <login> <other-policy>   # or --clear for the default")
	}
	if isDefault {
		fmt.Fprintf(&b, "\n    openldap-cli config set %s olcPPolicyDefault <other-policy-dn>", overlayDN)
	}
	fmt.Fprintf(&b, "\n\nOr re-run with --force to delete it and leave the references dangling.")
	return errors.New(b.String())
}
