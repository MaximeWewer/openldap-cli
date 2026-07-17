package cli

import (
	"fmt"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// `set` means REPLACE: the values you do not name are gone. On a single-valued
// attribute that is the whole point. On a multi-valued one — olcAccess,
// olcLimits, olcModuleLoad, member — naming one value deletes the rest, and the
// command still reports success. Wiping every ACL on a database is one
// `config set olcAccess '<one rule>'` away.
//
// So a replace that would drop values it was not shown is refused, and says
// which ones.

// stripIndex removes the `{N}` ordering prefix cn=config puts on the values of
// ordered attributes. The server hands values back indexed and takes them back
// unindexed, so comparing raw strings would call an exact rewrite a total loss.
func stripIndex(v string) string {
	if strings.HasPrefix(v, "{") {
		if i := strings.IndexByte(v, '}'); i > 0 {
			return v[i+1:]
		}
	}
	return v
}

// guardReplace reports the values a replace of attr on dn would drop.
//
// It only guards MULTI-valued attributes: replacing the single value of, say,
// olcDbMaxSize is exactly what `set` is for. Values the caller passes again are
// not lost, so a faithful full rewrite goes through untouched.
//
// A read that fails is not treated as "nothing to lose" — the caller decides,
// but it is not this function's place to wave the write through on no evidence.
func guardReplace(cli *ldapx.Client, dn, attr string, newValues []string) error {
	e, err := cli.ReadEntry(dn, []string{attr})
	if err != nil {
		return fmt.Errorf("read %s on %s to check what a replace would drop: %w", attr, dn, err)
	}
	current := e.GetAll(attr)
	if len(current) <= 1 {
		return nil // single-valued: replacing it is the point
	}
	keep := make(map[string]bool, len(newValues))
	for _, v := range newValues {
		keep[stripIndex(v)] = true
	}
	var lost []string
	for _, v := range current {
		if !keep[stripIndex(v)] {
			lost = append(lost, v)
		}
	}
	if len(lost) == 0 {
		return nil // every existing value was passed back
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s holds %d values on %s, and this would delete %d of them:\n", attr, len(current), dn, len(lost))
	for _, v := range lost {
		fmt.Fprintf(&b, "\n    %s", v)
	}
	fmt.Fprintf(&b, "\n\n  `set` replaces the whole attribute — it does not add to it.")
	if strings.EqualFold(attr, "olcAccess") {
		b.WriteString("\n  For ACLs use `config acl grant` / `revoke` / `delete`, which edit one rule.")
	}
	b.WriteString("\n  To append a value, use --add. To pass the values you keep, list them all.\n" +
		"  To delete them on purpose, re-run with --force")
	return fmt.Errorf("%s", b.String())
}
