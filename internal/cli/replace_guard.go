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
//
// "Multi-valued" is a property of the SCHEMA, not of the entry. An attribute
// holding one value today is not single-valued — `member` on a group with one
// member, `olcAccess` on a database with one rule, `olcDbIndex` on a stock mdb
// — and those are exactly the cases where the replace silently destroys the only
// value there was.

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
// Whether an attribute is multi-valued is the schema's SINGLE-VALUE flag, never
// how many values the entry happens to hold: a database with one olcAccess rule,
// or a group with one member, is a multi-valued attribute holding one value, and
// counting would wave through the replace that deletes it.
//
// Neither read failing is treated as "nothing to lose" — the caller decides, but
// it is not this function's place to wave the write through on no evidence.
func guardReplace(cli *ldapx.Client, dn, attr string, newValues []string) error {
	single, err := cli.IsSingleValued(attr)
	if err != nil {
		return fmt.Errorf("check whether %s is multi-valued before replacing it on %s: %w\n\n"+
			"  `set` replaces the whole attribute. Without the schema there is no way to\n"+
			"  tell whether that drops other values — re-run with --force to do it anyway", attr, dn, err)
	}
	if single {
		return nil // single-valued: replacing it is the point
	}
	e, err := cli.ReadEntry(dn, []string{attr})
	if err != nil {
		return fmt.Errorf("read %s on %s to check what a replace would drop: %w", attr, dn, err)
	}
	current := e.GetAll(attr)
	if len(current) == 0 {
		return nil // nothing there to lose
	}
	// `set <attr>` with no values is the documented delete verb: the caller is
	// keeping nothing and knows it. Taking out the single value they can see is
	// not the drop-by-surprise this guards against — but taking out several at
	// once still deserves the list.
	if len(newValues) == 0 && len(current) == 1 {
		return nil
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
	plural := func(n int) string {
		if n == 1 {
			return ""
		}
		return "s"
	}
	fmt.Fprintf(&b, "%s holds %d value%s on %s, and this would delete %d of them:\n",
		attr, len(current), plural(len(current)), dn, len(lost))
	for _, v := range lost {
		fmt.Fprintf(&b, "\n    %s", v)
	}
	fmt.Fprintf(&b, "\n\n  `set` replaces the whole attribute — it does not add to it.")
	if len(current) == 1 {
		// the counter-intuitive case: one value looks single-valued, and the
		// replace reads like an update right up until the value is gone
		fmt.Fprintf(&b, "\n  (%s holds one value here, but the schema says it is multi-valued —\n"+
			"  so this deletes rather than updates.)", attr)
	}
	if strings.EqualFold(attr, "olcAccess") {
		b.WriteString("\n  For ACLs use `config acl grant` / `revoke` / `delete`, which edit one rule.")
	}
	b.WriteString("\n  To append a value, use --add. To pass the values you keep, list them all.\n" +
		"  To delete them on purpose, re-run with --force")
	return fmt.Errorf("%s", b.String())
}
