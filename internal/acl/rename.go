package acl

import "strings"

// Renaming an entry changes its DN, and slapd rewrites nothing in olcAccess:
// every rule naming the old DN keeps naming it and silently stops matching.
// These helpers compute the rewritten rules so a rename can repair itself.

// unsafeToRewrite reports rule forms whose DNs cannot be rewritten mechanically:
//
//   - dn.regex=/group.regex=: the value is a regular expression, so a literal
//     substitution can change what it matches (an old DN carrying regex
//     metacharacters, an anchor spanning the part we would replace).
//   - set=: an ACL-set expression, a small language of its own.
//
// They are reported for review instead of being mangled.
func unsafeToRewrite(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "regex=") || strings.Contains(l, "set=")
}

// dnValueStart reports whether c can precede a DN value: `="…` and `"` open one,
// and `,` precedes the suffix of a longer DN (the case that catches the entries
// BELOW a renamed container).
func dnValueStart(c byte) bool { return c == '=' || c == '"' || c == ',' }

// dnValueEnd reports whether c terminates a DN value. A DN must match at its
// END — `,` is excluded on purpose: it would mean the old DN is only a PREFIX
// of the DN in the rule (`ou=old` inside `cn=x,ou=old,…` is a suffix and does
// match; `ou=old,dc=x` inside `ou=old,dc=x,dc=y` is a prefix and does not).
func dnValueEnd(c byte) bool {
	return c == '"' || c == ')' || c == ' ' || c == '\t'
}

// rewriteDNs replaces every DN in body that is oldDN, or sits beneath it, with
// the same DN re-based on newDN. It matches DN-insensitively (case) but keeps
// the rest of the rule byte-for-byte.
//
// It works on DN values wherever they appear — `to dn.subtree="…"`,
// `by dn.exact="…"`, `by group.exact="…"`, and inside a filter such as
// `filter=(memberOf=cn=devs,…)` (what `svc grant --members-of` emits) — rather
// than parsing each token, because they all quote or delimit DNs the same way.
func rewriteDNs(body, oldDN, newDN string) (out string, n int) {
	lb, lo := strings.ToLower(body), strings.ToLower(strings.TrimSpace(oldDN))
	if lo == "" {
		return body, 0
	}
	var b strings.Builder
	for i := 0; i < len(body); {
		j := strings.Index(lb[i:], lo)
		if j < 0 {
			b.WriteString(body[i:])
			break
		}
		start := i + j
		end := start + len(lo)
		// a DN value must open just before the match and close right after it
		okLeft := start > 0 && dnValueStart(body[start-1])
		okRight := end == len(body) || dnValueEnd(body[end])
		if !okLeft || !okRight {
			b.WriteString(body[i : start+1]) // not a DN here: step past this byte
			i = start + 1
			continue
		}
		b.WriteString(body[i:start])
		b.WriteString(newDN)
		n++
		i = end
	}
	return b.String(), n
}

// RenameDN re-points every olcAccess rule naming oldDN (or an entry beneath it)
// at newDN.
//
// It returns the COMPLETE rule list in order and without index prefixes, for a
// single olcAccess replace — the same mechanism as Reorder and RemoveGrantee.
// skipped holds the rules that name oldDN but cannot be rewritten safely
// (see unsafeToRewrite); they are returned unchanged and must be fixed by hand.
func RenameDN(values []string, oldDN, newDN string) (bodies []string, rewritten int, skipped []string) {
	lo := strings.ToLower(strings.TrimSpace(oldDN))
	for _, r := range splitRules(values) {
		if !strings.Contains(strings.ToLower(r.body), lo) {
			bodies = append(bodies, r.body)
			continue
		}
		if unsafeToRewrite(r.body) {
			skipped = append(skipped, r.body)
			bodies = append(bodies, r.body)
			continue
		}
		nb, n := rewriteDNs(r.body, oldDN, newDN)
		rewritten += n
		bodies = append(bodies, nb)
	}
	return bodies, rewritten, skipped
}
