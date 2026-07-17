package acl

import (
	"fmt"
	"sort"
	"strings"
)

// Levels reported by Lint.
const (
	LevelDead = "dead" // the rule can never fire
	LevelWarn = "warn" // suspicious, but not provably broken
)

// Finding is one lint result about a rule.
type Finding struct {
	Index   int    // the rule's {N} index
	Level   string // LevelDead | LevelWarn
	Rule    string // the rule body
	Message string
}

// selector is the parsed `to …` part of a rule.
type selector struct {
	raw   string
	kind  string // "*" | "attrs" | "dn" | "other"
	scope string // base | one | children | subtree | regex (dn kind only)
	dn    string // lower-cased target DN (dn kind only)
	// filter is the LDAP filter narrowing the selector, lower-cased ("" = none).
	// The text matters, not just its presence: two rules on the same tree with
	// DIFFERENT filters are different rules, and treating them as one would
	// inject a grant into the wrong one.
	filter string
	attrs  string // the attribute list it is narrowed to ("" = the whole entry)
}

// normalizeScope maps slapd.access(5)'s dnstyle synonyms onto one spelling.
// Missing one is not cosmetic: an unknown scope makes covers() give up, so a
// perfectly ordinary `dn.sub=` rule would stop being seen as shadowing anything.
func normalizeScope(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "base", "baseobject", "exact", "":
		return "base" // slapd.access(5): base is the default, exact is an alias
	case "one", "onelevel":
		return "one"
	case "sub", "subtree":
		return "subtree"
	case "children":
		return "children"
	default:
		return strings.ToLower(strings.TrimSpace(s)) // regex, or something new
	}
}

// selectorParts splits a `to …` body into its additive parts. slapd.access(5):
// "The dn, filter, and attrs statements are additive; they can be used in
// sequence" — so a selector can carry all three, and a naive split on the first
// `=` swallows the ones that follow into the DN.
//
// Quoted DNs and parenthesised filters are kept whole, since both may contain
// the spaces and `=` this would otherwise split on.
func selectorParts(body string) []string {
	var parts []string
	for i := 0; i < len(body); {
		for i < len(body) && body[i] == ' ' {
			i++
		}
		if i >= len(body) {
			break
		}
		start := i
		for i < len(body) && body[i] != '=' && body[i] != ' ' {
			i++
		}
		if i < len(body) && body[i] == '=' {
			i = scanValue(body, i+1)
		}
		parts = append(parts, body[start:i]) // a bare token (`*`) lands here too
	}
	return parts
}

// scanValue returns the index just past the value starting at i: a quoted DN, a
// parenthesised filter, or a bare run up to the next space.
func scanValue(body string, i int) int {
	if i >= len(body) {
		return i
	}
	switch body[i] {
	case '"':
		for i++; i < len(body) && body[i] != '"'; i++ {
		}
		if i < len(body) {
			i++ // closing quote
		}
	case '(':
		depth := 0
		for ; i < len(body); i++ {
			if body[i] == '(' {
				depth++
			} else if body[i] == ')' {
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
	default:
		for ; i < len(body) && body[i] != ' '; i++ {
		}
	}
	return i
}

// parseSelector parses `to *`, `to attrs=x`, `to dn.subtree="X" filter=(…)`,
// `to dn.sub="X" attrs=mail`, …
func parseSelector(s string) selector {
	sel := selector{raw: strings.TrimSpace(s)}
	body := strings.TrimSpace(strings.TrimPrefix(sel.raw, "to "))
	if body == "*" {
		sel.kind = "*"
		return sel
	}
	for _, p := range selectorParts(body) {
		key, val, ok := strings.Cut(p, "=")
		if !ok {
			sel.kind = "other"
			return sel
		}
		switch k := strings.ToLower(key); {
		case k == "filter":
			sel.filter = strings.ToLower(val)
		case k == "attrs":
			sel.attrs = strings.ToLower(val)
			if sel.kind == "" {
				sel.kind = "attrs"
			}
		case k == "dn" || strings.HasPrefix(k, "dn."):
			sel.kind = "dn"
			// `dn=<DN>` with no style is legal — slapd.access(5) makes base the
			// default — so an empty scope must normalize to base, not be dropped.
			sel.scope = normalizeScope(strings.TrimPrefix(k, "dn."))
			if k == "dn" {
				sel.scope = "base"
			}
			sel.dn = strings.ToLower(strings.Trim(strings.TrimSpace(val), `"`))
		default:
			// val=, or anything slapd grows later: not something we can reason about
			sel.kind = "other"
			return sel
		}
	}
	if sel.kind == "" {
		sel.kind = "other"
	}
	return sel
}

// covers reports whether every access matched by b is already matched by a —
// i.e. a, being earlier, always decides first.
//
// It must only claim coverage it can prove: a false "yes" would call a live rule
// dead, or place a grant above a rule that was not in its way. Anything it
// cannot reason about (a filter, a regex, a `one` scope, an attribute list it
// cannot compare) is therefore a "no", at the cost of missing some real
// shadowing.
func covers(a, b selector) bool {
	// a matches only the entries its filter selects — a subset we cannot
	// enumerate, so it may leave some of b's entries for b to answer.
	if a.filter != "" {
		return false
	}
	// The same, one dimension over: a narrowed to some attributes cannot cover
	// an access to the others. Equal lists cancel out; the rest is not provable
	// without parsing the list (a covering superset reads as a miss, not a lie).
	if a.attrs != "" && a.attrs != b.attrs {
		return false
	}
	if a.kind == "*" {
		return true
	}
	if a.kind != "dn" || b.kind != "dn" {
		return false
	}
	under := b.dn == a.dn || strings.HasSuffix(b.dn, ","+a.dn)
	switch a.scope {
	case "subtree":
		return under
	case "base":
		return b.scope == "base" && b.dn == a.dn
	case "children":
		return strings.HasSuffix(b.dn, ","+a.dn)
	case "one":
		// a matches b's entries only if they all sit exactly one level under a;
		// provable when b is that single entry.
		return b.scope == "base" && strings.HasSuffix(b.dn, ","+a.dn) &&
			!strings.Contains(strings.TrimSuffix(b.dn, ","+a.dn), ",")
	default: // regex, or a style we do not know — not provable
		return false
	}
}

// byClauses returns the `by …` clauses of a rule body.
func byClauses(body string) []string {
	parts := strings.Split(body, " by ")
	if len(parts) < 2 {
		return nil
	}
	return parts[1:]
}

// hasBreak reports whether any clause ends in `break`, which lets evaluation
// continue to the rules below (so the rule does not shadow them).
func hasBreak(body string) bool {
	for _, c := range byClauses(body) {
		f := strings.Fields(c)
		if len(f) > 0 && f[len(f)-1] == "break" {
			return true
		}
	}
	return false
}

// isNoOp reports whether a rule does literally nothing: every clause is a
// catch-all that breaks (`by * break`), so it neither grants nor denies and
// evaluation just falls through. Typically what a revoke leaves behind.
// A catch-all with a real action (`by * read`, `by * none`) is a deliberate
// public grant / deny and is NOT reported.
func isNoOp(body string) bool {
	cs := byClauses(body)
	if len(cs) == 0 {
		return false
	}
	for _, c := range cs {
		if strings.Fields(strings.TrimSpace(c) + " x")[0] != "*" {
			return false
		}
		f := strings.Fields(c)
		if len(f) < 2 || f[len(f)-1] != "break" {
			return false
		}
	}
	return true
}

// ShadowIndex returns the index of the earliest existing rule that would shadow
// a new rule with o's selector — one that matches the same entries first and
// never breaks. That index is exactly where the new rule must be inserted to be
// reachable. Returns -1 when nothing shadows it (safe to append at the end).
func ShadowIndex(values []string, o InjectOpts) int {
	target := parseSelector(o.selector())
	type r struct {
		idx int
		sel selector
		brk bool
	}
	rules := make([]r, 0, len(values))
	for _, v := range values {
		idx, body := SplitIndexed(v)
		body = strings.TrimSpace(body)
		s := body
		if i := strings.Index(body, " by "); i >= 0 {
			s = body[:i]
		}
		rules = append(rules, r{idx, parseSelector(s), hasBreak(body)})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].idx < rules[j].idx })
	for _, x := range rules {
		if !x.brk && covers(x.sel, target) {
			return x.idx
		}
	}
	return -1
}

// Lint inspects an ordered olcAccess list and reports rules that can never fire.
//
// slapd stops at the FIRST rule whose `to` matches, so a rule is unreachable
// when an earlier rule matches the same entries and never says `break`. This is
// the classic cause of a grant that "exists" but has no effect (and of the
// noSuchObject the client sees when disclose is denied).
func Lint(values []string) []Finding {
	type rule struct {
		idx  int
		body string
		sel  selector
		brk  bool
	}
	rules := make([]rule, 0, len(values))
	for _, v := range values {
		idx, body := SplitIndexed(v)
		body = strings.TrimSpace(body)
		sel := body
		if i := strings.Index(body, " by "); i >= 0 {
			sel = body[:i]
		}
		rules = append(rules, rule{idx: idx, body: body, sel: parseSelector(sel), brk: hasBreak(body)})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].idx < rules[j].idx })

	var out []Finding
	for j := range rules {
		if isNoOp(rules[j].body) {
			out = append(out, Finding{
				Index: rules[j].idx, Level: LevelWarn, Rule: rules[j].body,
				Message: "does nothing: every clause is `by * break`, so it neither grants nor denies — leftover from a revoke?",
			})
		}
		for i := range j {
			if rules[i].brk || !covers(rules[i].sel, rules[j].sel) {
				continue
			}
			out = append(out, Finding{
				Index: rules[j].idx, Level: LevelDead, Rule: rules[j].body,
				Message: fmt.Sprintf("unreachable: rule {%d} (%s) matches the same entries first and never breaks — move this rule above it (`config acl move`) or add `by * break` to {%d}",
					rules[i].idx, rules[i].sel.raw, rules[i].idx),
			})
			break
		}
	}
	return out
}
