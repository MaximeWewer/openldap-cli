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
	raw    string
	kind   string // "*" | "attrs" | "dn" | "other"
	scope  string // base | one | children | subtree | regex (dn kind only)
	dn     string // lower-cased target DN (dn kind only)
	filter bool   // the selector is narrowed by filter=(…)
}

// parseSelector parses `to *`, `to attrs=x`, `to dn.subtree="X" filter=(…)`, …
func parseSelector(s string) selector {
	sel := selector{raw: strings.TrimSpace(s)}
	body := strings.TrimSpace(strings.TrimPrefix(sel.raw, "to "))
	if i := strings.Index(body, " filter="); i >= 0 {
		sel.filter = true
		body = strings.TrimSpace(body[:i])
	}
	switch {
	case body == "*":
		sel.kind = "*"
	case strings.HasPrefix(body, "attrs="):
		sel.kind = "attrs"
	case strings.HasPrefix(body, "dn."):
		sel.kind = "dn"
		rest := strings.TrimPrefix(body, "dn.")
		scope, dn, ok := strings.Cut(rest, "=")
		if !ok {
			sel.kind = "other"
			return sel
		}
		sel.scope = strings.ToLower(strings.TrimSpace(scope))
		if sel.scope == "exact" { // exact and base are synonyms
			sel.scope = "base"
		}
		sel.dn = strings.ToLower(strings.Trim(strings.TrimSpace(dn), `"`))
	default:
		sel.kind = "other"
	}
	return sel
}

// covers reports whether every entry matched by b is already matched by a — i.e.
// a, being earlier, always decides first. A filtered a matches only a subset, so
// it is never treated as covering (we cannot prove it statically).
func covers(a, b selector) bool {
	if a.filter {
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
	default: // one, regex, … — not provable
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
