// Package acl performs pure transformations on OpenLDAP olcAccess values.
//
// olcAccess is an ordered multi-valued attribute; each value is prefixed with
// an index like "{2}". Editing a value means deleting the old indexed string
// and adding the new one (same index). These functions compute those edits;
// the caller performs the LDAP read/modify.
package acl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Edit is one olcAccess change: delete Delete (empty = none) and add Add.
type Edit struct {
	Delete string
	Add    string
}

// SplitIndexed splits "{2}to ..." into (2, "to ..."). Returns (-1, v) if none.
func SplitIndexed(v string) (int, string) {
	if strings.HasPrefix(v, "{") {
		if i := strings.IndexByte(v, '}'); i > 0 {
			if n, err := strconv.Atoi(v[1:i]); err == nil {
				return n, v[i+1:]
			}
		}
	}
	return -1, v
}

// Reorder takes the indexed olcAccess values, sorts them by current index, moves
// the rule at position `from` to position `to`, and returns the rule bodies in
// the new order WITHOUT index prefixes — suitable for a single olcAccess replace
// (the server renumbers them {0},{1},… in this order). Positions are zero-based.
func Reorder(values []string, from, to int) ([]string, error) {
	type rule struct {
		idx  int
		body string
	}
	rules := make([]rule, len(values))
	for i, v := range values {
		idx, body := SplitIndexed(v)
		rules[i] = rule{idx, strings.TrimSpace(body)}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].idx < rules[j].idx })

	n := len(rules)
	if n == 0 {
		return nil, fmt.Errorf("no olcAccess rules to reorder")
	}
	if from < 0 || from >= n || to < 0 || to >= n {
		return nil, fmt.Errorf("index out of range: from=%d to=%d (have %d rules, {0}..{%d})", from, to, n, n-1)
	}

	bodies := make([]string, n)
	for i, r := range rules {
		bodies[i] = r.body
	}
	if from == to {
		return bodies, nil
	}
	moved := bodies[from]
	bodies = append(bodies[:from], bodies[from+1:]...) // remove
	bodies = append(bodies[:to], append([]string{moved}, bodies[to:]...)...)
	return bodies, nil
}

// DNWho builds the olcAccess "who" token for a single entry (dn.exact).
func DNWho(dn string) string { return fmt.Sprintf(`dn.exact="%s"`, dn) }

// GroupWho builds the olcAccess "who" token for a group's members (group.exact).
// Every member of the group then shares the granted access — the scalable way
// to give several service accounts the same rights on a tree.
func GroupWho(groupDN string) string { return fmt.Sprintf(`group.exact="%s"`, groupDN) }

// InjectOpts describes one olcAccess grant to inject.
type InjectOpts struct {
	Target string // the DN the rule protects
	Scope  string // "subtree" (default) or "base" (the container entry only)
	Filter string // optional LDAP filter — only entries matching it are covered
	Who    string // who-token: DNWho(dn) / GroupWho(dn)
	Access string // read, write, search, …

	// Terminator is the trailing `by *` action of a NEW rule: "break" (default,
	// additive — other identities fall through to the rules below) or "none".
	Terminator string
	// At is the index a NEW rule is inserted at; negative appends at the end.
	// Placing it above a broader rule is what stops it being shadowed.
	At int
}

// selector builds the rule's `to …` part.
func (o InjectOpts) selector() string {
	scope := o.Scope
	if scope == "" {
		scope = "subtree"
	}
	s := fmt.Sprintf("to dn.%s=%q", scope, o.Target)
	if o.Filter != "" {
		s += " filter=" + o.Filter
	}
	return s
}

// Inject adds `by <who> <access>` to the rule whose selector matches exactly
// (before its trailing `by *` clause), or returns a new rule when none matches.
// Adding a `by` clause to the SAME rule — rather than a second rule with the
// same `to`, which would be dead — is what lets multiple grantees coexist.
func Inject(values []string, o InjectOpts) (edit Edit, appended bool) {
	sel := o.selector()
	clause := fmt.Sprintf("by %s %s", o.Who, o.Access)

	for _, v := range values {
		idx, body := SplitIndexed(v)
		body = strings.TrimSpace(body)
		rest, ok := strings.CutPrefix(body, sel)
		// the selector must match exactly: what follows is the first `by`, not
		// a further qualifier (e.g. a filter= we did not ask for).
		if !ok || !strings.HasPrefix(strings.TrimSpace(rest), "by ") {
			continue
		}
		var nb string
		switch {
		case strings.Contains(body, "by * none"):
			nb = strings.Replace(body, "by * none", clause+" by * none", 1)
		case strings.Contains(body, "by * break"):
			nb = strings.Replace(body, "by * break", clause+" by * break", 1)
		default:
			nb = strings.TrimRight(body, " ") + " " + clause
		}
		return Edit{Delete: v, Add: fmt.Sprintf("{%d}%s", idx, nb)}, false
	}

	term := o.Terminator
	if term == "" {
		term = "break"
	}
	rule := fmt.Sprintf("%s %s by * %s", sel, clause, term)
	if o.At >= 0 {
		rule = fmt.Sprintf("{%d}%s", o.At, rule)
	}
	return Edit{Add: rule}, true
}

// RemoveGrantee strips every `by <who> <access>` clause referencing who,
// returning the edits to apply and how many clauses were removed. `who` is a
// full who-token (DNWho/GroupWho).
func RemoveGrantee(values []string, who string) (edits []Edit, removed int) {
	needle := who
	for _, v := range values {
		if !strings.Contains(v, needle) {
			continue
		}
		idx, body := SplitIndexed(v)
		parts := strings.Split(body, " by ") // parts[0]="to <target>", rest="<who> <access>"
		kept := []string{parts[0]}
		for _, p := range parts[1:] {
			if strings.Contains(p, needle) {
				removed++
				continue
			}
			kept = append(kept, p)
		}
		edits = append(edits, Edit{Delete: v, Add: fmt.Sprintf("{%d}%s", idx, strings.Join(kept, " by "))})
	}
	return edits, removed
}
