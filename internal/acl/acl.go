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

// Inject adds `by dn.exact="svc" <access>` to the rule targeting subtree (before
// `by * none`), or returns a new appended rule when none targets it.
func Inject(values []string, subtree, svc, access string) (edit Edit, appended bool) {
	targetPrefix := fmt.Sprintf(`to dn.subtree="%s"`, subtree)
	clause := fmt.Sprintf(`by dn.exact="%s" %s`, svc, access)

	for _, v := range values {
		idx, body := SplitIndexed(v)
		if !strings.HasPrefix(strings.TrimSpace(body), targetPrefix) {
			continue
		}
		var nb string
		if strings.Contains(body, "by * none") {
			nb = strings.Replace(body, "by * none", clause+" by * none", 1)
		} else {
			nb = strings.TrimRight(body, " ") + " " + clause
		}
		return Edit{Delete: v, Add: fmt.Sprintf("{%d}%s", idx, nb)}, false
	}
	return Edit{Add: fmt.Sprintf("%s %s by * none", targetPrefix, clause)}, true
}

// RemoveGrantee strips every `by dn.exact="svc" <access>` clause referencing svc,
// returning the edits to apply and how many clauses were removed.
func RemoveGrantee(values []string, svc string) (edits []Edit, removed int) {
	needle := fmt.Sprintf(`dn.exact="%s"`, svc)
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
