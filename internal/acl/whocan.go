package acl

import (
	"fmt"
	"strings"
)

// Answering "who can write this entry?" means evaluating olcAccess the way slapd
// does, and slapd.access(5) pins the three rules that matter:
//
//   - "each <who> clause list is implicitly terminated by a `by * none stop`" —
//     so once a rule's `to` matches, identities it does not name are DENIED and
//     evaluation STOPS. It does not fall through to a later rule.
//   - "each access level implies all the preceding ones": none < disclose < auth
//     < compare < search < read < write < manage.
//   - "the rootdn can always read and write EVERYTHING" — access control is
//     bypassed for it entirely, so it never appears in any rule.
//
// The exception to the first rule is `break`: a clause ending in `break` hands
// the question to the rules below instead of settling it. This CLI's own grants
// end in `by * break` precisely so they stay additive, so following it is not an
// edge case here — it is the common path.
//
// What this cannot do is decide a rule that needs the entry's attributes
// (`filter=`), a regex, or a `set=` expression. Those are reported as
// undecidable rather than guessed: a wrong answer here reads as "nobody can
// write this", which is the kind of lie that ends up in a security review.

// Match is how a rule's `to` selector relates to a concrete entry.
type Match int

const (
	MatchNo      Match = iota // the rule provably does not cover the entry
	MatchYes                  // the rule provably covers it
	MatchUnknown              // deciding needs data or a regex engine we do not run
)

// Grant is one parsed `by <who> <access> [<control>]` clause.
type Grant struct {
	Who     string `json:"who" yaml:"who"`
	Access  string `json:"access" yaml:"access"`
	Control string `json:"control,omitempty" yaml:"control,omitempty"` // stop (default) | break | continue
}

// byFields splits a `by` clause into tokens, keeping a quoted DN whole: a group
// or user DN may carry the spaces this would otherwise split on.
func byFields(c string) []string {
	var out []string
	for i := 0; i < len(c); {
		for i < len(c) && (c[i] == ' ' || c[i] == '\t') {
			i++
		}
		if i >= len(c) {
			break
		}
		start := i
		for i < len(c) && c[i] != ' ' && c[i] != '\t' {
			if c[i] == '"' {
				for i++; i < len(c) && c[i] != '"'; i++ {
				}
			}
			i++
		}
		out = append(out, c[start:i])
	}
	return out
}

// isControl reports whether tok is a control keyword.
func isControl(tok string) bool {
	switch strings.ToLower(tok) {
	case "stop", "break", "continue":
		return true
	}
	return false
}

// parseBy parses one `by` clause body (without the leading "by ").
//
// The grammar is `by <who> [<access>] [<control>]` — the ACCESS is optional, so
// in `by * break` the second token is the control, not a level. Reading it as an
// access is how a rule that hands the question on looks like one that grants
// something called "break".
func parseBy(c string) Grant {
	f := byFields(c)
	g := Grant{}
	if len(f) > 0 {
		g.Who = f[0]
	}
	if len(f) > 1 {
		if isControl(f[1]) {
			g.Control = strings.ToLower(f[1])
			return g
		}
		g.Access = f[1]
	}
	if len(f) > 2 && isControl(f[2]) {
		g.Control = strings.ToLower(f[2])
	}
	return g
}

// Grants returns the parsed `by` clauses of a rule body, in order.
func Grants(body string) []Grant {
	var out []Grant
	for _, c := range byClauses(body) {
		out = append(out, parseBy(strings.TrimSpace(c)))
	}
	return out
}

// levelRank orders slapd's access levels. Each implies the preceding ones.
var levelRank = map[string]int{
	"none": 0, "disclose": 1, "auth": 2, "compare": 3,
	"search": 4, "read": 5, "add": 6, "delete": 6, "write": 7, "manage": 8,
}

// writeRank is the level from which an identity can modify the entry.
const writeRank = 7

// GrantsWrite reports whether an <access> token confers write, and whether that
// could be decided at all.
//
// Two spellings exist: a level (`write`), and a privilege set (`=wrscd`, `+w`,
// `-w`) where `w` is write and `m` manage. A `-` set removes privileges, so it
// grants nothing.
func GrantsWrite(access string) (grants, decidable bool) {
	a := strings.ToLower(strings.TrimSpace(access))
	// `by self write`-style modifiers sit on the who, not here, but `realself`
	// and friends can prefix the level in some spellings — strip a known one.
	a = strings.TrimPrefix(a, "self")

	if a == "" {
		return false, false
	}
	if r, ok := levelRank[a]; ok {
		return r >= writeRank, true
	}
	if a[0] == '=' || a[0] == '+' || a[0] == '-' {
		if a[0] == '-' {
			return false, true // removes privileges
		}
		return strings.ContainsAny(a[1:], "wm"), true
	}
	return false, false
}

// MatchDN reports whether the rule body's `to` selector selects the entry at dn,
// on the DN dimension alone — the attribute dimension is a separate question the
// caller asks with attr, so it is deliberately not consulted here.
//
// Anything it cannot decide — a filter, whose answer is in the entry's own
// attributes; a regex — comes back MatchUnknown rather than MatchNo. For this
// question a silent "no" is not a missed optimization, it is a wrong verdict.
func MatchDN(body, dn string) Match {
	sel := ruleSelector(body)
	switch {
	case sel.filter != "", sel.kind == "other":
		return MatchUnknown
	case sel.kind == "*", sel.kind == "attrs":
		return MatchYes // no DN restriction: every entry
	case sel.kind != "dn":
		return MatchUnknown
	}

	d := strings.ToLower(strings.TrimSpace(dn))
	a := sel.dn
	yes := func(b bool) Match {
		if b {
			return MatchYes
		}
		return MatchNo
	}
	switch sel.scope {
	case "base":
		return yes(d == a)
	case "subtree":
		return yes(d == a || strings.HasSuffix(d, ","+a))
	case "children":
		return yes(strings.HasSuffix(d, ","+a))
	case "one":
		return yes(strings.HasSuffix(d, ","+a) &&
			!strings.Contains(strings.TrimSuffix(d, ","+a), ","))
	default: // regex, or a style we do not know
		return MatchUnknown
	}
}

// Decision is who can act on one entry, per the rules of one database.
type Decision struct {
	// Rules are the rules consulted, in evaluation order, each with the grants
	// it contributes.
	Rules []DecidingRule `json:"rules,omitempty" yaml:"rules,omitempty"`
	// Undecidable names the rule that stopped the evaluation, and why. When set,
	// Rules holds only what was established before it.
	Undecidable string `json:"undecidable,omitempty" yaml:"undecidable,omitempty"`
	// AttrOnly are rules that cover the entry but only for named attributes, so
	// they decide a different question than the one asked.
	AttrOnly []string `json:"attrOnly,omitempty" yaml:"attrOnly,omitempty"`
	// Settled reports whether a rule took the decision (i.e. the implicit
	// `by * none stop` applies). False means no rule matched: access falls
	// through to the database's default, which is deny.
	Settled bool `json:"settled" yaml:"settled"`
}

// DecidingRule is one rule that had a say.
type DecidingRule struct {
	Index  int     `json:"index" yaml:"index"`
	Rule   string  `json:"rule" yaml:"rule"`
	Grants []Grant `json:"grants" yaml:"grants"`
	// FellThrough reports that the rule ended in a catch-all `break`, so the
	// rules below still got a say.
	FellThrough bool `json:"fellThrough" yaml:"fellThrough"`
}

// catchAllBreaks reports whether the rule ends with a catch-all clause that
// hands the question on (`by * break`). Without one, the implicit
// `by * none stop` terminates evaluation at this rule.
func catchAllBreaks(body string) bool {
	for _, g := range Grants(body) {
		if g.Who == "*" && g.Control == "break" {
			return true
		}
	}
	return false
}

// WhoCan evaluates the ordered olcAccess values against a concrete entry DN and
// returns the rules that get a say, in order.
//
// attr narrows the question to one attribute; "" asks about the entry's
// attributes in general, in which case rules restricted to named attributes are
// set aside (they decide only their own attributes) rather than treated as
// deciding.
func WhoCan(values []string, dn, attr string) Decision {
	var d Decision
	attr = strings.ToLower(strings.TrimSpace(attr))

	for _, r := range splitRules(values) {
		sel := ruleSelector(r.body)

		// A rule narrowed to attributes only answers for those attributes.
		if sel.attrs != "" {
			if attr == "" {
				if MatchDN(r.body, dn) != MatchNo {
					d.AttrOnly = append(d.AttrOnly, fmt.Sprintf("{%d}%s", r.idx, r.body))
				}
				continue
			}
			if !attrListHas(sel.attrs, attr) {
				continue // asks about an attribute this rule does not cover
			}
		}

		switch MatchDN(r.body, dn) {
		case MatchNo:
			continue
		case MatchUnknown:
			d.Undecidable = fmt.Sprintf("{%d}%s", r.idx, r.body)
			return d
		case MatchYes: // the rule gets a say — fall through to collect it
		}

		fell := catchAllBreaks(r.body)
		d.Rules = append(d.Rules, DecidingRule{
			Index: r.idx, Rule: r.body, Grants: Grants(r.body), FellThrough: fell,
		})
		if !fell {
			// implicit `by * none stop`: this rule settles it
			d.Settled = true
			return d
		}
	}
	return d
}

// attrListHas reports whether an `attrs=` list names attr. Anything exotic — a
// negation, an objectClass shorthand — reads as a match, so the rule is shown
// rather than silently dropped from an answer that claims completeness.
func attrListHas(list, attr string) bool {
	for _, a := range strings.Split(list, ",") {
		a = strings.TrimSpace(a)
		if a == attr || a == "*" || strings.HasPrefix(a, "@") || strings.HasPrefix(a, "!") {
			return true
		}
	}
	return false
}

// WriteGrants returns the clauses of d that confer write, and the ones whose
// access token could not be read.
func (d Decision) WriteGrants() (write []Grant, unreadable []Grant) {
	for _, r := range d.Rules {
		for _, g := range r.Grants {
			grants, ok := GrantsWrite(g.Access)
			switch {
			case !ok:
				unreadable = append(unreadable, g)
			case grants:
				write = append(write, g)
			}
		}
	}
	return write, unreadable
}
