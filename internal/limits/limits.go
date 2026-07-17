// Package limits performs pure transformations on OpenLDAP olcLimits values.
//
// olcLimits is an ordered multi-valued attribute — each value carries an index
// like "{2}" — and slapd "examines each clause in turn until it finds one that
// matches the operation's initiator or base DN. If no match is found, the global
// limits will be used" (Admin Guide, "Limits"). So it is olcAccess's trap in a
// second attribute: the FIRST matching clause decides and evaluation stops, and
// a broader clause placed above a narrower one silently swallows it. slapd
// reports nothing — the limit is simply never reached.
//
// The one difference from olcAccess is the fallback: an identity that matches no
// clause gets the database's global olcSizeLimit/olcTimeLimit rather than a
// denial. That makes a shadowed limit quieter still, since the identity keeps
// working, just at the wrong ceiling.
//
// These functions compute the new value list; the caller performs the LDAP
// read/modify.
package limits

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Limit is one parsed olcLimits value.
type Limit struct {
	Index int      // its {N} position, -1 when unindexed
	Who   Who      // the selector it applies to
	Specs []string // size=…, time=…, size.pr=…
	Body  string   // the value without its {N} prefix
}

// Who is a parsed <who> selector. slapd's grammar, verbatim:
//
//	"*" | anonymous | users | self
//	dn[.<type>][.<style>]=<pattern>
//	group[/<oc>[/<at>]]=<pattern>
//
// where <type> is self or this, and <style> is one of exact, base, onelevel,
// subtree, children, regex or anonymous.
type Who struct {
	Raw   string
	Kind  string // "*" | "anonymous" | "users" | "self" | "dn" | "group" | "other"
	Type  string // dn: "self" | "this" | ""
	Scope string // dn: base | one | subtree | children | regex | …
	DN    string // dn: lower-cased pattern
	Group string // group: lower-cased pattern
	OC    string // group: objectClass
	AT    string // group: attribute holding the members
}

// splitIndexed splits "{2}dn.exact=… size=5" into (2, "dn.exact=… size=5").
// The {N} prefix is cn=config's X-ORDERED convention, not an olcAccess one.
func splitIndexed(v string) (int, string) {
	if strings.HasPrefix(v, "{") {
		if i := strings.IndexByte(v, '}'); i > 0 {
			if n, err := strconv.Atoi(v[1:i]); err == nil {
				return n, v[i+1:]
			}
		}
	}
	return -1, v
}

// normalizeScope maps the dnstyle synonyms onto one spelling. Missing one is not
// cosmetic: an unknown scope makes Covers give up, so an ordinary clause would
// stop being seen as shadowing anything.
func normalizeScope(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "exact", "base", "":
		return "base"
	case "one", "onelevel":
		return "one"
	case "sub", "subtree":
		return "subtree"
	case "children":
		return "children"
	default:
		return strings.ToLower(strings.TrimSpace(s)) // regex, anonymous, or something new
	}
}

// scanToken returns the index just past the token starting at i. A quoted
// pattern is kept whole: a DN carries the spaces this would otherwise split on.
func scanToken(s string, i int) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
			}
		case ' ':
			return i
		}
	}
	return i
}

// fields splits a limits value into its whitespace-separated tokens, keeping
// quoted patterns whole.
func fields(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && s[i] == ' ' {
			i++
		}
		if i >= len(s) {
			break
		}
		end := scanToken(s, i)
		out = append(out, s[i:end])
		i = end
	}
	return out
}

// ParseWho parses one <who> token.
func ParseWho(tok string) Who {
	w := Who{Raw: strings.TrimSpace(tok)}
	lower := strings.ToLower(w.Raw)
	switch lower {
	case "*":
		w.Kind = "*"
		return w
	case "anonymous", "users", "self":
		w.Kind = lower
		return w
	}

	key, val, ok := strings.Cut(w.Raw, "=")
	if !ok {
		w.Kind = "other"
		return w
	}
	val = strings.Trim(strings.TrimSpace(val), `"`)
	k := strings.ToLower(strings.TrimSpace(key))

	switch {
	case k == "dn" || strings.HasPrefix(k, "dn."):
		w.Kind = "dn"
		w.DN = strings.ToLower(val)
		// dn[.<type>][.<style>]: type is self/this, anything else is the style.
		// A bare `dn=` has no style, and base is the default.
		w.Scope = "base"
		for _, part := range strings.Split(strings.TrimPrefix(k, "dn"), ".") {
			switch part {
			case "":
			case "self", "this":
				w.Type = part
			default:
				w.Scope = normalizeScope(part)
			}
		}
	case k == "group" || strings.HasPrefix(k, "group/"):
		w.Kind = "group"
		w.Group = strings.ToLower(val)
		if seg := strings.Split(k, "/"); len(seg) > 1 {
			w.OC = seg[1]
			if len(seg) > 2 {
				w.AT = seg[2]
			}
		}
	default:
		w.Kind = "other"
	}
	return w
}

// Parse parses one olcLimits value.
func Parse(value string) Limit {
	idx, body := splitIndexed(value)
	body = strings.TrimSpace(body)
	l := Limit{Index: idx, Body: body}
	toks := fields(body)
	if len(toks) == 0 {
		l.Who = Who{Kind: "other"}
		return l
	}
	l.Who = ParseWho(toks[0])
	l.Specs = toks[1:]
	return l
}

// ParseAll parses the values and orders them the way slapd evaluates them.
// The server's response order is not guaranteed to match the {N} order.
func ParseAll(values []string) []Limit {
	ls := make([]Limit, 0, len(values))
	for _, v := range values {
		ls = append(ls, Parse(v))
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Index < ls[j].Index })
	return ls
}

// SameWho reports whether two selectors name the same identity set, comparing
// the PARSED form: slapd reads `dn.exact=` and `dn.base=` (and a bare `dn=`) as
// the same thing, so matching on spelling would miss the existing clause and add
// a second one that slapd never reaches.
//
// Selectors we cannot parse ("other") never match, so an unknown form gets its
// own clause rather than being merged into something we misread.
func SameWho(a, b Who) bool {
	if a.Kind == "other" || b.Kind == "other" {
		return false
	}
	return a.Kind == b.Kind && a.Type == b.Type && a.Scope == b.Scope &&
		a.DN == b.DN && a.Group == b.Group && a.OC == b.OC && a.AT == b.AT
}

// Covers reports whether every identity matched by b is already matched by a —
// i.e. a, being earlier, always decides first and b is unreachable.
//
// It must only claim coverage it can prove: a false "yes" calls a live clause
// dead. Anything it cannot reason about — a group's membership, a regex, `self`
// — is a "no", at the cost of missing some real shadowing.
func Covers(a, b Who) bool {
	if a.Kind == "other" || b.Kind == "other" {
		return false
	}
	if a.Kind == "*" {
		return true // matches everyone, authenticated or not
	}
	// `users` is every authenticated identity. A group's members and `self` are
	// always authenticated; a DN pattern is too, unless it is the empty DN (the
	// anonymous bind) or the `anonymous` dnstyle.
	if a.Kind == "users" {
		switch b.Kind {
		case "group", "self", "users":
			return true
		case "dn":
			return b.DN != "" && b.Scope != "anonymous"
		}
		return false
	}
	if a.Kind == "anonymous" {
		return b.Kind == "anonymous"
	}
	if a.Kind != "dn" || b.Kind != "dn" || a.Type != b.Type {
		// group-vs-dn needs the directory to answer; self is per-operation
		return SameWho(a, b)
	}
	under := b.DN == a.DN || strings.HasSuffix(b.DN, ","+a.DN)
	switch a.Scope {
	case "subtree":
		return under
	case "base":
		return b.Scope == "base" && b.DN == a.DN
	case "children":
		return strings.HasSuffix(b.DN, ","+a.DN)
	case "one":
		// a matches b's entries only if they sit exactly one level under a;
		// provable when b is that single entry.
		return b.Scope == "base" && strings.HasSuffix(b.DN, ","+a.DN) &&
			!strings.Contains(strings.TrimSuffix(b.DN, ","+a.DN), ",")
	default: // regex, anonymous-style, or something we do not know
		return false
	}
}

// specKey returns the setting a spec token assigns: "size=500" -> "size".
func specKey(spec string) string {
	k, _, _ := strings.Cut(spec, "=")
	return strings.ToLower(k)
}

// mergeSpecs overlays set onto specs: a key already present is overwritten in
// place, a new one is appended.
//
// Overlaying rather than replacing is the point: `--size` on a clause that also
// carries `time=` must not silently drop the time limit. That is the same
// whole-attribute-replace trap one level down.
func mergeSpecs(specs []string, set []string) []string {
	out := append([]string(nil), specs...)
	for _, s := range set {
		k := specKey(s)
		replaced := false
		for i := range out {
			if specKey(out[i]) == k {
				out[i], replaced = s, true
				break
			}
		}
		if !replaced {
			out = append(out, s)
		}
	}
	return out
}

// Result describes what Upsert did, so the caller can report it truthfully.
type Result struct {
	Action string // "added" | "updated" | "unchanged"
	// At is the position the clause ended up at (0-based).
	At int
	// Before is the clause as it was, when Action is "updated".
	Before string
	// After is the clause as written.
	After string
	// ShadowedBy names the earlier clause that would have swallowed this one, if
	// any: the clause was placed above it instead of appended.
	ShadowedBy string
}

// Upsert returns the complete ordered olcLimits bodies (no {N} prefixes) after
// applying set to who's clause — suitable for a single replace, which the server
// renumbers {0},{1},… in this order.
//
// An existing clause for the same identity is UPDATED in place rather than
// appended to: a second clause for the same identity is one slapd never reaches,
// because the first already decided.
//
// A new clause is placed above any earlier clause that would shadow it, rather
// than at the end where it would be dead on arrival.
func Upsert(values []string, who Who, set []string) ([]string, Result, error) {
	if who.Kind == "other" {
		return nil, Result{}, fmt.Errorf("unrecognized selector %q: expected *, anonymous, users, self, dn[.<style>]=<pattern> or group[/<oc>[/<at>]]=<pattern>", who.Raw)
	}
	if len(set) == 0 {
		return nil, Result{}, fmt.Errorf("no limit to set")
	}
	ls := ParseAll(values)

	for i, l := range ls {
		if !SameWho(l.Who, who) {
			continue
		}
		merged := mergeSpecs(l.Specs, set)
		body := strings.Join(append([]string{l.Who.Raw}, merged...), " ")
		res := Result{Action: "updated", At: i, Before: l.Body, After: body}
		if body == l.Body {
			res.Action = "unchanged"
		}
		bodies := make([]string, len(ls))
		for j, x := range ls {
			bodies[j] = x.Body
		}
		bodies[i] = body
		return bodies, res, nil
	}

	body := strings.Join(append([]string{who.Raw}, set...), " ")
	res := Result{Action: "added", At: len(ls), After: body}
	for i, l := range ls {
		if Covers(l.Who, who) {
			res.At, res.ShadowedBy = i, l.Body
			break
		}
	}
	bodies := make([]string, 0, len(ls)+1)
	for _, l := range ls {
		bodies = append(bodies, l.Body)
	}
	bodies = append(bodies, "")
	copy(bodies[res.At+1:], bodies[res.At:])
	bodies[res.At] = body
	return bodies, res, nil
}

// Remove returns the complete ordered bodies with every clause for who dropped,
// plus the clauses removed. Every clause, not the first: a duplicate for the
// same identity is exactly the wreckage this cleans up.
func Remove(values []string, who Who) ([]string, []Limit, error) {
	if who.Kind == "other" {
		return nil, nil, fmt.Errorf("unrecognized selector %q", who.Raw)
	}
	var bodies []string
	var removed []Limit
	for _, l := range ParseAll(values) {
		if SameWho(l.Who, who) {
			removed = append(removed, l)
			continue
		}
		bodies = append(bodies, l.Body)
	}
	if len(removed) == 0 {
		return nil, nil, fmt.Errorf("no olcLimits clause for %s", who.Raw)
	}
	return bodies, removed, nil
}

// Finding is one lint result.
type Finding struct {
	Index   int
	Limit   string
	Message string
}

// Lint reports the clauses slapd can never reach: an earlier clause matching the
// same identities always decides first. This is the state `set` used to create
// on every re-run, and the reason a limit can be "there" and have no effect.
func Lint(values []string) []Finding {
	ls := ParseAll(values)
	var out []Finding
	for j := range ls {
		for i := range j {
			if !Covers(ls[i].Who, ls[j].Who) {
				continue
			}
			msg := fmt.Sprintf("unreachable: clause {%d} (%s) matches the same identities first, and slapd stops at the first match",
				ls[i].Index, ls[i].Who.Raw)
			if SameWho(ls[i].Who, ls[j].Who) {
				msg = fmt.Sprintf("unreachable: clause {%d} already sets limits for %s — this duplicate is never reached",
					ls[i].Index, ls[i].Who.Raw)
			}
			out = append(out, Finding{Index: ls[j].Index, Limit: ls[j].Body, Message: msg})
			break
		}
	}
	return out
}
