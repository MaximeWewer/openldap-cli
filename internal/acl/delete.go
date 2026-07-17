package acl

import "fmt"

// FindRule returns the stored value of the rule at index — the exact string,
// `{N}` prefix included, that a caller deletes.
//
// Callers must delete by VALUE, not by index: olcAccess is ordered, so removing
// a rule renumbers every rule below it. Reading the value back and handing that
// same string to the server is what keeps a delete pointed at the rule the
// operator actually looked at.
func FindRule(values []string, index int) (string, error) {
	rules := splitRules(values)
	if len(rules) == 0 {
		return "", fmt.Errorf("no olcAccess rules on this database")
	}
	for _, r := range rules {
		if r.idx == index {
			return fmt.Sprintf("{%d}%s", r.idx, r.body), nil
		}
	}
	return "", fmt.Errorf("no rule {%d}: the database has {%d}..{%d}",
		index, rules[0].idx, rules[len(rules)-1].idx)
}

// InspectDelete reports what deleting the rule at index would change, and
// returns that rule's exact stored value.
//
// Deleting a rule that never fired changes nothing — that is the safe case, and
// the reason this command exists (a revoke keeps a deliberate `by * none`, so a
// dead rule can otherwise only be removed by rewriting the whole attribute).
// Deleting a LIVE rule hands its entries to whatever rule sits below, which
// silently changes who has access; that is what the impact names.
func InspectDelete(values []string, index int) (value string, impact Impact, err error) {
	value, err = FindRule(values, index)
	if err != nil {
		return "", Impact{}, err
	}
	var after []string
	for _, r := range splitRules(values) {
		if r.idx == index {
			continue
		}
		after = append(after, r.body)
	}
	_, body := SplitIndexed(value)
	return value, inspect(values, indexed(after), body), nil
}
