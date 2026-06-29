package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// ---- shared renderers ---------------------------------------------------

// entryResult renders one LDAP entry (DN + attributes) in text/json/yaml.
type entryResult struct {
	DN    string              `json:"dn" yaml:"dn"`
	Attrs map[string][]string `json:"attrs" yaml:"attrs"`
}

func newEntryResult(e *ldapx.Entry) entryResult {
	m := map[string][]string{}
	for _, name := range e.Names() {
		m[name] = e.GetAll(name)
	}
	return entryResult{DN: e.DN, Attrs: m}
}

func (r entryResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.DN)
	keys := make([]string, 0, len(r.Attrs))
	for k := range r.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Attrs[k] {
			fmt.Fprintf(&b, "  %s: %s\n", k, v)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

type entryList struct {
	Entries []entryResult `json:"entries" yaml:"entries"`
}

func (r entryList) Text() string {
	if len(r.Entries) == 0 {
		return "no entries"
	}
	parts := make([]string, len(r.Entries))
	for i, e := range r.Entries {
		parts[i] = e.Text()
	}
	return strings.Join(parts, "\n\n") + fmt.Sprintf("\n\n(%d entries)", len(r.Entries))
}

// itemList renders a flat name+DN listing.
type item struct {
	Name string `json:"name" yaml:"name"`
	DN   string `json:"dn" yaml:"dn"`
}

type itemList struct {
	Kind  string `json:"kind" yaml:"kind"`
	Items []item `json:"items" yaml:"items"`
}

func (r itemList) Text() string {
	if len(r.Items) == 0 {
		return "no " + r.Kind
	}
	var b strings.Builder
	for _, it := range r.Items {
		fmt.Fprintf(&b, "%s\n", it.Name)
	}
	fmt.Fprintf(&b, "(%d %s)", len(r.Items), r.Kind)
	return b.String()
}

// namesToItems builds an itemList from entries, using the given attr as name.
func entriesToItems(kind, nameAttr string, entries []*ldapx.Entry) itemList {
	l := itemList{Kind: kind}
	for _, e := range entries {
		l.Items = append(l.Items, item{Name: e.Get(nameAttr), DN: e.DN})
	}
	return l
}
