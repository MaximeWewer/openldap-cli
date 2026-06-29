package ldapx

import (
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

// AttributeTypeNames returns the set of attributeType names the server knows,
// read from the subschema subentry (works with the normal data bind).
func (c *Client) AttributeTypeNames() (map[string]bool, error) {
	root, err := c.ReadEntry("", []string{"subschemaSubentry"})
	if err != nil {
		return nil, err
	}
	sub := root.Get("subschemaSubentry")
	if sub == "" {
		sub = "cn=Subschema"
	}
	e, err := c.ReadEntry(sub, []string{"attributeTypes"})
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, def := range e.GetAll("attributeTypes") {
		for _, n := range schema.Names(def) {
			set[strings.ToLower(n)] = true
		}
	}
	return set, nil
}
