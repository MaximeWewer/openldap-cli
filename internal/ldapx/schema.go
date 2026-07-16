package ldapx

import (
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

// subschemaNames returns the set of NAMEs declared by attr on the subschema
// subentry — the schema as the server advertises it to a normal data bind, so
// no config bind is needed.
func (c *Client) subschemaNames(attr string) (map[string]bool, error) {
	root, err := c.ReadEntry("", []string{"subschemaSubentry"})
	if err != nil {
		return nil, err
	}
	sub := root.Get("subschemaSubentry")
	if sub == "" {
		sub = "cn=Subschema"
	}
	e, err := c.ReadEntry(sub, []string{attr})
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, def := range e.GetAll(attr) {
		for _, n := range schema.Names(def) {
			set[strings.ToLower(n)] = true
		}
	}
	return set, nil
}

// AttributeTypeNames returns the set of attributeType names the server knows.
func (c *Client) AttributeTypeNames() (map[string]bool, error) {
	return c.subschemaNames("attributeTypes")
}

// ObjectClassNames returns the set of objectClass names the server knows.
// Sending an objectClass it does not know fails with the opaque
// `objectClass: value #N invalid per syntax`, so callers check first and say
// which schema is missing.
func (c *Client) ObjectClassNames() (map[string]bool, error) {
	return c.subschemaNames("objectClasses")
}

// HasObjectClass reports whether the server's schema declares name.
func (c *Client) HasObjectClass(name string) (bool, error) {
	set, err := c.ObjectClassNames()
	if err != nil {
		return false, err
	}
	return set[strings.ToLower(name)], nil
}
