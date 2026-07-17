package ldapx

import (
	"fmt"
	"strings"

	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

// subschemaDefs returns the raw definitions attr declares on the subschema
// subentry — the schema as the server advertises it to a normal data bind, so
// no config bind is needed. The cn=config attributes (olcAccess, olcLimits, …)
// are in there too: slapd's schema is global.
func (c *Client) subschemaDefs(attr string) ([]string, error) {
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
	return e.GetAll(attr), nil
}

// subschemaNames returns the set of NAMEs declared by attr on the subschema
// subentry.
func (c *Client) subschemaNames(attr string) (map[string]bool, error) {
	defs, err := c.subschemaDefs(attr)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, def := range defs {
		for _, n := range schema.Names(def) {
			set[strings.ToLower(n)] = true
		}
	}
	return set, nil
}

// IsSingleValued reports whether the server's schema declares name SINGLE-VALUE.
// It errors if the schema does not declare name at all — an unknown attribute is
// not evidence of anything, and the caller is about to decide whether a replace
// destroys data.
//
// The subschema subentry is one large read, so the parsed answer is cached for
// the life of the client.
func (c *Client) IsSingleValued(name string) (bool, error) {
	if c.singleValued == nil {
		defs, err := c.subschemaDefs("attributeTypes")
		if err != nil {
			return false, err
		}
		c.singleValued = map[string]bool{}
		for _, def := range defs {
			single := schema.SingleValue(def)
			for _, n := range schema.Names(def) {
				c.singleValued[strings.ToLower(n)] = single
			}
		}
	}
	single, ok := c.singleValued[strings.ToLower(name)]
	if !ok {
		return false, fmt.Errorf("attribute %q is not in the server's schema", name)
	}
	return single, nil
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
