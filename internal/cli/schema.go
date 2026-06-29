package cli

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

var schemaCmd = &cobra.Command{
	Use:   "schema",
	Short: "Inspect the directory schema (objectClasses, attributeTypes)",
}

func schemaEntries(attr string) ([]*ldapx.Entry, error) {
	cc, err := connectConfig()
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	return cc.Search("cn=schema,cn=config", "(objectClass=olcSchemaConfig)", []string{attr})
}

// allNames collects sorted, de-duplicated NAMEs across every definition.
func allNames(entries []*ldapx.Entry, attr string) []string {
	seen := map[string]bool{}
	for _, e := range entries {
		for _, def := range e.GetAll(attr) {
			for _, n := range schema.Names(def) {
				seen[n] = true
			}
		}
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func newListCmd(use, short, attr, kind string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := schemaEntries(attr)
			if err != nil {
				return err
			}
			names := allNames(entries, attr)
			items := itemList{Kind: kind}
			for _, n := range names {
				items.Items = append(items.Items, item{Name: n})
			}
			return out.Emit(items)
		},
	}
}

var schemaShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show the raw definition of an objectClass or attributeType",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := strings.ToLower(strings.TrimSpace(args[0]))
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		entries, err := cc.Search("cn=schema,cn=config", "(objectClass=olcSchemaConfig)",
			[]string{"olcObjectClasses", "olcAttributeTypes"})
		if err != nil {
			return err
		}
		res := schemaShowResult{Name: args[0]}
		for _, e := range entries {
			for _, attr := range []string{"olcObjectClasses", "olcAttributeTypes"} {
				for _, def := range e.GetAll(attr) {
					for _, n := range schema.Names(def) {
						if strings.EqualFold(n, target) {
							res.Definitions = append(res.Definitions, def)
						}
					}
				}
			}
		}
		return out.Emit(res)
	},
}

type schemaShowResult struct {
	Name        string   `json:"name" yaml:"name"`
	Definitions []string `json:"definitions" yaml:"definitions"`
}

func (r schemaShowResult) Text() string {
	if len(r.Definitions) == 0 {
		return "no schema element named " + r.Name
	}
	return strings.Join(r.Definitions, "\n")
}

func init() {
	schemaCmd.AddCommand(
		newListCmd("list-classes", "List objectClass names", "olcObjectClasses", "objectClasses"),
		newListCmd("list-attrs", "List attributeType names", "olcAttributeTypes", "attributeTypes"),
		schemaShowCmd,
	)
	rootCmd.AddCommand(schemaCmd)
}
