package cli

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// ---- whoami -------------------------------------------------------------

var whoamiCmd = &cobra.Command{
	Use:   "whoami",
	Short: "Show the bound identity (LDAP Who Am I ext-op)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		id, err := cli.WhoAmI()
		if err != nil {
			return err
		}
		if id == "" {
			id = "(anonymous)"
		}
		return out.Emit(okResult{Action: "bound as", DN: id})
	},
}

// ---- search -------------------------------------------------------------

var (
	searchBase       string
	searchScope      string
	searchAttrs      []string
	searchConfigBind bool
)

var searchCmd = &cobra.Command{
	Use:   "search <filter>",
	Short: "Raw LDAP search (escape hatch)",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli search '(mail=*@example.org)' --attrs uid,mail\n" +
		"  openldap-cli search '(objectClass=groupOfNames)' --base ou=groups,dc=example,dc=org\n" +
		"  openldap-cli search '(objectClass=olcModuleList)' --base cn=config --attrs olcModuleLoad --config-bind",
	RunE: func(cmd *cobra.Command, args []string) error {
		connectFn := connect
		if searchConfigBind {
			connectFn = connectConfig
		}
		cli, err := connectFn()
		if err != nil {
			return err
		}
		defer cli.Close()

		base := searchBase
		if base == "" {
			base = cli.Config().BaseDN
		}
		scope := ldapx.ScopeSub
		switch searchScope {
		case "base":
			scope = ldapx.ScopeBase
		case "one":
			scope = ldapx.ScopeOne
		case "sub", "":
		default:
			return fmt.Errorf("--scope must be base|one|sub")
		}

		entries, err := cli.SearchScope(base, scope, args[0], searchAttrs, 250)
		if err != nil {
			return fmt.Errorf("search: %w", err)
		}
		res := entryList{}
		for _, e := range entries {
			res.Entries = append(res.Entries, newEntryResult(e))
		}
		return out.Emit(res)
	},
}

// ---- version ------------------------------------------------------------

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("openldap-cli %s (go %s)\n", version, strings.TrimPrefix(runtime.Version(), "go"))
	},
}

func init() {
	searchCmd.Flags().StringVar(&searchBase, "base", "", "search base DN (default: base DN)")
	searchCmd.Flags().StringVar(&searchScope, "scope", "sub", "scope: base|one|sub")
	searchCmd.Flags().StringSliceVar(&searchAttrs, "attrs", nil, "attributes to return (comma-separated)")
	searchCmd.Flags().BoolVar(&searchConfigBind, "config-bind", false, "bind as the config identity (to search cn=config)")
	rootCmd.AddCommand(whoamiCmd, searchCmd, versionCmd)
}
