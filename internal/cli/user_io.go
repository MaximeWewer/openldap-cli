package cli

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/domain"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/ldif"
)

// ---- import -------------------------------------------------------------

var userImportStopOnError bool

var userImportCmd = &cobra.Command{
	Use:   "import <csv-file>",
	Short: "Bulk-create users from CSV",
	Long: "CSV rows: firstname.lastname[,group][,mail-override]\n" +
		"Blank lines and lines starting with # are skipped, as is a header row\n" +
		"whose first field is login/uid/firstname.lastname.",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()

		r := csv.NewReader(f)
		r.FieldsPerRecord = -1 // 1..3 columns
		r.Comment = '#'
		r.TrimLeadingSpace = true

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		var res importResult
		for {
			row, err := r.Read()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return fmt.Errorf("read csv: %w", err)
			}
			if len(row) == 0 || strings.TrimSpace(row[0]) == "" {
				continue
			}
			login := strings.ToLower(strings.TrimSpace(row[0]))
			if isHeader(login) {
				continue
			}
			group, mailOverride := "", ""
			if len(row) > 1 {
				group = strings.TrimSpace(row[1])
			}
			if len(row) > 2 {
				mailOverride = strings.TrimSpace(row[2])
			}

			u, err := domain.ParseUser(login, cfg.MailDomain)
			if err != nil {
				res.Failed = append(res.Failed, importIssue{login, err.Error()})
				if userImportStopOnError {
					return err
				}
				continue
			}
			if mailOverride != "" {
				u.Mail = mailOverride
			}
			dn := u.DN(cfg.UserOU, cfg.BaseDN)
			if err := cli.AddEntry(dn, u.AttributeMap("", nil)); err != nil {
				res.Failed = append(res.Failed, importIssue{login, err.Error()})
				if userImportStopOnError {
					return fmt.Errorf("create %s: %w", login, err)
				}
				continue
			}
			res.Created = append(res.Created, dn)

			if group != "" {
				if err := addToGroup(cli, group, u.DN(cfg.UserOU, cfg.BaseDN)); err != nil {
					res.Warnings = append(res.Warnings, importIssue{login, "group " + group + ": " + err.Error()})
				}
			}
		}
		log.Debug().Int("created", len(res.Created)).Int("failed", len(res.Failed)).Msg("import done")
		return out.Emit(res)
	},
}

// toLDIF converts directory entries to the ldif package's neutral form.
func toLDIF(entries []*ldapx.Entry) []ldif.Entry {
	out := make([]ldif.Entry, 0, len(entries))
	for _, e := range entries {
		le := ldif.Entry{DN: e.DN}
		for _, name := range e.Names() {
			le.Attrs = append(le.Attrs, ldif.Attr{Name: name, Values: e.GetAll(name)})
		}
		out = append(out, le)
	}
	return out
}

func isHeader(first string) bool {
	switch first {
	case "login", "uid", "firstname.lastname", "user", "username":
		return true
	}
	return false
}

func addToGroup(cli *ldapx.Client, group, memberDN string) error {
	g, err := cli.FindGroup(group, []string{"cn"})
	if err != nil {
		return err
	}
	return cli.Modify(g.DN, []ldapx.Mod{{Op: ldapx.ModAdd, Name: "member", Values: []string{memberDN}}})
}

type importIssue struct {
	Login string `json:"login" yaml:"login"`
	Error string `json:"error" yaml:"error"`
}

type importResult struct {
	Created  []string      `json:"created" yaml:"created"`
	Failed   []importIssue `json:"failed,omitempty" yaml:"failed,omitempty"`
	Warnings []importIssue `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

func (r importResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "imported %d, failed %d, warnings %d\n",
		len(r.Created), len(r.Failed), len(r.Warnings))
	for _, c := range r.Created {
		fmt.Fprintf(&b, "  + %s\n", c)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "  ~ %s: %s\n", w.Login, w.Error)
	}
	for _, f := range r.Failed {
		fmt.Fprintf(&b, "  ! %s: %s\n", f.Login, f.Error)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- export -------------------------------------------------------------

var (
	userExportWithHash bool
	userExportGroup    string
	userExportLDIF     bool
)

var userExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export users to stdout as CSV (or LDIF with --ldif)",
	Long: "Writes CSV (uid,cn,sn,givenName,displayName,mail) to stdout. The global\n" +
		"-o flag does not apply here. --with-hash appends the userPassword column.\n" +
		"--ldif writes full entries as LDIF (re-importable with import-ldif).",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		filter := "(objectClass=inetOrgPerson)"
		if userExportGroup != "" {
			g, gerr := cli.FindGroup(userExportGroup, []string{"cn"})
			if gerr != nil {
				return gerr
			}
			filter = "(&" + filter + "(memberOf=" + ldapx.EscapeFilter(g.DN) + "))"
		}

		if userExportLDIF {
			entries, serr := searchAll(cli, cli.UserBase(), filter, nil)
			if serr != nil {
				return fmt.Errorf("search users: %w", serr)
			}
			ldif.Write(os.Stdout, toLDIF(entries))
			return nil
		}

		cols := []string{"uid", "cn", "sn", "givenName", "displayName", "mail"}
		if userExportWithHash {
			cols = append(cols, "userPassword")
		}
		entries, err := searchAll(cli, cli.UserBase(), filter, cols)
		if err != nil {
			return fmt.Errorf("search users: %w", err)
		}

		w := csv.NewWriter(os.Stdout)
		defer w.Flush()
		if err := w.Write(cols); err != nil {
			return err
		}
		for _, e := range entries {
			rec := make([]string, len(cols))
			for i, c := range cols {
				rec[i] = e.Get(c)
			}
			if err := w.Write(rec); err != nil {
				return err
			}
		}
		log.Debug().Int("users", len(entries)).Msg("export done")
		return w.Error()
	},
}

func init() {
	userImportCmd.Flags().BoolVar(&userImportStopOnError, "stop-on-error", false, "abort on the first failing row")
	userExportCmd.Flags().BoolVar(&userExportWithHash, "with-hash", false, "include the userPassword column")
	userExportCmd.Flags().StringVar(&userExportGroup, "group", "", "only members of this group")
	userExportCmd.Flags().BoolVar(&userExportLDIF, "ldif", false, "output full entries as LDIF instead of CSV")
	// import/export are bulk -> live under `users`
	usersCmd.AddCommand(userImportCmd, userExportCmd)
}
