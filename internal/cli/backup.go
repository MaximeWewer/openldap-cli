package cli

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/humanize"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/ldif"
)

var (
	backupOperational bool
	restoreStopOnErr  bool
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Dump and restore the directory as (gzipped) LDIF over LDAP",
	Long: "Logical, protocol-level backup: no docker, shell, or volume access needed.\n" +
		"Exports use Simple Paged Results, so the server's olcSizeLimit never\n" +
		"silently truncates the dump. Files ending in .gz are gzip-compressed; the\n" +
		"matching gzip is auto-detected on restore.\n\n" +
		"Dumps contain password hashes — keep them on an encrypted partition.\n\n" +
		"This complements, and does NOT replace, a filesystem / slapcat backup:\n" +
		"operational state (entryUUID/entryCSN, replication contextCSN) and the\n" +
		"config tree are not restorable over the wire.",
}

// ---- data dump ----------------------------------------------------------

var backupDataCmd = &cobra.Command{
	Use:   "data <file>",
	Short: "Dump the data tree (base_dn subtree) as LDIF, gzipped if *.gz",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli backup data backup_data.ldif.gz\n" +
		"  openldap-cli backup data --operational full_dump.ldif.gz",
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()
		return dumpSubtree(cli, cli.Config().BaseDN, args[0])
	},
}

// ---- config dump --------------------------------------------------------

var backupConfigCmd = &cobra.Command{
	Use:   "config <file>",
	Short: "Dump the cn=config tree as LDIF (inspection / DR record only)",
	Long: "Requires the config bind. The dump is a read-only escape hatch for\n" +
		"inspection and disaster-recovery records — it is NOT restorable live over\n" +
		"LDAP. Recover the config tree from a slapd.d / slapcat -n0 backup instead.",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli backup config backup_config.ldif.gz",
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		return dumpSubtree(cc, "cn=config", args[0])
	},
}

// ---- restore ------------------------------------------------------------

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <file>",
	Short: "Restore entries from a (gzipped) LDIF dump into the data tree",
	Long: "Reads a plain or gzipped LDIF file (auto-detected) and re-adds every\n" +
		"entry. No-user-modification operational attributes (entryUUID, entryCSN,\n" +
		"structuralObjectClass, memberOf, ppolicy timers, ...) are stripped, and the\n" +
		"Relax control is sent so pre-hashed userPassword values are accepted under a\n" +
		"strict ppolicy. Existing entries fail individually; --stop-on-error aborts.",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli backup restore backup_data.ldif.gz",
	RunE: func(cmd *cobra.Command, args []string) error {
		entries, err := readLDIF(args[0])
		if err != nil {
			return err
		}
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		var res importResult
		for _, e := range entries {
			attrs := map[string][]string{}
			for _, a := range e.Attrs {
				if isNoUserMod(a.Name) {
					continue
				}
				attrs[a.Name] = a.Values
			}
			if err := cli.AddEntryRelax(e.DN, attrs); err != nil {
				res.Failed = append(res.Failed, importIssue{e.DN, err.Error()})
				if restoreStopOnErr {
					return fmt.Errorf("add %s: %w", e.DN, err)
				}
				continue
			}
			res.Created = append(res.Created, e.DN)
		}
		log.Debug().Int("restored", len(res.Created)).Int("failed", len(res.Failed)).Msg("restore done")
		return out.Emit(res)
	},
}

// ---- helpers ------------------------------------------------------------

// dumpSubtree writes a paged subtree search to path as LDIF, gzip-compressed
// when path ends in .gz. Pagination is transparent: olcSizeLimit never
// truncates the dump.
func dumpSubtree(cli *ldapx.Client, base, path string) error {
	var attrs []string // nil = all user attributes
	if backupOperational {
		attrs = []string{"*", "+"} // user + operational
	}
	entries, err := searchAll(cli, base, "(objectClass=*)", attrs)
	if err != nil {
		return fmt.Errorf("dump %s: %w", base, err)
	}

	f, err := os.Create(path) // #nosec G304 -- destination chosen by the operator
	if err != nil {
		return err
	}
	var w io.Writer = f
	var gz *gzip.Writer
	if strings.HasSuffix(path, ".gz") {
		gz = gzip.NewWriter(f)
		w = gz
	}
	ldif.Write(w, toLDIF(entries))
	if gz != nil {
		if cerr := gz.Close(); cerr != nil {
			_ = f.Close()
			return cerr
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	var size int64
	if fi, statErr := os.Stat(path); statErr == nil {
		size = fi.Size()
	}
	log.Debug().Str("file", path).Int("entries", len(entries)).Int64("bytes", size).Msg("backup written")
	return out.Emit(dumpResult{File: path, Base: base, Entries: len(entries), Bytes: size})
}

// readLDIF reads entries from a plain or gzipped LDIF file (auto-detected by
// the gzip magic bytes, regardless of extension).
func readLDIF(path string) ([]ldif.Entry, error) {
	f, err := os.Open(path) // #nosec G304 -- source chosen by the operator
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, gerr := gzip.NewReader(br)
		if gerr != nil {
			return nil, fmt.Errorf("gunzip %s: %w", path, gerr)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	}
	entries, err := ldif.Parse(r)
	if err != nil {
		return nil, fmt.Errorf("parse ldif: %w", err)
	}
	return entries, nil
}

// noUserMod lists operational attributes the server manages itself; they must
// be stripped before re-adding an entry, or the add is rejected.
var noUserMod = map[string]bool{
	"structuralobjectclass": true,
	"memberof":              true, // maintained by the memberof overlay
	"entryuuid":             true,
	"entrycsn":              true,
	"entrydn":               true,
	"creatorsname":          true,
	"createtimestamp":       true,
	"modifiersname":         true,
	"modifytimestamp":       true,
	"subschemasubentry":     true,
	"hassubordinates":       true,
	"numsubordinates":       true,
	"contextcsn":            true,
	"pwdchangedtime":        true,
	"pwdfailuretime":        true,
	"pwdaccountlockedtime":  true,
	"pwdgraceusetime":       true,
	"pwdhistory":            true,
}

func isNoUserMod(name string) bool { return noUserMod[strings.ToLower(name)] }

// dumpResult reports a written backup file.
type dumpResult struct {
	File    string `json:"file" yaml:"file"`
	Base    string `json:"base" yaml:"base"`
	Entries int    `json:"entries" yaml:"entries"`
	Bytes   int64  `json:"bytes" yaml:"bytes"`
}

func (r dumpResult) Text() string {
	return fmt.Sprintf("backed up %d entries, %s (%s) -> %s",
		r.Entries, humanize.Bytes(r.Bytes), r.Base, r.File)
}

func init() {
	backupDataCmd.Flags().BoolVar(&backupOperational, "operational", false, "include operational attributes (full-fidelity dump, not restorable)")
	backupRestoreCmd.Flags().BoolVar(&restoreStopOnErr, "stop-on-error", false, "abort on the first failing entry")

	backupCmd.AddCommand(backupDataCmd, backupConfigCmd, backupRestoreCmd)
	rootCmd.AddCommand(backupCmd)
}
