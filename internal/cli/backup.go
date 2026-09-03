package cli

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	dnpkg "github.com/MaximeWewer/openldap-cli/internal/dn"
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
		"The dump carries only what the BIND can read: slapd applies its ACLs, so a\n" +
		"non-rootDN bind silently omits entries and attributes (userPassword above\n" +
		"all) it is denied. `backup data` checks this and warns — take backups as the\n" +
		"rootDN, whose reads bypass every ACL. Dumps then contain password hashes;\n" +
		"keep them on an encrypted partition.\n\n" +
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

		// shallowest DN first: slapd refuses an entry whose parent does not
		// exist yet, and nothing guarantees the dump listed them in that order
		sort.SliceStable(entries, func(i, j int) bool {
			return dnDepth(entries[i].DN) < dnDepth(entries[j].DN)
		})

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
		return emitBatch(res, len(res.Failed), len(res.Created)+len(res.Failed))
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

	size, err := writeDump(path, toLDIF(entries))
	if err != nil {
		return err
	}
	log.Debug().Str("file", path).Int("entries", len(entries)).Int64("bytes", size).Msg("backup written")
	// the dump went through the profile's bind, so it carries only what that
	// identity may read — say whether that is the whole database or a subset
	audit := auditBackup(cli, base, len(entries))
	return out.Emit(dumpResult{File: path, Base: base, Entries: len(entries), Bytes: size, Audit: audit})
}

// dnDepth counts a DN's RDN components, honoring escaped commas.
func dnDepth(d string) int {
	n := 0
	for rest := d; rest != ""; n++ {
		_, rest = dnpkg.Split(rest)
	}
	return n
}

// writeDump writes the LDIF to a sibling temp file and renames it over path
// only once every byte is on disk. A dump is a backup: truncating the previous
// one up front means a failure half way through destroys the good copy and
// leaves a partial file wearing its name.
//
// The file is 0600, not the 0666&umask of os.Create - a data dump taken as the
// rootDN carries every userPassword hash in the directory.
func writeDump(path string, entries []ldif.Entry) (size int64, err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return 0, err
	}

	bw := bufio.NewWriter(tmp)
	var w io.Writer = bw
	var gz *gzip.Writer
	if strings.HasSuffix(path, ".gz") {
		gz = gzip.NewWriter(bw)
		w = gz
	}
	if err = ldif.Write(w, entries); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	if gz != nil {
		if err = gz.Close(); err != nil {
			return 0, fmt.Errorf("write %s: %w", path, err)
		}
	}
	if err = bw.Flush(); err != nil {
		return 0, fmt.Errorf("write %s: %w", path, err)
	}
	// fsync before the rename, or a crash can leave the new name pointing at
	// a file whose contents never reached the disk
	if err = tmp.Sync(); err != nil {
		return 0, fmt.Errorf("sync %s: %w", path, err)
	}
	fi, err := tmp.Stat()
	if err != nil {
		return 0, err
	}
	if err = tmp.Close(); err != nil {
		return 0, err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return 0, err
	}
	return fi.Size(), nil
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
	File    string      `json:"file" yaml:"file"`
	Base    string      `json:"base" yaml:"base"`
	Entries int         `json:"entries" yaml:"entries"`
	Bytes   int64       `json:"bytes" yaml:"bytes"`
	Audit   backupAudit `json:"audit" yaml:"audit"`
}

func (r dumpResult) Text() string {
	s := fmt.Sprintf("backed up %d entries, %s (%s) -> %s",
		r.Entries, humanize.Bytes(r.Bytes), r.Base, r.File)
	if w := r.Audit.Warning(); w != "" {
		s += "\n  " + w
	}
	return s
}

func init() {
	backupDataCmd.Flags().BoolVar(&backupOperational, "operational", false, "include operational attributes (full-fidelity dump, not restorable)")
	backupRestoreCmd.Flags().BoolVar(&restoreStopOnErr, "stop-on-error", false, "abort on the first failing entry")

	backupCmd.AddCommand(backupDataCmd, backupConfigCmd, backupRestoreCmd)
	rootCmd.AddCommand(backupCmd)
}
