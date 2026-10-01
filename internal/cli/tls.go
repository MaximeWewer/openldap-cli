package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/tlsx"
)

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "Inspect and export the server's TLS certificates",
	Long: "Reads the certificate chain the server presents during the handshake, so a\n" +
		"client can be given the trust anchor it needs to connect over LDAPS.\n\n" +
		"No bind is involved: the certificate exchange happens before any credential\n" +
		"does, so these commands work with nothing but the URL - including from a\n" +
		"machine that has no account on the directory yet.\n\n" +
		"What the server loads its certificates FROM (olcTLSCACertificateFile and\n" +
		"friends) is a path on the server's filesystem, and LDAP exposes the path\n" +
		"but never the file. `tls config` shows those paths; the certificate bytes\n" +
		"can only come off the wire, which is what `show` and `export` do.",
}

// ---- shared -------------------------------------------------------------

// fetchChain handshakes with the profile's URL and returns what it presented.
func fetchChain() (*tlsx.Chain, string, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, "", err
	}
	chain, err := tlsx.Fetch(tlsx.Target{URL: cfg.URL, StartTLS: cfg.StartTLS, Timeout: cfg.Timeout})
	return chain, cfg.URL, err
}

// certInfo is one certificate as a result record.
type certInfo struct {
	Position    int      `json:"position" yaml:"position"`
	Role        string   `json:"role" yaml:"role"`
	Subject     string   `json:"subject" yaml:"subject"`
	Issuer      string   `json:"issuer" yaml:"issuer"`
	SANs        []string `json:"sans,omitempty" yaml:"sans,omitempty"`
	NotAfter    string   `json:"not_after" yaml:"not_after"`
	DaysLeft    int      `json:"days_left" yaml:"days_left"`
	Expired     bool     `json:"expired" yaml:"expired"`
	Fingerprint string   `json:"sha256_fingerprint" yaml:"sha256_fingerprint"`
}

// role names a certificate by the job it does in the chain, which is what
// decides whether a client installs it or merely passes through it.
func role(c *x509.Certificate, i int) string {
	switch {
	case i == 0 && tlsx.IsSelfSigned(c):
		return "server (self-signed, it is its own CA)"
	case i == 0:
		return "server"
	case tlsx.IsSelfSigned(c):
		return "root CA"
	case c.IsCA:
		return "intermediate CA"
	default:
		return "extra"
	}
}

func describe(chain *tlsx.Chain) []certInfo {
	now := time.Now()
	out := make([]certInfo, 0, len(chain.Certs))
	for i, c := range chain.Certs {
		expired, days := tlsx.Expiry(c, now)
		out = append(out, certInfo{
			Position:    i,
			Role:        role(c, i),
			Subject:     c.Subject.String(),
			Issuer:      c.Issuer.String(),
			SANs:        tlsx.SANs(c),
			NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:    days,
			Expired:     expired,
			Fingerprint: tlsx.Fingerprint(c),
		})
	}
	return out
}

// anchorAdvice is the sentence that decides what the operator does next.
func anchorAdvice(chain *tlsx.Chain) string {
	if err := chain.Verify(); err != nil {
		if chain.Root() == nil {
			return "the server did not send a root CA, so nothing here anchors trust on its own.\n" +
				"  That is normal for a certificate issued by a corporate or public CA: get the\n" +
				"  root from whoever runs that PKI. (" + err.Error() + ")"
		}
		return "a root is present but the chain still does not validate: " + err.Error()
	}
	return "this chain validates " + chain.ServerName + " on its own: exporting it is enough for a client to verify the server"
}

// ---- show ---------------------------------------------------------------

type tlsShowResult struct {
	URL      string     `json:"url" yaml:"url"`
	Protocol string     `json:"protocol" yaml:"protocol"`
	Cipher   string     `json:"cipher" yaml:"cipher"`
	Chain    []certInfo `json:"chain" yaml:"chain"`
	Verified bool       `json:"verified_by_own_chain" yaml:"verified_by_own_chain"`
	Advice   string     `json:"advice" yaml:"advice"`
}

func (r tlsShowResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  (%s, %s)\n", r.URL, r.Protocol, r.Cipher)
	for _, c := range r.Chain {
		fmt.Fprintf(&b, "\n  [%d] %s\n", c.Position, c.Role)
		fmt.Fprintf(&b, "      subject: %s\n", c.Subject)
		fmt.Fprintf(&b, "      issuer:  %s\n", c.Issuer)
		if len(c.SANs) > 0 {
			fmt.Fprintf(&b, "      names:   %s\n", strings.Join(c.SANs, ", "))
		}
		exp := fmt.Sprintf("%s (%d days left)", c.NotAfter, c.DaysLeft)
		if c.Expired {
			exp = c.NotAfter + "  EXPIRED"
		}
		fmt.Fprintf(&b, "      expires: %s\n", exp)
		fmt.Fprintf(&b, "      sha256:  %s\n", c.Fingerprint)
	}
	fmt.Fprintf(&b, "\n  %s", r.Advice)
	return b.String()
}

var tlsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Describe the certificate chain the server presents",
	Long: "Handshakes with the profile's URL and reports every certificate: what it is\n" +
		"in the chain, the names it covers, when it expires, and its SHA-256\n" +
		"fingerprint in the same format as `openssl x509 -fingerprint -sha256`.\n\n" +
		"The last line says whether the chain validates on its own - i.e. whether\n" +
		"`tls export` gives a client everything it needs, or whether the root has to\n" +
		"come from the PKI instead.",
	Args:    cobra.NoArgs,
	Example: "  openldap-cli --profile prod tls show",
	RunE: func(cmd *cobra.Command, args []string) error {
		chain, url, err := fetchChain()
		if err != nil {
			return err
		}
		return out.Emit(tlsShowResult{
			URL:      url,
			Protocol: tls.VersionName(chain.Version),
			Cipher:   tls.CipherSuiteName(chain.CipherSuite),
			Chain:    describe(chain),
			Verified: chain.Verify() == nil,
			Advice:   anchorAdvice(chain),
		})
	},
}

// ---- export -------------------------------------------------------------

var tlsExportFull bool

type tlsExportResult struct {
	File         string     `json:"file,omitempty" yaml:"file,omitempty"`
	Certificates []certInfo `json:"certificates" yaml:"certificates"`
	Advice       string     `json:"advice" yaml:"advice"`
}

func (r tlsExportResult) Text() string {
	var b strings.Builder
	if r.File == "" {
		return "" // the PEM already went to stdout; saying anything else would corrupt it
	}
	fmt.Fprintf(&b, "wrote %d certificate(s) to %s\n", len(r.Certificates), r.File)
	for _, c := range r.Certificates {
		fmt.Fprintf(&b, "  %s\n    %s\n    sha256: %s\n", c.Role, c.Subject, c.Fingerprint)
	}
	fmt.Fprintf(&b, "\n  %s\n", r.Advice)
	b.WriteString("  Compare the fingerprint against the server's own record before installing it:\n" +
		"  this was fetched over a connection it could not itself verify.")
	return b.String()
}

var tlsExportCmd = &cobra.Command{
	Use:   "export [file]",
	Short: "Export the server's certificates as PEM, for a client's trust store",
	Long: "Writes the certificates the server presents as PEM - to <file>, or to stdout\n" +
		"when no file is named, so it pipes.\n\n" +
		"By default it exports the CA certificates: that is what a client installs to\n" +
		"verify the server, and it keeps working when the server's own certificate is\n" +
		"renewed. --full writes the whole chain (server certificate included), which\n" +
		"is what you want to pin a single host or to archive what was presented.\n\n" +
		"A self-signed server with no CA above it is its own anchor, and is exported\n" +
		"as such.\n\n" +
		"TRUST: the fetch cannot verify the certificate it is fetching - there is\n" +
		"nothing to verify against yet. Treat the result as trust-on-first-use and\n" +
		"compare the printed SHA-256 against the server's own record, out of band,\n" +
		"before installing it anywhere that matters.",
	Args: cobra.MaximumNArgs(1),
	Example: "  # the CA a client needs, straight into its trust store\n" +
		"  openldap-cli --profile prod tls export ca.pem\n" +
		"  # everything presented, for pinning or an archive\n" +
		"  openldap-cli --profile prod tls export --full chain.pem\n" +
		"  # no file: PEM on stdout\n" +
		"  openldap-cli --profile prod tls export | sudo tee /usr/local/share/ca-certificates/ldap.crt",
	RunE: func(cmd *cobra.Command, args []string) error {
		chain, _, err := fetchChain()
		if err != nil {
			return err
		}

		certs := chain.Certs
		if !tlsExportFull {
			certs = chain.CACerts()
			// a lone self-signed server certificate is the trust anchor; there
			// is no CA above it to export instead
			if len(certs) == 0 && tlsx.IsSelfSigned(chain.Leaf()) {
				certs = []*x509.Certificate{chain.Leaf()}
			}
			if len(certs) == 0 {
				return fmt.Errorf("the server sent no CA certificate, only its own:\n"+
					"  there is nothing here to anchor trust on. Get the root from whoever runs\n"+
					"  the PKI that issued %q, or re-run with --full to export the server\n"+
					"  certificate itself and pin that instead", chain.Leaf().Subject.String())
			}
		}

		res := tlsExportResult{Certificates: describeAs(certs, chain), Advice: anchorAdvice(chain)}

		if len(args) == 0 || args[0] == "-" {
			if err := tlsx.WritePEM(os.Stdout, certs); err != nil {
				return err
			}
			// the advice belongs on stderr: stdout is the PEM and nothing else
			log.Info().Msg(res.Advice)
			log.Warn().Msg("fetched over an unverified connection; compare the SHA-256 out of band: " +
				tlsx.Fingerprint(certs[len(certs)-1]))
			return nil
		}

		path := args[0]
		if err := writePEMFile(path, certs); err != nil {
			return err
		}
		res.File = path
		log.Debug().Str("file", path).Int("certs", len(certs)).Msg("certificates exported")
		return out.Emit(res)
	},
}

// describeAs renders certs with the roles they hold in their original chain.
func describeAs(certs []*x509.Certificate, chain *tlsx.Chain) []certInfo {
	idx := map[string]int{}
	for i, c := range chain.Certs {
		idx[string(c.Raw)] = i
	}
	now := time.Now()
	out := make([]certInfo, 0, len(certs))
	for _, c := range certs {
		i := idx[string(c.Raw)]
		expired, days := tlsx.Expiry(c, now)
		out = append(out, certInfo{
			Position:    i,
			Role:        role(c, i),
			Subject:     c.Subject.String(),
			Issuer:      c.Issuer.String(),
			SANs:        tlsx.SANs(c),
			NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:    days,
			Expired:     expired,
			Fingerprint: tlsx.Fingerprint(c),
		})
	}
	return out
}

// writePEMFile writes the bundle atomically, so a failed export never leaves a
// half-written trust store that a client would then load.
func writePEMFile(path string, certs []*x509.Certificate) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	// 0644: a CA certificate is public by nature and a trust store has to be
	// readable by whatever service loads it
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tlsx.WritePEM(tmp, certs); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ---- config -------------------------------------------------------------

type tlsConfigResult struct {
	DN       string            `json:"dn" yaml:"dn"`
	Settings map[string]string `json:"settings" yaml:"settings"`
	Note     string            `json:"note" yaml:"note"`
}

func (r tlsConfigResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.DN)
	if len(r.Settings) == 0 {
		b.WriteString("  no olcTLS* settings (this server is not configured for TLS)\n")
	}
	for _, k := range tlsSettingOrder {
		if v, ok := r.Settings[k]; ok {
			fmt.Fprintf(&b, "  %-28s %s\n", k+":", v)
		}
	}
	fmt.Fprintf(&b, "\n  %s", r.Note)
	return b.String()
}

var tlsSettingOrder = []string{
	"olcTLSCACertificateFile",
	"olcTLSCACertificatePath",
	"olcTLSCertificateFile",
	"olcTLSCertificateKeyFile",
	"olcTLSCipherSuite",
	"olcTLSProtocolMin",
	"olcTLSVerifyClient",
	"olcTLSCRLCheck",
}

var tlsConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show where the server loads its TLS material from (olcTLS*, config bind)",
	Long: "Reads the olcTLS* settings off cn=config. These are PATHS on the server's\n" +
		"filesystem: LDAP exposes where the CA lives, never its contents, so this\n" +
		"cannot export anything - use `tls export` for the certificate bytes.\n\n" +
		"Useful to tell which CA file a renewal has to replace, and to check\n" +
		"olcTLSProtocolMin / olcTLSVerifyClient.",
	Args:    cobra.NoArgs,
	Example: "  openldap-cli --profile prod-root tls config",
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		e, err := cc.ReadEntry("cn=config", tlsSettingOrder)
		if err != nil {
			return fmt.Errorf("read the TLS settings on cn=config: %w", err)
		}
		settings := map[string]string{}
		for _, k := range tlsSettingOrder {
			if v := e.Get(k); v != "" {
				settings[k] = v
			}
		}
		return out.Emit(tlsConfigResult{
			DN:       e.DN,
			Settings: settings,
			Note:     "these are paths on the server host; `tls export` is what reads the certificates themselves",
		})
	},
}

// ---- check --------------------------------------------------------------

var tlsCheckDays int

type tlsCheckResult struct {
	URL      string     `json:"url" yaml:"url"`
	OK       bool       `json:"ok" yaml:"ok"`
	Problems []string   `json:"problems,omitempty" yaml:"problems,omitempty"`
	Chain    []certInfo `json:"chain" yaml:"chain"`
}

func (r tlsCheckResult) Text() string {
	if r.OK {
		var soonest = -1
		for _, c := range r.Chain {
			if soonest < 0 || c.DaysLeft < soonest {
				soonest = c.DaysLeft
			}
		}
		return fmt.Sprintf("%s OK - chain valid, %d days before the first certificate expires", r.URL, soonest)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s NOT OK\n", r.URL)
	for _, p := range r.Problems {
		fmt.Fprintf(&b, "  ! %s\n", p)
	}
	return strings.TrimRight(b.String(), "\n")
}

var tlsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Fail when the server's certificate is expiring or does not validate",
	Long: "One command for a cron job or a monitoring probe: it exits non-zero when\n" +
		"any certificate in the chain has expired or expires within --days, or when\n" +
		"the chain does not validate the hostname it is serving.\n\n" +
		"It verifies against the chain the server itself presents, so it catches the\n" +
		"renewal nobody noticed - not whether this particular host happens to trust\n" +
		"the CA. Point `ca_file` at your anchor and the usual commands do the rest.",
	Args: cobra.NoArgs,
	Example: "  openldap-cli --profile prod tls check --days 30\n" +
		"  # in cron: mail only when it has something to say\n" +
		"  openldap-cli --profile prod tls check --days 30 || echo 'LDAPS cert needs attention'",
	RunE: func(cmd *cobra.Command, args []string) error {
		chain, url, err := fetchChain()
		if err != nil {
			return err
		}
		res := tlsCheckResult{URL: url, Chain: describe(chain), OK: true}

		now := time.Now()
		for i, c := range chain.Certs {
			expired, days := tlsx.Expiry(c, now)
			switch {
			case expired:
				res.Problems = append(res.Problems,
					fmt.Sprintf("%s (%s) EXPIRED on %s", role(c, i), c.Subject.String(), c.NotAfter.UTC().Format(time.RFC3339)))
			case days < tlsCheckDays:
				res.Problems = append(res.Problems,
					fmt.Sprintf("%s (%s) expires in %d days, on %s", role(c, i), c.Subject.String(), days, c.NotAfter.UTC().Format(time.RFC3339)))
			}
		}
		if verr := chain.Verify(); verr != nil {
			// a chain missing its root is not a fault of the server: say what it
			// is rather than reporting a renewal problem that does not exist
			if chain.Root() == nil {
				res.Problems = append(res.Problems,
					"the chain does not carry its root, so it cannot be validated from the wire alone: "+verr.Error())
			} else {
				res.Problems = append(res.Problems, "the chain does not validate "+chain.ServerName+": "+verr.Error())
			}
		}

		res.OK = len(res.Problems) == 0
		if err := out.Emit(res); err != nil {
			return err
		}
		if !res.OK {
			// the report is already on stdout; the exit status is what a probe reads
			return fmt.Errorf("%d problem(s) with the certificate on %s", len(res.Problems), url)
		}
		return nil
	},
}

// ---- published CAs (RFC 4523) -------------------------------------------

// A directory can publish its CA certificates as entries holding
// cACertificate, which is a different source from the handshake: it answers
// "what does this organization publish" rather than "what does this server
// present", and carries no chain, no cipher and no hostname to check against.
// Hence its own pair of commands rather than a flag on show/export.

var tlsCABase string

// publishedCAs searches for entries holding cACertificate and parses them.
func publishedCAs() ([]publishedCA, error) {
	cli, err := connect()
	if err != nil {
		return nil, err
	}
	defer cli.Close()

	base := strings.TrimSpace(tlsCABase)
	if base == "" {
		base = cli.Config().BaseDN
	}
	// a presence filter, not an objectClass one: pkiCA (RFC 4523) and the older
	// certificationAuthority both carry the attribute, and so do schemas that
	// use neither. Ask for the ;binary form, which is how it comes back.
	entries, err := searchAll(cli, base, "(cACertificate=*)",
		[]string{"cACertificate;binary", "cACertificate", "cn"})
	if err != nil {
		return nil, fmt.Errorf("search published CAs under %s: %w", base, err)
	}

	var out []publishedCA
	for _, e := range entries {
		vals := e.GetAllOpt("cACertificate")
		if len(vals) == 0 {
			continue
		}
		certs, perr := tlsx.ParseDER(vals)
		if perr != nil {
			return nil, fmt.Errorf("%s: %w", e.DN, perr)
		}
		out = append(out, publishedCA{DN: e.DN, Certs: certs})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no entry under %s publishes a cACertificate\n"+
			"  This directory does not advertise its CA in the tree; read it off the\n"+
			"  wire with `tls export` instead", base)
	}
	return out, nil
}

type publishedCA struct {
	DN    string
	Certs []*x509.Certificate
}

type tlsCAListResult struct {
	Base    string             `json:"base" yaml:"base"`
	Entries []tlsCAEntryResult `json:"entries" yaml:"entries"`
}

type tlsCAEntryResult struct {
	DN           string     `json:"dn" yaml:"dn"`
	Certificates []certInfo `json:"certificates" yaml:"certificates"`
}

func (r tlsCAListResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "published CA certificates under %s\n", r.Base)
	for _, e := range r.Entries {
		fmt.Fprintf(&b, "\n  %s\n", e.DN)
		for _, c := range e.Certificates {
			fmt.Fprintf(&b, "      subject: %s\n", c.Subject)
			fmt.Fprintf(&b, "      issuer:  %s\n", c.Issuer)
			exp := fmt.Sprintf("%s (%d days left)", c.NotAfter, c.DaysLeft)
			if c.Expired {
				exp = c.NotAfter + "  EXPIRED"
			}
			fmt.Fprintf(&b, "      expires: %s\n", exp)
			fmt.Fprintf(&b, "      sha256:  %s\n", c.Fingerprint)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// describePublished renders certificates that came out of the tree. They have
// no position in a chain, so the role is read off the certificate alone.
func describePublished(certs []*x509.Certificate) []certInfo {
	now := time.Now()
	out := make([]certInfo, 0, len(certs))
	for i, c := range certs {
		expired, days := tlsx.Expiry(c, now)
		kind := "not a CA certificate" // published, but it anchors nothing
		switch {
		case tlsx.IsSelfSigned(c):
			kind = "root CA"
		case c.IsCA:
			kind = "intermediate CA"
		}
		out = append(out, certInfo{
			Position:    i,
			Role:        kind,
			Subject:     c.Subject.String(),
			Issuer:      c.Issuer.String(),
			SANs:        tlsx.SANs(c),
			NotAfter:    c.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:    days,
			Expired:     expired,
			Fingerprint: tlsx.Fingerprint(c),
		})
	}
	return out
}

var tlsCAListCmd = &cobra.Command{
	Use:   "ca-list",
	Short: "List the CA certificates the directory publishes (cACertificate)",
	Long: "Some directories publish their CA in the tree, as entries carrying\n" +
		"cACertificate (RFC 4523, objectClass pkiCA or the older\n" +
		"certificationAuthority). This finds them and describes what they hold.\n\n" +
		"That is a different source from `tls show`: it answers what the\n" +
		"organization publishes, not what one server presents, so there is no chain\n" +
		"and nothing to validate a hostname against. Most directories publish\n" +
		"nothing here - that is not a fault, just read the certificate off the wire\n" +
		"with `tls export`.",
	Args:    cobra.NoArgs,
	Example: "  openldap-cli --profile prod tls ca-list --base ou=pki,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		cas, err := publishedCAs()
		if err != nil {
			return err
		}
		res := tlsCAListResult{Base: tlsCABase}
		if res.Base == "" {
			cfg, cerr := loadConfig()
			if cerr != nil {
				return cerr
			}
			res.Base = cfg.BaseDN
		}
		for _, c := range cas {
			res.Entries = append(res.Entries, tlsCAEntryResult{DN: c.DN, Certificates: describePublished(c.Certs)})
		}
		return out.Emit(res)
	},
}

var tlsCAExportCmd = &cobra.Command{
	Use:   "ca-export [file]",
	Short: "Export the CA certificates the directory publishes, as PEM",
	Long: "Writes every cACertificate found in the tree as PEM - to <file>, or to\n" +
		"stdout when no file is named.\n\n" +
		"Unlike `tls export` this does not read the wire, so what comes out is what\n" +
		"the directory says its CA is, carried over an LDAP connection that is only\n" +
		"as trustworthy as the one you made. Compare the fingerprints out of band\n" +
		"before installing them.",
	Args: cobra.MaximumNArgs(1),
	Example: "  openldap-cli --profile prod tls ca-export pki-cas.pem\n" +
		"  openldap-cli --profile prod tls ca-export --base ou=pki,dc=example,dc=org",
	RunE: func(cmd *cobra.Command, args []string) error {
		cas, err := publishedCAs()
		if err != nil {
			return err
		}
		var certs []*x509.Certificate
		for _, c := range cas {
			certs = append(certs, c.Certs...)
		}

		if len(args) == 0 || args[0] == "-" {
			if err := tlsx.WritePEM(os.Stdout, certs); err != nil {
				return err
			}
			log.Warn().Msg("published by the directory, not read off the wire; compare the fingerprints out of band")
			return nil
		}
		if err := writePEMFile(args[0], certs); err != nil {
			return err
		}
		log.Debug().Str("file", args[0]).Int("certs", len(certs)).Msg("published CAs exported")
		return out.Emit(tlsExportResult{
			File:         args[0],
			Certificates: describePublished(certs),
			Advice:       "these come from the directory tree, not from the TLS handshake",
		})
	},
}

func init() {
	tlsExportCmd.Flags().BoolVar(&tlsExportFull, "full", false,
		"export the whole chain, server certificate included")
	for _, c := range []*cobra.Command{tlsCAListCmd, tlsCAExportCmd} {
		c.Flags().StringVar(&tlsCABase, "base", "", "search base for published CAs (default: the profile's base_dn)")
	}
	tlsCheckCmd.Flags().IntVar(&tlsCheckDays, "days", 30, "fail when a certificate expires within this many days")
	tlsCmd.AddCommand(tlsShowCmd, tlsExportCmd, tlsCheckCmd, tlsConfigCmd, tlsCAListCmd, tlsCAExportCmd)
	rootCmd.AddCommand(tlsCmd)
}
