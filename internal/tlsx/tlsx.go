// Package tlsx fetches and describes the certificate chain an LDAP server
// presents, so an operator can hand a client the trust anchor it needs.
//
// The whole point is to run BEFORE you have the CA, so the fetch cannot verify
// the certificate it is fetching. That makes it trust-on-first-use: fine for
// bootstrapping over a network you already trust, but the fingerprint has to be
// compared out of band before the result is installed anywhere that matters.
// Every entry point here reports the fingerprint for exactly that reason.
package tlsx

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Target names the endpoint to handshake with.
type Target struct {
	URL      string // ldaps://host:636 or ldap://host:389
	StartTLS bool   // upgrade an ldap:// URL before reading the chain
	Timeout  time.Duration
}

// Chain is what one server presented, in the order it sent it: leaf first.
type Chain struct {
	ServerName  string // the host the certificate was asked to be valid for
	Version     uint16
	CipherSuite uint16
	Certs       []*x509.Certificate
}

// Fetch completes a TLS handshake and returns the chain, without binding: the
// certificate exchange happens before any credential does, so this needs none.
func Fetch(t Target) (*Chain, error) {
	host, err := hostOf(t.URL)
	if err != nil {
		return nil, err
	}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	// InsecureSkipVerify is the point, not an oversight: we are retrieving the
	// trust anchor, so there is nothing to verify against yet. Verify reports
	// separately on what the chain would prove once installed.
	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // #nosec G402 -- fetching the trust anchor; see Verify
		MinVersion:         tls.VersionTLS12,
	}

	conn, err := ldap.DialURL(t.URL,
		ldap.DialWithTLSConfig(cfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
	)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", t.URL, err)
	}
	defer func() { _ = conn.Close() }()
	conn.SetTimeout(timeout)

	if t.StartTLS {
		if err := conn.StartTLS(cfg); err != nil {
			return nil, fmt.Errorf("starttls on %s: %w", t.URL, err)
		}
	}

	state, ok := conn.TLSConnectionState()
	if !ok {
		return nil, fmt.Errorf("%s is not encrypted: use an ldaps:// URL, or ldap:// with start_tls", t.URL)
	}
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("the server presented no certificate")
	}
	return &Chain{
		ServerName:  host,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		Certs:       state.PeerCertificates,
	}, nil
}

// hostOf pulls the hostname out of an LDAP URL, and refuses the schemes that
// never carry TLS.
func hostOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse url %q: %w", raw, err)
	}
	switch u.Scheme {
	case "ldaps", "ldap":
	case "ldapi":
		return "", errors.New("ldapi:// is a Unix socket and carries no certificate")
	default:
		return "", fmt.Errorf("unsupported url scheme %q", u.Scheme)
	}
	if h := u.Hostname(); h != "" {
		return h, nil
	}
	return "", fmt.Errorf("no host in url %q", raw)
}

// Leaf is the server's own certificate.
func (c *Chain) Leaf() *x509.Certificate {
	if len(c.Certs) == 0 {
		return nil
	}
	return c.Certs[0]
}

// CACerts returns the CA certificates in the chain - what a client installs as
// its trust anchor. The leaf is never one of them, even if it is marked as a CA.
func (c *Chain) CACerts() []*x509.Certificate {
	var out []*x509.Certificate
	for i, cert := range c.Certs {
		if i == 0 {
			continue
		}
		if cert.IsCA {
			out = append(out, cert)
		}
	}
	return out
}

// Root returns the self-signed certificate in the chain, or nil when the server
// did not send one.
//
// A server legitimately omits the root (RFC 8446 s4.4.2 says it MAY), so this
// being nil is the normal case for a chain anchored in a public or corporate
// CA: there is simply nothing here to install, and the client has to get the
// root from the PKI instead.
func (c *Chain) Root() *x509.Certificate {
	for _, cert := range c.Certs {
		if IsSelfSigned(cert) {
			return cert
		}
	}
	return nil
}

// IsSelfSigned reports whether a certificate is its own issuer and signed
// itself - a root, as opposed to a cert someone else vouched for.
func IsSelfSigned(cert *x509.Certificate) bool {
	if !cert.IsCA || cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// Verify answers the question the export is really about: once a client trusts
// the CA certificates in this chain, does the server's certificate check out
// for this hostname?
//
// It deliberately trusts only what the chain itself carries, never the host's
// own store, so the answer is about the file being exported and not about how
// this particular machine happens to be configured.
func (c *Chain) Verify() error {
	leaf := c.Leaf()
	if leaf == nil {
		return errors.New("no certificate")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, cert := range c.Certs[1:] {
		if IsSelfSigned(cert) {
			roots.AddCert(cert)
		} else {
			inter.AddCert(cert)
		}
	}
	// a self-signed leaf is its own anchor: installing it IS the trust decision
	if len(c.Certs) == 1 && IsSelfSigned(leaf) {
		roots.AddCert(leaf)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       c.ServerName,
		Roots:         roots,
		Intermediates: inter,
	})
	return err
}

// Fingerprint is the SHA-256 digest of a certificate, formatted the way
// `openssl x509 -fingerprint -sha256` prints it so the two can be compared
// out of band character for character.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

// SANs lists the names the certificate is actually valid for - the usual reason
// an LDAPS client rejects a server it can otherwise reach.
func SANs(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// WritePEM encodes certificates in the order given.
func WritePEM(w io.Writer, certs []*x509.Certificate) error {
	for _, cert := range certs {
		if err := pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return err
		}
	}
	return nil
}

// ParseDER turns raw certificate values - as an LDAP server returns
// cACertificate;binary, i.e. DER, one certificate per value - into parsed
// certificates. A value that is not a certificate is reported rather than
// skipped: an operator exporting a trust anchor needs to know the directory
// holds something it should not.
func ParseDER(values []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(values))
	for i, v := range values {
		cert, err := x509.ParseCertificate([]byte(v))
		if err != nil {
			return nil, fmt.Errorf("value %d is not a DER certificate: %w", i, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

// Expiry describes how a certificate sits against a moment in time.
func Expiry(cert *x509.Certificate, now time.Time) (expired bool, daysLeft int) {
	if now.After(cert.NotAfter) {
		return true, 0
	}
	return false, int(cert.NotAfter.Sub(now).Hours() / 24)
}
