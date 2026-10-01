package tlsx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// issue builds a certificate signed by parent, or self-signed when parent is nil.
func issue(t *testing.T, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, notAfter time.Time, dns ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  isCA,
		DNSNames:              dns,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	signer, signerKey := tmpl, key // self-signed by default
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestIsSelfSignedDistinguishesRootFromIntermediate(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := issue(t, "Test Root CA", true, nil, nil, far)
	inter, interKey := issue(t, "Test Intermediate CA", true, root, rootKey, far)
	leaf, _ := issue(t, "ldap.example.org", false, inter, interKey, far, "ldap.example.org")

	if !IsSelfSigned(root) {
		t.Error("root not recognized as self-signed")
	}
	if IsSelfSigned(inter) {
		t.Error("intermediate reported as self-signed")
	}
	if IsSelfSigned(leaf) {
		t.Error("leaf reported as self-signed")
	}
}

func TestChainWithRootVerifiesAndYieldsCAs(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := issue(t, "Test Root CA", true, nil, nil, far)
	inter, interKey := issue(t, "Test Intermediate CA", true, root, rootKey, far)
	leaf, _ := issue(t, "ldap.example.org", false, inter, interKey, far, "ldap.example.org")

	c := &Chain{ServerName: "ldap.example.org", Certs: []*x509.Certificate{leaf, inter, root}}

	if err := c.Verify(); err != nil {
		t.Errorf("Verify on a complete chain: %v", err)
	}
	if c.Root() == nil {
		t.Error("Root() = nil on a chain that includes one")
	}
	// the leaf is never offered as a trust anchor, only the CAs above it
	cas := c.CACerts()
	if len(cas) != 2 {
		t.Fatalf("CACerts() = %d, want 2", len(cas))
	}
	for _, cert := range cas {
		if cert.Equal(leaf) {
			t.Error("CACerts() included the leaf")
		}
	}
}

func TestChainWithoutRootReportsItHonestly(t *testing.T) {
	// the common real case: a server sends leaf + intermediate and omits the
	// root, so there is nothing in the export to anchor trust on
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := issue(t, "Test Root CA", true, nil, nil, far)
	inter, interKey := issue(t, "Test Intermediate CA", true, root, rootKey, far)
	leaf, _ := issue(t, "ldap.example.org", false, inter, interKey, far, "ldap.example.org")

	c := &Chain{ServerName: "ldap.example.org", Certs: []*x509.Certificate{leaf, inter}}

	if c.Root() != nil {
		t.Error("Root() invented a root the server never sent")
	}
	if err := c.Verify(); err == nil {
		t.Error("Verify succeeded without a trust anchor; it must not claim the export is usable")
	}
}

func TestSelfSignedLeafIsItsOwnAnchor(t *testing.T) {
	// the throwaway/dev case: one self-signed cert, no CA above it. Installing
	// that cert IS the trust decision, so it has to verify.
	far := time.Now().Add(24 * time.Hour)
	leaf, _ := issue(t, "ldap.example.org", true, nil, nil, far, "ldap.example.org")

	c := &Chain{ServerName: "ldap.example.org", Certs: []*x509.Certificate{leaf}}
	if err := c.Verify(); err != nil {
		t.Errorf("Verify on a self-signed leaf: %v", err)
	}
}

func TestVerifyRejectsAHostnameMismatch(t *testing.T) {
	// the usual reason an LDAPS client refuses a server it can reach
	far := time.Now().Add(24 * time.Hour)
	leaf, _ := issue(t, "ldap.example.org", true, nil, nil, far, "ldap.example.org")

	c := &Chain{ServerName: "ldap.internal", Certs: []*x509.Certificate{leaf}}
	if err := c.Verify(); err == nil {
		t.Error("Verify accepted a certificate that does not name the host")
	}
}

func TestFingerprintMatchesOpenSSLFormat(t *testing.T) {
	leaf, _ := issue(t, "x", true, nil, nil, time.Now().Add(time.Hour))
	fp := Fingerprint(leaf)

	if n := strings.Count(fp, ":"); n != 31 {
		t.Errorf("fingerprint has %d separators, want 31 for a SHA-256: %s", n, fp)
	}
	if len(fp) != 95 {
		t.Errorf("fingerprint length = %d, want 95: %s", len(fp), fp)
	}
	if fp != strings.ToUpper(fp) {
		t.Errorf("fingerprint is not upper-case: %s", fp)
	}
}

func TestWritePEMRoundTrips(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := issue(t, "Test Root CA", true, nil, nil, far)
	inter, _ := issue(t, "Test Intermediate CA", true, root, rootKey, far)

	var b bytes.Buffer
	if err := WritePEM(&b, []*x509.Certificate{inter, root}); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b.Bytes()) {
		t.Fatal("the PEM we wrote is not loadable as a trust store")
	}
	if got := strings.Count(b.String(), "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("wrote %d PEM blocks, want 2", got)
	}
}

func TestHostOfRejectsWhatCarriesNoCertificate(t *testing.T) {
	if _, err := hostOf("ldapi:///"); err == nil {
		t.Error("hostOf accepted a Unix socket URL")
	}
	if _, err := hostOf("http://x"); err == nil {
		t.Error("hostOf accepted a non-LDAP scheme")
	}
	for _, u := range []string{"ldaps://ldap.example.org:636", "ldap://ldap.example.org"} {
		h, err := hostOf(u)
		if err != nil || h != "ldap.example.org" {
			t.Errorf("hostOf(%q) = %q, %v", u, h, err)
		}
	}
}

func TestExpiryFlagsAnExpiredCertificate(t *testing.T) {
	past, _ := issue(t, "old", true, nil, nil, time.Now().Add(-time.Minute))
	if expired, _ := Expiry(past, time.Now()); !expired {
		t.Error("an already-expired certificate was not flagged")
	}
	future, _ := issue(t, "new", true, nil, nil, time.Now().Add(72*time.Hour))
	expired, days := Expiry(future, time.Now())
	if expired || days < 2 || days > 3 {
		t.Errorf("Expiry = %v, %d days; want valid with ~3 days", expired, days)
	}
}

// serveTLS starts a bare TLS listener presenting chain, and returns its
// ldaps:// URL. An ldaps:// dial completes the handshake before any LDAP
// message is exchanged, so a listener that speaks no LDAP is enough to
// exercise the real network path.
func serveTLS(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				// complete the handshake, then let the client hang up
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(50 * time.Millisecond)
				_ = conn.Close()
			}()
		}
	}()
	return "ldaps://" + ln.Addr().String()
}

func TestFetchReadsTheChainOffTheWire(t *testing.T) {
	far := time.Now().Add(24 * time.Hour)
	root, rootKey := issue(t, "Wire Root CA", true, nil, nil, far)
	inter, interKey := issue(t, "Wire Intermediate CA", true, root, rootKey, far)
	leaf, leafKey := issue(t, "127.0.0.1", false, inter, interKey, far, "localhost")
	leaf.IPAddresses = nil // names come from the SAN list set at issue time

	url := serveTLS(t, [][]byte{leaf.Raw, inter.Raw, root.Raw}, leafKey)

	got, err := Fetch(Target{URL: url, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(got.Certs) != 3 {
		t.Fatalf("got %d certificates, want the 3 the server sent", len(got.Certs))
	}
	if got.Certs[0].Subject.CommonName != "127.0.0.1" {
		t.Errorf("leaf is not first: %s", got.Certs[0].Subject)
	}
	if got.Root() == nil {
		t.Error("Root() = nil though the server sent one")
	}
	if n := len(got.CACerts()); n != 2 {
		t.Errorf("CACerts() = %d, want 2", n)
	}
	// what was fetched must load as a trust store, which is the whole point
	var b bytes.Buffer
	if err := WritePEM(&b, got.CACerts()); err != nil {
		t.Fatal(err)
	}
	if !x509.NewCertPool().AppendCertsFromPEM(b.Bytes()) {
		t.Error("the exported CA bundle is not loadable")
	}
}

func TestFetchRefusesAPlaintextEndpoint(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
			_ = c.Close()
		}
	}()

	// ldap:// without StartTLS carries no certificate: say so rather than
	// return an empty chain that reads like "this server has no certs"
	_, err = Fetch(Target{URL: "ldap://" + ln.Addr().String(), Timeout: 3 * time.Second})
	if err == nil {
		t.Fatal("Fetch returned a chain for an unencrypted connection")
	}
	if !strings.Contains(err.Error(), "not encrypted") {
		t.Errorf("error does not explain the problem: %v", err)
	}
}
