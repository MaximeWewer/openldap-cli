package cli

import (
	"strings"
	"testing"
)

// found reports whether any finding mentions sub.
func found(fs []string, sub string) bool {
	for _, f := range fs {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

func TestJudgeFlagsAProtocolFloorThatIsTooLow(t *testing.T) {
	// OpenLDAP writes the record version: 3.1 is TLS 1.0, 3.3 is TLS 1.2
	for v, weak := range map[string]bool{
		"3.0": true, "3.1": true, "3.2": true,
		"3.3": false, "3.4": false,
	} {
		got := found(judge(map[string]string{"olcTLSProtocolMin": v}), "RFC 8996")
		if got != weak {
			t.Errorf("olcTLSProtocolMin %s: flagged=%v, want %v", v, got, weak)
		}
	}
	// a floor nobody stated is a floor nobody controls
	if !found(judge(map[string]string{}), "unset") {
		t.Error("an absent olcTLSProtocolMin went unremarked")
	}
	if !found(judge(map[string]string{"olcTLSProtocolMin": "9.9"}), "not a version") {
		t.Error("an unparsable olcTLSProtocolMin went unremarked")
	}
}

func TestJudgeFlagsClientCertsTrustedWithoutRevocationChecking(t *testing.T) {
	// verifying a client certificate while never asking whether it was revoked
	// is the combination that looks secure and is not
	for _, crl := range []string{"", "none"} {
		fs := judge(map[string]string{"olcTLSVerifyClient": "demand", "olcTLSCRLCheck": crl})
		if !found(fs, "revoked") {
			t.Errorf("olcTLSCRLCheck %q with demand went unremarked: %v", crl, fs)
		}
	}
	// and a server that does check is left alone
	if fs := judge(map[string]string{"olcTLSVerifyClient": "demand", "olcTLSCRLCheck": "peer"}); found(fs, "revoked") {
		t.Errorf("flagged a server that checks CRLs: %v", fs)
	}
}

func TestJudgeExplainsWhySASLExternalCannotWork(t *testing.T) {
	// the exact trap: EXTERNAL is absent because no client certificate is ever
	// validated, which reads like a missing SASL mechanism
	fs := judge(map[string]string{"olcTLSCertificateFile": "/x.crt", "olcTLSVerifyClient": "never"})
	if !found(fs, "SASL EXTERNAL") {
		t.Errorf("never-verify went unremarked on a TLS-enabled server: %v", fs)
	}
	// nothing to say about a server that serves no TLS at all
	if fs := judge(map[string]string{"olcTLSVerifyClient": "never"}); found(fs, "SASL EXTERNAL") {
		t.Errorf("remarked on a server with no certificate: %v", fs)
	}
}

func TestJudgeIsSilentOnASoundConfiguration(t *testing.T) {
	fs := judge(map[string]string{
		"olcTLSCertificateFile": "/x.crt",
		"olcTLSProtocolMin":     "3.3",
		"olcTLSVerifyClient":    "demand",
		"olcTLSCRLCheck":        "peer",
	})
	if len(fs) != 0 {
		t.Errorf("findings on a sound configuration: %v", fs)
	}
}
