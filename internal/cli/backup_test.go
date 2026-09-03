package cli

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/MaximeWewer/openldap-cli/internal/ldif"
)

func TestDNDepthCountsRDNs(t *testing.T) {
	// an escaped comma is part of the RDN, not a separator: getting this wrong
	// sorts a child before its parent and the restore fails on it
	for d, want := range map[string]int{
		"":                         0,
		"dc=e":                     1,
		"ou=people,dc=e":           2,
		`cn=Doe\, John,ou=p,dc=e`:  3,
		"cn=a,ou=b,ou=c,dc=d,dc=e": 5,
	} {
		if got := dnDepth(d); got != want {
			t.Errorf("dnDepth(%q) = %d, want %d", d, got, want)
		}
	}
}

func TestRestoreOrderPutsParentsFirst(t *testing.T) {
	// this is the sort `backup restore` applies; a dump listing a child before
	// its parent would otherwise fail on every child
	entries := []ldif.Entry{
		{DN: "cn=deep,ou=p,dc=e"},
		{DN: "dc=e"},
		{DN: "ou=p,dc=e"},
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return dnDepth(entries[i].DN) < dnDepth(entries[j].DN)
	})
	want := []string{"dc=e", "ou=p,dc=e", "cn=deep,ou=p,dc=e"}
	for i, e := range entries {
		if e.DN != want[i] {
			t.Fatalf("order = %v, want %v", entries, want)
		}
	}
}

func TestWriteDumpIsPrivateAndAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.ldif")
	entries := []ldif.Entry{{DN: "cn=x,dc=e", Attrs: []ldif.Attr{{Name: "cn", Values: []string{"x"}}}}}

	if _, err := writeDump(path, entries); err != nil {
		t.Fatalf("writeDump: %v", err)
	}
	// a dump carries password hashes, so it must not be readable by the world
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("dump is mode %#o, want no group/other bits", mode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "dn: cn=x,dc=e") {
		t.Errorf("dump content = %q", body)
	}
	// nothing is left behind next to it
	names, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*"))
	if len(names) != 1 {
		t.Errorf("writeDump left temp files behind: %v", names)
	}
}

func TestWriteDumpGzipsByExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.ldif.gz")
	if _, err := writeDump(path, []ldif.Entry{{DN: "cn=x,dc=e"}}); err != nil {
		t.Fatalf("writeDump: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("not gzip: %v", err)
	}
	got, err := ldif.Parse(gz)
	if err != nil || len(got) != 1 || got[0].DN != "cn=x,dc=e" {
		t.Errorf("round-trip through gzip gave %v, %v", got, err)
	}
}

func TestWriteDumpKeepsThePreviousFileOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dump.ldif")
	// the parent does not exist, so the write cannot succeed
	if _, err := writeDump(path, []ldif.Entry{{DN: "cn=x,dc=e"}}); err == nil {
		t.Fatal("writeDump succeeded with no parent directory")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("a failed dump left a file at the destination")
	}
}

func TestIsNoUserModIgnoresCase(t *testing.T) {
	// the server sends its own spelling; the strip has to match either way
	for _, n := range []string{"entryUUID", "entryuuid", "ENTRYUUID", "structuralObjectClass"} {
		if !isNoUserMod(n) {
			t.Errorf("isNoUserMod(%q) = false, want true", n)
		}
	}
	if isNoUserMod("cn") {
		t.Error(`isNoUserMod("cn") = true`)
	}
}
