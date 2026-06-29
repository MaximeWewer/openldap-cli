package ldif

import (
	"bytes"
	"strings"
	"testing"
)

func attrVal(e Entry, name string) []string {
	for _, a := range e.Attrs {
		if a.Name == name {
			return a.Values
		}
	}
	return nil
}

func TestRoundtrip(t *testing.T) {
	in := []Entry{{DN: "cn=a,dc=x", Attrs: []Attr{
		{Name: "objectClass", Values: []string{"top", "person"}},
		{Name: "cn", Values: []string{"a"}},
		{Name: "sn", Values: []string{"Alpha"}},
	}}}
	var buf bytes.Buffer
	Write(&buf, in)

	out, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].DN != "cn=a,dc=x" {
		t.Fatalf("got %+v", out)
	}
	if got := attrVal(out[0], "sn"); len(got) != 1 || got[0] != "Alpha" {
		t.Errorf("sn = %v", got)
	}
	if got := attrVal(out[0], "objectClass"); len(got) != 2 {
		t.Errorf("objectClass = %v", got)
	}
}

func TestBase64Roundtrip(t *testing.T) {
	val := "héllo\nworld" // non-ascii + newline -> must base64
	var buf bytes.Buffer
	Write(&buf, []Entry{{DN: "cn=b,dc=x", Attrs: []Attr{{Name: "description", Values: []string{val}}}}})
	if !strings.Contains(buf.String(), "description:: ") {
		t.Errorf("expected base64 line, got:\n%s", buf.String())
	}
	out, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := attrVal(out[0], "description"); len(got) != 1 || got[0] != val {
		t.Errorf("description = %v, want %q", got, val)
	}
}

func TestParseFoldingAndComments(t *testing.T) {
	in := "dn: cn=c,dc=x\n# a comment\nobjectClass: top\nsn: Very\n Long\n\n"
	out, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d records", len(out))
	}
	if got := attrVal(out[0], "sn"); len(got) != 1 || got[0] != "VeryLong" {
		t.Errorf("folded sn = %v, want [VeryLong]", got)
	}
}

func TestParseMultiValue(t *testing.T) {
	in := "dn: cn=d,dc=x\nmember: cn=a,dc=x\nmember: cn=b,dc=x\n"
	out, _ := Parse(strings.NewReader(in))
	if got := attrVal(out[0], "member"); len(got) != 2 {
		t.Errorf("member = %v, want 2 values", got)
	}
}
