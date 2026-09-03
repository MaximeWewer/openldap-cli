package output

import (
	"bytes"
	"strings"
	"testing"
)

type fake struct {
	Name string `json:"name" yaml:"name"`
}

func (f fake) Text() string { return "TEXT:" + f.Name }

func emit(t *testing.T, format string, v Renderable) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := New(format, &buf)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	if err := w.Emit(v); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestText(t *testing.T) {
	if got := emit(t, "text", fake{"x"}); strings.TrimSpace(got) != "TEXT:x" {
		t.Errorf("text = %q", got)
	}
}

func TestJSON(t *testing.T) {
	got := emit(t, "json", fake{"x"})
	if !strings.Contains(got, `"name": "x"`) {
		t.Errorf("json = %q", got)
	}
}

func TestYAML(t *testing.T) {
	got := emit(t, "yaml", fake{"x"})
	if !strings.Contains(got, "name: x") {
		t.Errorf("yaml = %q", got)
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := New("toml", &bytes.Buffer{}); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestJSONDoesNotEscapeHTMLOrReorderKeys(t *testing.T) {
	// directory data is full of < > & (an RFC 4514 DN escapes < and >, ACL
	// rules carry &), and results go to a pipe, not an HTML page
	var b bytes.Buffer
	w, err := New("json", &b)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Emit(entryish{DN: `cn=a\<b\>c,dc=e`, Attrs: map[string][]string{
		"z": {"last"}, "a": {"R&D <team>"},
	}}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	if strings.Contains(got, `\u003c`) || strings.Contains(got, `\u0026`) {
		t.Errorf("JSON still escapes HTML characters:\n%s", got)
	}
	if !strings.Contains(got, `cn=a\\<b\\>c,dc=e`) {
		t.Errorf("DN not rendered readably:\n%s", got)
	}
	// map keys stay sorted, so two runs of a command diff cleanly
	if strings.Index(got, `"a"`) > strings.Index(got, `"z"`) {
		t.Errorf("map keys are not sorted:\n%s", got)
	}
}

type entryish struct {
	DN    string              `json:"dn" yaml:"dn"`
	Attrs map[string][]string `json:"attrs" yaml:"attrs"`
}

func (e entryish) Text() string { return e.DN }
