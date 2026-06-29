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
