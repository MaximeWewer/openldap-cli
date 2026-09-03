// Package output renders command results to stdout in a selectable format.
// Logs go to stderr (zerolog); data goes here. Keep them separate so `-o json`
// stays machine-parseable.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
)

// Format is a stdout rendering mode.
type Format string

const (
	Text Format = "text" // human-readable
	JSON Format = "json"
	YAML Format = "yaml"
)

// Renderable is any result that can describe itself for human (text) output.
// JSON/YAML modes marshal the value directly, so export the fields you want.
type Renderable interface {
	Text() string
}

// Writer emits Renderables in the chosen Format.
type Writer struct {
	format Format
	w      io.Writer
}

// New validates the format string and returns a Writer.
func New(format string, w io.Writer) (*Writer, error) {
	f := Format(strings.ToLower(format))
	switch f {
	case Text, JSON, YAML:
		return &Writer{format: f, w: w}, nil
	default:
		return nil, fmt.Errorf("unknown output format %q (text|json|yaml)", format)
	}
}

// Emit writes one result in the configured format.
func (o *Writer) Emit(v Renderable) error {
	switch o.format {
	case JSON:
		enc := json.NewEncoder(o.w)
		enc.SetIndent("", "  ")
		// results go to a pipe, never into an HTML page, and directory data is
		// full of the three characters this escapes: an RFC 4514 DN quotes `<`
		// and `>`, olcAccess rules and descriptions carry `&`. Escaping them
		// turned a readable DN into cn=a\u003cb\u003ec for no one's benefit.
		enc.SetEscapeHTML(false)
		return enc.Encode(v)
	case YAML:
		b, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		_, err = o.w.Write(b)
		return err
	default:
		// escape here rather than in each Text(): attribute values are written
		// by whoever can write the entry, so any of them can carry ESC
		// sequences that repaint the operator's terminal. JSON and YAML encode
		// control characters themselves, so only the text path needs it.
		_, err := fmt.Fprintln(o.w, SafeBlock(v.Text()))
		return err
	}
}
