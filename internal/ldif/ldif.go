// Package ldif reads and writes a minimal subset of LDIF (add-style records),
// independent of any LDAP client library.
package ldif

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

// Attr is one attribute and its values.
type Attr struct {
	Name   string
	Values []string
}

// Entry is a DN plus its attributes.
type Entry struct {
	DN    string
	Attrs []Attr
}

// needsBase64 reports whether an LDIF value must be base64-encoded.
func needsBase64(v string) bool {
	if v == "" {
		return false
	}
	if v[0] == ' ' || v[0] == ':' || v[0] == '<' {
		return true
	}
	for i := range len(v) {
		if v[i] < 32 || v[i] > 126 {
			return true
		}
	}
	return false
}

func line(w io.Writer, name, val string) {
	if needsBase64(val) {
		fmt.Fprintf(w, "%s:: %s\n", name, base64.StdEncoding.EncodeToString([]byte(val)))
	} else {
		fmt.Fprintf(w, "%s: %s\n", name, val)
	}
}

// Write emits entries as LDIF (dn + attributes), blank-line separated.
func Write(w io.Writer, entries []Entry) {
	for _, e := range entries {
		line(w, "dn", e.DN)
		for _, a := range e.Attrs {
			for _, v := range a.Values {
				line(w, a.Name, v)
			}
		}
		fmt.Fprintln(w)
	}
}

// Parse reads add-style LDIF records (changetype ignored; dn separated out).
func Parse(r io.Reader) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	var records [][]string
	var cur []string
	flush := func() {
		if len(cur) > 0 {
			records = append(records, cur)
			cur = nil
		}
	}
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "#"):
			// comment
		case strings.TrimSpace(l) == "":
			flush()
		case strings.HasPrefix(l, " "):
			if len(cur) > 0 {
				cur[len(cur)-1] += l[1:] // unfold continuation
			}
		default:
			cur = append(cur, l)
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}

	var entries []Entry
	for _, rec := range records {
		var e Entry
		idx := map[string]int{} // attr name -> position in e.Attrs
		for _, l := range rec {
			name, val, ok := splitLine(l)
			if !ok {
				continue
			}
			switch strings.ToLower(name) {
			case "dn":
				e.DN = val
			case "changetype":
				// adds only
			default:
				if i, seen := idx[name]; seen {
					e.Attrs[i].Values = append(e.Attrs[i].Values, val)
				} else {
					idx[name] = len(e.Attrs)
					e.Attrs = append(e.Attrs, Attr{Name: name, Values: []string{val}})
				}
			}
		}
		if e.DN == "" {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// splitLine parses "name: value" / "name:: base64" into (name, decoded, ok).
func splitLine(l string) (string, string, bool) {
	i := strings.IndexByte(l, ':')
	if i <= 0 {
		return "", "", false
	}
	name := l[:i]
	rest := l[i+1:]
	if strings.HasPrefix(rest, ":") { // base64
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest[1:]))
		if err != nil {
			return "", "", false
		}
		return name, string(dec), true
	}
	return name, strings.TrimSpace(rest), true
}
