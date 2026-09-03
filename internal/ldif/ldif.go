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
// needsBase64 reports whether RFC 2849 forbids writing v as a plain value.
// A trailing space counts: readers strip it, so `cn: admin ` comes back as
// "admin" and a backup/restore round-trip silently loses the character.
func needsBase64(v string) bool {
	if v == "" {
		return false
	}
	if v[0] == ' ' || v[0] == ':' || v[0] == '<' {
		return true
	}
	if v[len(v)-1] == ' ' {
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
		idx := map[string]int{} // canonical attr name -> position in e.Attrs
		for _, l := range rec {
			name, val, ok := splitLine(l)
			if !ok {
				continue
			}
			// a value given as a URL reference names a file the writer expected
			// the reader to fetch; storing the reference text would put
			// "< file://..." in the directory, so refuse rather than corrupt it
			if isURLRef(l) {
				return nil, fmt.Errorf("%s: URL-referenced values (%s:<) are not supported", e.DN, name)
			}
			switch key := strings.ToLower(name); key {
			case "dn":
				e.DN = val
			case "changetype":
				// every caller re-ADDS what it reads, so a modify or delete
				// record would be applied as its own opposite
				if !strings.EqualFold(strings.TrimSpace(val), "add") {
					return nil, fmt.Errorf("%s: changetype %q is not supported, only add", e.DN, val)
				}
			default:
				// attribute names are case-insensitive, so "CN" and "cn" are one
				// attribute; keeping them apart makes the add fail on a duplicate
				if i, seen := idx[key]; seen {
					e.Attrs[i].Values = append(e.Attrs[i].Values, val)
				} else {
					idx[key] = len(e.Attrs)
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
// isURLRef reports whether l uses the "attr:< url" form.
func isURLRef(l string) bool {
	i := strings.IndexByte(l, ':')
	return i > 0 && strings.HasPrefix(strings.TrimLeft(l[i+1:], " "), "<")
}

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
	// only the single space after the colon is the separator: RFC 2849 keeps
	// everything past it, so trimming the whole run would eat real characters
	return name, strings.TrimPrefix(rest, " "), true
}
