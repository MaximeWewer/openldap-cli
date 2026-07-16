// Package overlay resolves how an OpenLDAP overlay is instantiated in cn=config.
//
// An overlay is a child entry of a database entry:
//
//	dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
//	objectClass: olcOverlayConfig
//	objectClass: olcMemberOfConfig
//
// The second objectClass is the overlay's own config class, and it is what
// carries the overlay's settings. slapd only knows that class once the
// overlay's module is loaded, so creating the entry with the module missing
// fails with the opaque `objectClass: value #1 invalid per syntax`.
//
// Rather than hard-code a name->class table that would drift with the server
// version and build options, we read the classes back from the server: every
// overlay config class is declared `SUP olcOverlayConfig`, so the live schema
// IS the catalogue. Its presence also doubles as the "is the module loaded?"
// probe, since a module registers its schema when it loads.
package overlay

import "strings"

// Module returns the module file that provides an overlay. Every in-tree
// overlay ships as <name>.so (memberof.so, refint.so, unique.so, …).
func Module(name string) string { return name + ".so" }

// Name strips the ordering prefix from an olcOverlay value: "{0}memberof" ->
// "memberof". Values without a prefix are returned as-is.
func Name(value string) string {
	if strings.HasPrefix(value, "{") {
		if i := strings.IndexByte(value, '}'); i > 0 {
			return value[i+1:]
		}
	}
	return value
}

// classToName maps a config objectClass to the overlay it configures:
// olcUniqueConfig -> unique, olcMemberOfConfig -> memberof, olcDynListConfig ->
// dynlist. Classes are conventionally olc<Overlay>Config.
func classToName(oc string) string {
	n := oc
	if len(n) > 3 && strings.EqualFold(n[:3], "olc") {
		n = n[3:]
	}
	if len(n) > 6 && strings.EqualFold(n[len(n)-6:], "Config") {
		n = n[:len(n)-6]
	}
	return strings.ToLower(n)
}

// derivesFromOverlayConfig reports whether an objectClass definition declares
// `SUP olcOverlayConfig` — i.e. it configures an overlay rather than anything
// else in cn=config.
func derivesFromOverlayConfig(def string) bool {
	i := strings.Index(def, " SUP ")
	if i < 0 {
		return false
	}
	f := strings.Fields(def[i+5:])
	// a multi-valued SUP ( a $ b ) is not used by overlay classes; the single
	// superior is the first token.
	return len(f) > 0 && strings.EqualFold(strings.Trim(f[0], "'"), "olcOverlayConfig")
}

// ConfigClass finds the config objectClass for the named overlay among the
// server's objectClass definitions, returning "" when none matches (the usual
// cause: the overlay's module is not loaded, so its schema is not registered).
//
// names extracts every NAME of a definition, because some classes carry an
// alias whose spelling is the one that matches (olcMemberOfConfig/olcMemberOf,
// olcDynListConfig/olcDynamicList) — we match on any of them but return the
// primary name, which is what we write to the entry.
func ConfigClass(defs []string, name string, names func(def string) []string) string {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, def := range defs {
		if !derivesFromOverlayConfig(def) {
			continue
		}
		ns := names(def)
		if len(ns) == 0 {
			continue
		}
		for _, n := range ns {
			if classToName(n) == want {
				return ns[0] // the primary name
			}
		}
	}
	return ""
}

// KnownOverlays lists the overlay names the server currently has schema for —
// i.e. those whose module is loaded and which `enable` can instantiate now.
func KnownOverlays(defs []string, names func(def string) []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, def := range defs {
		if !derivesFromOverlayConfig(def) {
			continue
		}
		ns := names(def)
		if len(ns) == 0 {
			continue
		}
		if n := classToName(ns[0]); !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
