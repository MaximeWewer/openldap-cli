package overlay

import (
	"testing"

	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

// Definitions captured verbatim from a live slapd 2.6 (`schema show`), so the
// parsing is tested against what the server actually returns.
var live = []string{
	`( OLcfgGlOc:5 NAME 'olcOverlayConfig' DESC 'OpenLDAP Overlay-specific options' SUP olcConfig STRUCTURAL MUST olcOverlay MAY olcDisabled )`,
	`( OLcfgOvOc:10.1 NAME 'olcUniqueConfig' DESC 'Attribute value uniqueness configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcUniqueBase $ olcUniqueIgnore $ olcUniqueAttribute $ olcUniqueStrict $ olcUniqueURI ) )`,
	`( OLcfgOvOc:18.1 NAME ( 'olcMemberOfConfig' 'olcMemberOf' ) DESC 'Member-of configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcMemberOfDN $ olcMemberOfDangling ) )`,
	`( OLcfgOvOc:11.1 NAME 'olcRefintConfig' DESC 'Referential integrity configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcRefintAttribute ) )`,
	`( OLcfgOvOc:12.1 NAME 'olcPPolicyConfig' DESC 'Password Policy configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcPPolicyDefault ) )`,
	`( OLcfgOvOc:8.1 NAME ( 'olcDynListConfig' 'olcDynamicList' ) DESC 'Dynamic list configuration' SUP olcOverlayConfig STRUCTURAL MAY ( olcDynListAttrSet $ olcDynListSimple ) )`,
	`( OLcfgOvOc:4.1 NAME 'olcAccessLogConfig' DESC 'Access log configuration' SUP olcOverlayConfig STRUCTURAL MUST olcAccessLogDB MAY ( olcAccessLogOps ) )`,
	// not an overlay: must never be matched
	`( OLcfgDbOc:4.1 NAME 'olcMdbConfig' DESC 'MDB backend configuration' SUP olcDatabaseConfig STRUCTURAL MAY ( olcDbMaxSize ) )`,
}

func TestConfigClass(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"unique", "olcUniqueConfig"},
		{"refint", "olcRefintConfig"},
		{"ppolicy", "olcPPolicyConfig"},
		{"accesslog", "olcAccessLogConfig"},
		// matched via the primary name, whose alias (olcMemberOf) does not
		// derive the overlay name on its own
		{"memberof", "olcMemberOfConfig"},
		// the alias (olcDynamicList) would derive "dynamiclist"; the primary
		// name is what matches
		{"dynlist", "olcDynListConfig"},
		{"MemberOf", "olcMemberOfConfig"}, // case-insensitive
		{"nosuchoverlay", ""},
		// a database class, not an overlay one
		{"mdb", ""},
	} {
		if got := ConfigClass(live, tc.name, schema.Names); got != tc.want {
			t.Errorf("ConfigClass(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestKnownOverlaysExcludesNonOverlays(t *testing.T) {
	got := KnownOverlays(live, schema.Names)
	want := map[string]bool{"unique": true, "memberof": true, "refint": true, "ppolicy": true, "dynlist": true, "accesslog": true}
	if len(got) != len(want) {
		t.Fatalf("KnownOverlays() = %v, want %d entries", got, len(want))
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("KnownOverlays() returned unexpected %q", n)
		}
	}
}

func TestName(t *testing.T) {
	for in, want := range map[string]string{
		"{0}memberof": "memberof",
		"{12}ppolicy": "ppolicy",
		"unique":      "unique", // no prefix yet: what we send on add
		"":            "",
	} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestModule(t *testing.T) {
	if got := Module("memberof"); got != "memberof.so" {
		t.Errorf("Module(memberof) = %q", got)
	}
}
