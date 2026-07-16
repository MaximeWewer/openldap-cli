package ldapx

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/MaximeWewer/openldap-cli/internal/overlay"
	"github.com/MaximeWewer/openldap-cli/internal/schema"
)

// DataDatabaseDN returns the cn=config database entry holding base (the DN a
// caller passes to the overlay/ACL helpers). Must be called on a config bind.
func (c *Client) DataDatabaseDN(base string) (string, error) { return c.dataDatabaseDN(base) }

// objectClassDefs returns every objectClass definition the server knows,
// including the ones registered by loaded modules.
func (c *Client) objectClassDefs() ([]string, error) {
	es, err := c.Search("cn=schema,cn=config", "(objectClass=olcSchemaConfig)", []string{"olcObjectClasses"})
	if err != nil {
		return nil, fmt.Errorf("read the config schema: %w", err)
	}
	var defs []string
	for _, e := range es {
		defs = append(defs, e.GetAll("olcObjectClasses")...)
	}
	return defs, nil
}

// OverlayConfigClass resolves the config objectClass for an overlay from the
// live schema, and reports every overlay the server could instantiate right now
// (useful to spell out the alternatives when name is not among them).
func (c *Client) OverlayConfigClass(name string) (class string, known []string, err error) {
	defs, err := c.objectClassDefs()
	if err != nil {
		return "", nil, err
	}
	known = overlay.KnownOverlays(defs, schema.Names)
	sort.Strings(known)
	return overlay.ConfigClass(defs, name, schema.Names), known, nil
}

// moduleListDN returns the cn=config entry holding olcModuleLoad. Absent means
// slapd was built with the overlays linked in (nothing to load).
func (c *Client) moduleListDN() (string, error) {
	es, err := c.Search("cn=config", "(objectClass=olcModuleList)", []string{"olcModuleLoad"})
	if err != nil {
		return "", fmt.Errorf("locate the module list: %w", err)
	}
	if len(es) == 0 {
		return "", nil
	}
	return es[0].DN, nil
}

// LoadModule appends file to the server's module list, loading it immediately.
// Note this is one-way: slapd rejects the removal of an olcModuleLoad value
// ("cannot delete olcModuleLoad"), so a module stays loaded until restart.
func (c *Client) LoadModule(file string) error {
	dn, err := c.moduleListDN()
	if err != nil {
		return err
	}
	if dn == "" {
		return fmt.Errorf("no olcModuleList entry: this slapd has no dynamic modules, so %q must be built in", file)
	}
	if err := c.Modify(dn, []Mod{{Op: ModAdd, Name: "olcModuleLoad", Values: []string{file}}}); err != nil {
		return fmt.Errorf("load module %s (is it present in olcModulePath?): %w", file, err)
	}
	return nil
}

// FindOverlay returns the overlay entry named name under dbDN, or nil when the
// overlay is not configured there. The stored value carries an ordering prefix
// ("{2}ppolicy"), so we match on the parsed name rather than filtering on it.
func (c *Client) FindOverlay(dbDN, name string) (*Entry, error) {
	es, err := c.search(dbDN, ldap.ScopeSingleLevel, "(objectClass=olcOverlayConfig)",
		[]string{"olcOverlay", "olcDisabled", "objectClass"}, 0)
	if err != nil {
		return nil, fmt.Errorf("list the overlays on %s: %w", dbDN, err)
	}
	for _, e := range es {
		if strings.EqualFold(overlay.Name(e.Get("olcOverlay")), name) {
			return e, nil
		}
	}
	return nil, nil
}

// OverlayState is what EnableOverlay/DisableOverlay did.
type OverlayState struct {
	DN     string // the overlay entry
	Action string // created | re-enabled | disabled | deleted | unchanged
	Module string // module we had to load to get here ("" if none)
}

// EnableOverlay makes the named overlay active on dbDN, creating its entry or
// clearing olcDisabled on an existing one. Re-running is a no-op.
//
// loadModule allows adding the overlay's module when its schema is missing;
// with it false, a missing module is reported instead of fixed.
func (c *Client) EnableOverlay(dbDN, name string, loadModule bool) (OverlayState, error) {
	st := OverlayState{}

	// already configured? then this is at most an olcDisabled flip.
	e, err := c.FindOverlay(dbDN, name)
	if err != nil {
		return st, err
	}
	if e != nil {
		st.DN = e.DN
		if !strings.EqualFold(e.Get("olcDisabled"), "TRUE") {
			st.Action = "unchanged"
			return st, nil
		}
		// FALSE rather than a delete: the attribute is what the server reports,
		// and setting it keeps the overlay's settings intact either way.
		if err := c.Modify(e.DN, []Mod{{Op: ModReplace, Name: "olcDisabled", Values: []string{"FALSE"}}}); err != nil {
			return st, fmt.Errorf("re-enable overlay %s: %w", name, err)
		}
		st.Action = "re-enabled"
		return st, nil
	}

	class, known, err := c.OverlayConfigClass(name)
	if err != nil {
		return st, err
	}
	if class == "" && loadModule {
		mod := overlay.Module(name)
		if err := c.LoadModule(mod); err != nil {
			return st, err
		}
		st.Module = mod
		if class, _, err = c.OverlayConfigClass(name); err != nil {
			return st, err
		}
	}

	attrs := map[string][]string{
		"objectClass": {"olcOverlayConfig"},
		"olcOverlay":  {name},
	}
	if class != "" {
		attrs["objectClass"] = append(attrs["objectClass"], class)
	} else if !loadModule {
		return st, fmt.Errorf("overlay %q has no schema on this server: its module (%s) is not loaded — drop --no-module to load it, or pick one of: %s",
			name, overlay.Module(name), strings.Join(known, ", "))
	}
	// class may still be "" for the few overlays with no settings of their own
	// (they are configured by olcOverlayConfig alone); let the server rule.

	// the RDN goes in unindexed; slapd assigns the {N} and renames the entry.
	dn := fmt.Sprintf("olcOverlay=%s,%s", name, dbDN)
	if err := c.AddEntry(dn, attrs); err != nil {
		return st, fmt.Errorf("enable overlay %s on %s: %w", name, dbDN, err)
	}
	if e, ferr := c.FindOverlay(dbDN, name); ferr == nil && e != nil {
		dn = e.DN // report the indexed DN the server settled on
	}
	st.DN, st.Action = dn, "created"
	return st, nil
}

// DisableOverlay deactivates the named overlay on dbDN. By default it sets
// olcDisabled: TRUE, which stops the overlay at runtime but keeps its
// configuration, so enabling it again restores the settings. With purge it
// deletes the entry and the settings with it.
func (c *Client) DisableOverlay(dbDN, name string, purge bool) (OverlayState, error) {
	e, err := c.FindOverlay(dbDN, name)
	if err != nil {
		return OverlayState{}, err
	}
	if e == nil {
		return OverlayState{Action: "unchanged"}, nil
	}
	st := OverlayState{DN: e.DN}
	if purge {
		if err := c.Delete(e.DN); err != nil {
			return st, fmt.Errorf("delete overlay %s: %w", name, err)
		}
		st.Action = "deleted"
		return st, nil
	}
	if strings.EqualFold(e.Get("olcDisabled"), "TRUE") {
		st.Action = "unchanged"
		return st, nil
	}
	if err := c.Modify(e.DN, []Mod{{Op: ModReplace, Name: "olcDisabled", Values: []string{"TRUE"}}}); err != nil {
		return st, fmt.Errorf("disable overlay %s: %w", name, err)
	}
	st.Action = "disabled"
	return st, nil
}
