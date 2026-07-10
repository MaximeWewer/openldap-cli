package ldapx

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// bulkPageSize is the page size SearchAll uses to stream large result sets.
const bulkPageSize = 1000

// SizeLimitError is returned when a bulk search is capped by the server's
// administrative size limit and the cap could not be lifted (no usable config
// bind). It tells the operator how to raise the limit.
type SizeLimitError struct{ Base string }

func (e *SizeLimitError) Error() string {
	return fmt.Sprintf("results capped by the server size limit (olcSizeLimit) on %q and no config bind is available to lift it; set config_bind_dn / config_bind_pw or bind as the rootDN", e.Base)
}

// SearchAll runs a paged subtree search that transparently works around the
// server's per-identity administrative size limit (olcSizeLimit / olcLimits).
//
// The entry count is unknown up front, so it always pages. If the server caps
// the result (sizeLimitExceeded) and the profile carries a working config bind,
// it temporarily grants the bound identity an unlimited limit — a scoped
// olcLimits override on the data database — retries, then restores olcLimits
// exactly. Without a usable config bind it returns a *SizeLimitError instead of
// silently truncating.
//
// escalated reports whether the limit had to be lifted (so callers can log it).
func (c *Client) SearchAll(base, filter string, attrs []string) (entries []*Entry, escalated bool, err error) {
	entries, err = c.search(base, ldap.ScopeWholeSubtree, filter, attrs, bulkPageSize)
	if err == nil {
		return entries, false, nil
	}
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return nil, false, err
	}
	if c.cfg.ConfigBindDN == "" && !c.cfg.SASLExternal {
		return nil, false, &SizeLimitError{Base: base}
	}
	entries, err = c.searchEscalated(base, filter, attrs)
	if err != nil {
		return nil, false, err
	}
	return entries, true, nil
}

// searchEscalated lifts the bound identity's size limit via the config bind,
// runs the search, and restores olcLimits.
func (c *Client) searchEscalated(base, filter string, attrs []string) (entries []*Entry, err error) {
	// the config-bind attempt itself is the "is the config admin available?"
	// check — a missing DN or wrong credentials surfaces here as a clear error.
	cc := *c.cfg
	cc.BindDN, cc.BindPW = c.cfg.ConfigBindDN, c.cfg.ConfigBindPW
	cfg, err := Connect(&cc)
	if err != nil {
		return nil, fmt.Errorf("config bind to lift the size limit: %w", err)
	}
	defer cfg.Close()

	dbDN, err := cfg.dataDatabaseDN(c.cfg.BaseDN)
	if err != nil {
		return nil, err
	}

	// snapshot the existing olcLimits values so revert deletes exactly the one
	// we add, regardless of how the server re-indexes/normalizes it.
	before, err := cfg.ReadEntry(dbDN, []string{"olcLimits"})
	if err != nil {
		return nil, fmt.Errorf("read olcLimits on %s: %w", dbDN, err)
	}
	had := make(map[string]bool, len(before.GetAll("olcLimits")))
	for _, v := range before.GetAll("olcLimits") {
		had[v] = true
	}

	override := fmt.Sprintf(`dn.exact=%q time=unlimited size=unlimited size.pr=unlimited size.prtotal=unlimited`, c.cfg.BindDN)
	if merr := cfg.Modify(dbDN, []Mod{{Op: ModAdd, Name: "olcLimits", Values: []string{override}}}); merr != nil {
		return nil, fmt.Errorf("grant temporary unlimited size on %s: %w", dbDN, merr)
	}

	// always restore; if the search succeeded but revert fails, surface it loudly
	// (the identity would otherwise stay unlimited).
	defer func() {
		if rerr := cfg.revertLimit(dbDN, had); rerr != nil && err == nil {
			err = fmt.Errorf("search succeeded but FAILED to restore the size limit on %s (identity %q left unlimited): %w", dbDN, c.cfg.BindDN, rerr)
		}
	}()

	return c.search(base, ldap.ScopeWholeSubtree, filter, attrs, bulkPageSize)
}

// revertLimit deletes every olcLimits value on dbDN that is absent from `had`
// (i.e. the override searchEscalated added), restoring the prior state.
func (c *Client) revertLimit(dbDN string, had map[string]bool) error {
	e, err := c.ReadEntry(dbDN, []string{"olcLimits"})
	if err != nil {
		return err
	}
	var mods []Mod
	for _, v := range e.GetAll("olcLimits") {
		if !had[v] {
			mods = append(mods, Mod{Op: ModDelete, Name: "olcLimits", Values: []string{v}})
		}
	}
	if len(mods) == 0 {
		return nil
	}
	return c.Modify(dbDN, mods)
}

// dataDatabaseDN finds the cn=config database entry whose olcSuffix matches base.
func (c *Client) dataDatabaseDN(base string) (string, error) {
	filter := fmt.Sprintf("(&(objectClass=olcDatabaseConfig)(olcSuffix=%s))", ldap.EscapeFilter(base))
	es, err := c.search("cn=config", ldap.ScopeWholeSubtree, filter, []string{"olcSuffix"}, 0)
	if err != nil {
		return "", fmt.Errorf("locate the data database for %q: %w", base, err)
	}
	if len(es) == 0 {
		return "", fmt.Errorf("no cn=config database has suffix %q", base)
	}
	return es[0].DN, nil
}
