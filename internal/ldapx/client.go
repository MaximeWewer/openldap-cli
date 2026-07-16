// Package ldapx wraps go-ldap/v3 behind a neutral façade so the rest of the
// app never imports the LDAP library directly.
package ldapx

import (
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/MaximeWewer/openldap-cli/internal/config"
)

// Client is a bound LDAP connection plus the profile it was opened with.
type Client struct {
	conn *ldap.Conn
	cfg  *config.Profile
}

// Connect dials, optionally StartTLS-upgrades, and binds.
func Connect(p *config.Profile) (*Client, error) {
	if p.URL == "" {
		return nil, errors.New("ldap url not set")
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: p.Insecure} // #nosec G402 -- opt-in dev flag (insecure: true / LDAP_INSECURE)

	conn, err := ldap.DialURL(p.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", p.URL, err)
	}
	if p.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	switch {
	case p.SASLExternal:
		// identity comes from the transport (ldapi peer creds / TLS client cert)
		if err := conn.ExternalBind(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("sasl external bind: %w", err)
		}
	case p.BindDN != "":
		if err := bindWithPolicy(conn, p.BindDN, p.BindPW); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("bind as %s: %w", p.BindDN, err)
		}
	}
	return &Client{conn: conn, cfg: p}, nil
}

// Config returns the profile this client is bound with.
func (c *Client) Config() *config.Profile { return c.cfg }

// Close tears down the connection.
func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// ---- mutations ----------------------------------------------------------

// AddEntry creates an entry with the given attributes.
func (c *Client) AddEntry(dn string, attrs map[string][]string) error {
	req := ldap.NewAddRequest(dn, nil)
	for name, vals := range attrs {
		req.Attribute(name, vals)
	}
	return c.conn.Add(req)
}

// AddEntryRelax creates an entry with the Relax Rules control, so the server
// accepts values a normal add would reject — notably a pre-hashed userPassword
// under a strict ppolicy (pwdCheckQuality) during a restore.
func (c *Client) AddEntryRelax(dn string, attrs map[string][]string) error {
	relax := ldap.NewControlString("1.3.6.1.4.1.4203.666.5.12", true, "")
	req := ldap.NewAddRequest(dn, []ldap.Control{relax})
	for name, vals := range attrs {
		req.Attribute(name, vals)
	}
	return c.conn.Add(req)
}

// Delete removes the entry at dn.
func (c *Client) Delete(dn string) error { return c.conn.Del(ldap.NewDelRequest(dn, nil)) }

// Modify applies the given modifications to dn.
func (c *Client) Modify(dn string, mods []Mod) error { return c.modify(dn, mods, nil) }

// ModifyRelax applies modifications with the Relax Rules control, allowing
// changes to no-user-modification operational attributes.
func (c *Client) ModifyRelax(dn string, mods []Mod) error {
	relax := ldap.NewControlString("1.3.6.1.4.1.4203.666.5.12", true, "")
	return c.modify(dn, mods, []ldap.Control{relax})
}

func (c *Client) modify(dn string, mods []Mod, controls []ldap.Control) error {
	req := ldap.NewModifyRequest(dn, controls)
	for _, m := range mods {
		switch m.Op {
		case ModAdd:
			req.Add(m.Name, m.Values)
		case ModReplace:
			req.Replace(m.Name, m.Values)
		case ModDelete:
			req.Delete(m.Name, m.Values)
		}
	}
	return c.conn.Modify(req)
}

// Rename runs a modrdn (rename and/or move) on dn.
func (c *Client) Rename(dn, newRDN string, deleteOld bool, newSuperior string) error {
	return c.conn.ModifyDN(ldap.NewModifyDNRequest(dn, newRDN, deleteOld, newSuperior))
}

// SetPassword runs the Password Modify extended op against dn. An empty newPw
// asks the server to generate one (returned). The ppolicy overlay hashes it.
func (c *Client) SetPassword(dn, newPw string) (string, error) {
	res, err := c.conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", newPw))
	if err != nil {
		return "", err
	}
	return res.GeneratedPassword, nil
}

// WhoAmI returns the authorization identity of the current bind.
func (c *Client) WhoAmI() (string, error) {
	res, err := c.conn.WhoAmI(nil)
	if err != nil {
		return "", err
	}
	return res.AuthzID, nil
}

// ---- searches -----------------------------------------------------------

func (c *Client) search(base string, scope int, filter string, attrs []string, pageSize uint32) ([]*Entry, error) {
	if filter == "" {
		filter = "(objectClass=*)"
	}
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	var res *ldap.SearchResult
	var err error
	if pageSize > 0 {
		res, err = c.conn.SearchWithPaging(req, pageSize)
	} else {
		res, err = c.conn.Search(req)
	}
	if err != nil {
		return nil, err
	}
	return newEntries(res.Entries), nil
}

// Search runs a subtree search.
func (c *Client) Search(base, filter string, attrs []string) ([]*Entry, error) {
	return c.search(base, ldap.ScopeWholeSubtree, filter, attrs, 0)
}

// SearchPaged runs a subtree search using Simple Paged Results, returning more
// entries than the server's size limit allows.
func (c *Client) SearchPaged(base, filter string, attrs []string, pageSize uint32) ([]*Entry, error) {
	return c.search(base, ldap.ScopeWholeSubtree, filter, attrs, pageSize)
}

// SearchScope runs a search with an explicit scope. Paged when pageSize > 0.
func (c *Client) SearchScope(base string, scope Scope, filter string, attrs []string, pageSize uint32) ([]*Entry, error) {
	return c.search(base, scope.ldap(), filter, attrs, pageSize)
}

// ReadEntry fetches a single entry by DN (base scope).
func (c *Client) ReadEntry(dn string, attrs []string) (*Entry, error) {
	es, err := c.search(dn, ldap.ScopeBaseObject, "(objectClass=*)", attrs, 0)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, fmt.Errorf("entry %q not found", dn)
	}
	return es[0], nil
}

// FindGroup locates a groupOfNames by cn under the group base.
func (c *Client) FindGroup(name string, attrs []string) (*Entry, error) {
	filter := fmt.Sprintf("(&(objectClass=groupOfNames)(cn=%s))", ldap.EscapeFilter(name))
	es, err := c.search(c.groupBase(), ldap.ScopeWholeSubtree, filter, attrs, 0)
	if err != nil {
		return nil, err
	}
	switch len(es) {
	case 0:
		return nil, fmt.Errorf("group %q not found under %s", name, c.groupBase())
	case 1:
		return es[0], nil
	default:
		return nil, fmt.Errorf("group %q is ambiguous (%d matches)", name, len(es))
	}
}

// FindUser locates a person by login, matching either uid or cn so it works
// regardless of which RDN attribute the entry uses (nil attrs = all).
func (c *Client) FindUser(login string, attrs []string) (*Entry, error) {
	filter := fmt.Sprintf("(&(objectClass=inetOrgPerson)(|(uid=%s)(cn=%s)))",
		ldap.EscapeFilter(login), ldap.EscapeFilter(login))
	es, err := c.search(c.userBase(), ldap.ScopeWholeSubtree, filter, attrs, 0)
	if err != nil {
		return nil, err
	}
	switch len(es) {
	case 0:
		return nil, fmt.Errorf("user %q not found under %s", login, c.userBase())
	case 1:
		return es[0], nil
	default:
		return nil, fmt.Errorf("user %q is ambiguous (%d matches)", login, len(es))
	}
}

// ---- bases --------------------------------------------------------------

// UserBase is <userOU>,<baseDN>. GroupBase is <groupOU>,<baseDN>.
func (c *Client) UserBase() string  { return c.userBase() }
func (c *Client) GroupBase() string { return c.groupBase() }

func (c *Client) userBase() string {
	if c.cfg.UserOU == "" {
		return c.cfg.BaseDN
	}
	return c.cfg.UserOU + "," + c.cfg.BaseDN
}

func (c *Client) groupBase() string {
	if c.cfg.GroupOU == "" {
		return c.cfg.BaseDN
	}
	return c.cfg.GroupOU + "," + c.cfg.BaseDN
}

// PolicyBase is <policyOU>,<baseDN>, defaulting policyOU to ou=policies.
func (c *Client) PolicyBase() string {
	ou := c.cfg.PolicyOU
	if ou == "" {
		ou = "ou=policies"
	}
	return ou + "," + c.cfg.BaseDN
}
