// Package config loads connection + directory layout settings.
//
// Resolution order (last wins):
//  1. profile block in ~/.openldap-cli.yaml (or --config path)
//  2. environment variables (LDAP_*)
//
// Profile is chosen by: --profile flag > file `default:` key > "default".
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// Profile is one named target environment (dev / prod / ...).
type Profile struct {
	URL        string `yaml:"url"`         // ldaps://host:636 or ldap://host:389
	BaseDN     string `yaml:"base_dn"`     // dc=example,dc=org
	BindDN     string `yaml:"bind_dn"`     // cn=admin,dc=example,dc=org
	BindPW     string `yaml:"bind_pw"`     // prefer LDAP_BIND_PW over storing here
	UserOU     string `yaml:"user_ou"`     // ou=people
	GroupOU    string `yaml:"group_ou"`    // ou=groups
	PolicyOU   string `yaml:"policy_ou"`   // ou=policies (default)
	MailDomain string `yaml:"mail_domain"` // example.org
	StartTLS   bool   `yaml:"start_tls"`   // upgrade ldap:// to TLS
	Insecure   bool   `yaml:"insecure"`    // skip TLS cert verification (dev only)

	// Second bind for cn=config writes (ACL injection, overlays). Usually the
	// config rootDN, e.g. cn=adminconfig,cn=config.
	ConfigBindDN string `yaml:"config_bind_dn"`
	ConfigBindPW string `yaml:"config_bind_pw"`
}

type fileSchema struct {
	Default  string             `yaml:"default"`
	Profiles map[string]Profile `yaml:"profiles"`
}

// DefaultPath is ~/.openldap-cli.yaml.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".openldap-cli.yaml"
	}
	return filepath.Join(home, ".openldap-cli.yaml")
}

// Load reads the config file (if present), selects a profile, then applies
// LDAP_* env overrides. A missing file is not an error when env vars supply
// everything needed.
func Load(path, profile string) (*Profile, error) {
	if path == "" {
		path = DefaultPath()
	}

	var f fileSchema
	if raw, err := os.ReadFile(path); err == nil { // #nosec G304 -- path is the user's chosen config file
		if uerr := yaml.Unmarshal(raw, &f); uerr != nil {
			return nil, fmt.Errorf("parse %s: %w", path, uerr)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if profile == "" {
		if profile = f.Default; profile == "" {
			profile = "default"
		}
	}

	p := f.Profiles[profile] // zero value if absent; env may fill it
	applyEnv(&p)

	if p.URL == "" {
		return nil, fmt.Errorf("no LDAP url for profile %q (set it in %s or LDAP_URL)", profile, path)
	}
	if p.BaseDN == "" {
		return nil, fmt.Errorf("no base_dn for profile %q (set it in %s or LDAP_BASE_DN)", profile, path)
	}
	return &p, nil
}

// ReadProfiles returns all profiles in the file plus the current `default:`.
func ReadProfiles(path string) (profiles map[string]Profile, def string, err error) {
	if path == "" {
		path = DefaultPath()
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the user's chosen config file
	if err != nil {
		return nil, "", err
	}
	var f fileSchema
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, "", fmt.Errorf("parse %s: %w", path, err)
	}
	return f.Profiles, f.Default, nil
}

// ProfileNames returns the sorted profile names from the file.
func ProfileNames(path string) ([]string, string, error) {
	profiles, def, err := ReadProfiles(path)
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(profiles))
	for k := range profiles {
		names = append(names, k)
	}
	sort.Strings(names)
	return names, def, nil
}

// SetDefault persists the active profile by editing only the top-level
// `default:` line (comments and formatting elsewhere are preserved).
func SetDefault(path, name string) error {
	if path == "" {
		path = DefaultPath()
	}
	names, _, err := ProfileNames(path)
	if err != nil {
		return err
	}
	known := false
	for _, n := range names {
		if n == name {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("no profile %q in %s (have: %s)", name, path, strings.Join(names, ", "))
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the user's chosen config file
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	replaced := false
	for i, l := range lines {
		if strings.HasPrefix(l, "default:") {
			lines[i] = "default: " + name
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append([]string{"default: " + name}, lines...)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), info.Mode()) // #nosec G703,G304 -- writing the user's own config file
}

func applyEnv(p *Profile) {
	envStr(&p.URL, "LDAP_URL")
	envStr(&p.BaseDN, "LDAP_BASE_DN")
	envStr(&p.BindDN, "LDAP_BIND_DN")
	envStr(&p.BindPW, "LDAP_BIND_PW")
	envStr(&p.UserOU, "LDAP_USER_OU")
	envStr(&p.GroupOU, "LDAP_GROUP_OU")
	envStr(&p.PolicyOU, "LDAP_POLICY_OU")
	envStr(&p.MailDomain, "LDAP_MAIL_DOMAIN")
	envStr(&p.ConfigBindDN, "LDAP_CONFIG_BIND_DN")
	envStr(&p.ConfigBindPW, "LDAP_CONFIG_BIND_PW")
	envBool(&p.StartTLS, "LDAP_START_TLS")
	envBool(&p.Insecure, "LDAP_INSECURE")
}

func envStr(dst *string, key string) {
	if v, ok := os.LookupEnv(key); ok {
		*dst = v
	}
}

func envBool(dst *bool, key string) {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}
