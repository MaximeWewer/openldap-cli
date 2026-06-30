package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/config"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "List, show, or switch config profiles",
}

// configPath resolves the config file the same way loadConfig does.
func configPath() string {
	if flagConfig != "" {
		return flagConfig
	}
	return config.DefaultPath()
}

// ---- list ---------------------------------------------------------------

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List profiles (the default is marked *)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles, def, err := config.ReadProfiles(configPath())
		if err != nil {
			return err
		}
		res := profileListResult{Default: def}
		for name, p := range profiles {
			res.Profiles = append(res.Profiles, profileEntry{Name: name, URL: p.URL, Default: name == def})
		}
		sortProfiles(res.Profiles)
		return out.Emit(res)
	},
}

// ---- current ------------------------------------------------------------

var profileCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the active profile (passwords masked)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		name := flagProfile
		if name == "" {
			if _, def, derr := config.ProfileNames(configPath()); derr == nil {
				name = def
			}
		}
		return out.Emit(currentProfileResult{
			Name: name, URL: cfg.URL, BaseDN: cfg.BaseDN, BindDN: cfg.BindDN,
			UserOU: cfg.UserOU, GroupOU: cfg.GroupOU, PolicyOU: cfg.PolicyOU,
			ConfigBindDN: cfg.ConfigBindDN, BindPW: mask(cfg.BindPW),
		})
	},
}

// ---- use ----------------------------------------------------------------

var profileUseCmd = &cobra.Command{
	Use:   "use <name>",
	Short: "Persist the default profile (edits the `default:` key)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.TrimSpace(args[0])
		if err := config.SetDefault(configPath(), name); err != nil {
			return err
		}
		log.Debug().Str("profile", name).Str("file", configPath()).Msg("default profile set")
		return out.Emit(okResult{Action: "default profile set to", DN: name})
	},
}

// ---- renderers ----------------------------------------------------------

func mask(s string) string {
	if s == "" {
		return ""
	}
	return "********"
}

type profileEntry struct {
	Name    string `json:"name" yaml:"name"`
	URL     string `json:"url" yaml:"url"`
	Default bool   `json:"default" yaml:"default"`
}

func sortProfiles(p []profileEntry) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Name < p[j-1].Name; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

type profileListResult struct {
	Default  string         `json:"default" yaml:"default"`
	Profiles []profileEntry `json:"profiles" yaml:"profiles"`
}

func (r profileListResult) Text() string {
	if len(r.Profiles) == 0 {
		return "no profiles"
	}
	var b strings.Builder
	for _, p := range r.Profiles {
		mark := " "
		if p.Default {
			mark = "*"
		}
		fmt.Fprintf(&b, "%s %-12s %s\n", mark, p.Name, p.URL)
	}
	return strings.TrimRight(b.String(), "\n")
}

type currentProfileResult struct {
	Name         string `json:"name" yaml:"name"`
	URL          string `json:"url" yaml:"url"`
	BaseDN       string `json:"baseDN" yaml:"baseDN"`
	BindDN       string `json:"bindDN" yaml:"bindDN"`
	BindPW       string `json:"bindPw,omitempty" yaml:"bindPw,omitempty"`
	UserOU       string `json:"userOU,omitempty" yaml:"userOU,omitempty"`
	GroupOU      string `json:"groupOU,omitempty" yaml:"groupOU,omitempty"`
	PolicyOU     string `json:"policyOU,omitempty" yaml:"policyOU,omitempty"`
	ConfigBindDN string `json:"configBindDN,omitempty" yaml:"configBindDN,omitempty"`
}

func (r currentProfileResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "profile: %s\n", r.Name)
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %-14s %s\n", k+":", v)
		}
	}
	line("url", r.URL)
	line("base_dn", r.BaseDN)
	line("bind_dn", r.BindDN)
	line("bind_pw", r.BindPW)
	line("user_ou", r.UserOU)
	line("group_ou", r.GroupOU)
	line("policy_ou", r.PolicyOU)
	line("config_bind_dn", r.ConfigBindDN)
	return strings.TrimRight(b.String(), "\n")
}

func init() {
	profileCmd.AddCommand(profileListCmd, profileCurrentCmd, profileUseCmd)
	rootCmd.AddCommand(profileCmd)
}
