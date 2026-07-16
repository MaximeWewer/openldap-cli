package cli

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/config"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/output"
)

var (
	flagProfile   string
	flagConfig    string
	flagLogLevel  string
	flagLogFormat string
	flagOutput    string

	out *output.Writer // result writer, ready after PersistentPreRunE
)

// version is the CLI version, overridable at build time with:
//
//	-ldflags "-X github.com/MaximeWewer/openldap-cli/internal/cli.version=v1.2.3"
var version = "dev"

var rootCmd = &cobra.Command{
	Use:           "openldap-cli",
	Version:       version,
	Short:         "CLI for your OpenLDAP",
	Long:          "openldap-cli wraps your OpenLDAP admin operations behind typed, opinionated commands.",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := setupLogging(flagLogLevel, flagLogFormat); err != nil {
			return err
		}
		w, err := output.New(flagOutput, os.Stdout)
		if err != nil {
			return err
		}
		out = w
		return nil
	},
}

// Execute is the program entry point. Errors are printed as clean multi-line
// text in console mode (so cobra's "Did you mean" suggestions read naturally)
// and as structured records in json mode.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		err = explain(err) // add what the raw LDAP result code does not say
		if flagLogFormat == "json" {
			log.Error().Err(err).Msg("command failed")
		} else {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(1)
	}
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVarP(&flagProfile, "profile", "p", "", "config profile to use (default: file `default:` or \"default\")")
	pf.StringVarP(&flagConfig, "config", "c", "", "config file path (default: ~/.openldap-cli.yaml)")
	pf.StringVar(&flagLogLevel, "log-level", "info", "log level: trace|debug|info|warn|error")
	pf.StringVar(&flagLogFormat, "log-format", "console", "log format: console|json (logs -> stderr)")
	pf.StringVarP(&flagOutput, "output", "o", "text", "result format: text|json|yaml (results -> stdout)")
}

func setupLogging(level, format string) error {
	lvl, err := zerolog.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid --log-level %q", level)
	}
	zerolog.SetGlobalLevel(lvl)
	switch format {
	case "json":
		log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	case "console":
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	default:
		return fmt.Errorf("invalid --log-format %q (console|json)", format)
	}
	return nil
}

// loadConfig resolves the active profile (file + env override).
func loadConfig() (*config.Profile, error) {
	return config.Load(flagConfig, flagProfile)
}

// connect loads config and opens a bound LDAP client. Callers must Close it.
func connect() (*ldapx.Client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	log.Debug().Str("url", cfg.URL).Str("bind_dn", cfg.BindDN).Msg("connecting")
	return ldapx.Connect(cfg)
}

// searchAll runs a size-limit-transparent bulk subtree search. When the server
// caps the result and the limit is lifted via the config bind, it logs a
// warning so the (otherwise invisible) cn=config write is observable.
func searchAll(cli *ldapx.Client, base, filter string, attrs []string) ([]*ldapx.Entry, error) {
	entries, escalated, err := cli.SearchAll(base, filter, attrs)
	if escalated {
		log.Warn().Str("base", base).Int("entries", len(entries)).
			Msg("server size limit hit; temporarily lifted via the config bind to return all entries")
	}
	return entries, err
}

// connectConfig opens a second client bound as the config rootDN, for cn=config
// writes. Errors if config_bind_dn is not set.
func connectConfig() (*ldapx.Client, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	// With SASL EXTERNAL (e.g. root over ldapi://) the bound identity already
	// manages cn=config — no separate config bind DN is needed.
	if cfg.SASLExternal {
		log.Debug().Str("url", cfg.URL).Msg("connecting (config, sasl external)")
		return ldapx.Connect(cfg)
	}
	if cfg.ConfigBindDN == "" {
		return nil, fmt.Errorf("config_bind_dn not set (needed for cn=config writes; e.g. cn=adminconfig,cn=config)")
	}
	cc := *cfg
	cc.BindDN, cc.BindPW = cfg.ConfigBindDN, cfg.ConfigBindPW
	log.Debug().Str("url", cc.URL).Str("bind_dn", cc.BindDN).Msg("connecting (config)")
	return ldapx.Connect(&cc)
}
