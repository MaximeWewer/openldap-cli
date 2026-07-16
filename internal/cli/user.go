package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/domain"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/pwd"
)

// resolveMembers turns user logins into their real entry DNs.
func resolveMembers(cli *ldapx.Client, logins []string) ([]string, error) {
	dns := make([]string, 0, len(logins))
	for _, l := range logins {
		e, err := cli.FindUser(strings.ToLower(strings.TrimSpace(l)), []string{"uid"})
		if err != nil {
			return nil, err
		}
		dns = append(dns, e.DN)
	}
	return dns, nil
}

// okResult is a generic "<verb> <dn>" stdout payload. Password, when set,
// carries a generated secret as its own field (so `-o json | jq -r .password`
// extracts it cleanly) rather than being buried in Detail.
type okResult struct {
	Action   string `json:"action" yaml:"action"`
	DN       string `json:"dn" yaml:"dn"`
	Detail   string `json:"detail,omitempty" yaml:"detail,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

func (r okResult) Text() string {
	s := fmt.Sprintf("%s %s", r.Action, r.DN)
	if r.Detail != "" {
		s += "\n  " + r.Detail
	}
	if r.Password != "" {
		s += "\n  generated: " + r.Password
	}
	return s
}

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user accounts",
}

// ---- add ----------------------------------------------------------------

var (
	userAddPassword   string
	userAddNoPassword bool
	userAddPosix      bool
	userAddUIDNumber  int
	userAddGIDNumber  int
	userAddHome       string
	userAddShell      string
	userAddSet        []string
)

// requirePosixSchema fails early when the server has no posixAccount.
//
// posixAccount and its attributes ship with the `nis` schema, which OpenLDAP
// does not load by default. Without it, --posix fails on whichever piece slapd
// checks first — observed: `Undefined Attribute Type: homeDirectory: attribute
// type undefined` — naming a symptom rather than the missing schema. We probe
// the objectClass because that is what --posix is really asking for; nis is
// all-or-nothing, so its presence stands for the attributes too.
//
// Unlike an overlay module, slapd has no way to load a schema by name (it even
// refuses to delete one at runtime), so this can only be reported, not repaired.
//
// A schema we cannot read is not treated as missing — that would block --posix
// on a server that supports it perfectly well.
func requirePosixSchema(cli *ldapx.Client) error {
	ok, err := cli.HasObjectClass("posixAccount")
	if err != nil {
		log.Debug().Err(err).Msg("could not read the subschema to check for posixAccount")
		return nil
	}
	if !ok {
		return fmt.Errorf("--posix needs the objectClass posixAccount, which this server's schema does not have: " +
			"load the `nis` schema (it ships with OpenLDAP as schema/nis.ldif) and retry — " +
			"`schema list-classes` shows what the server knows")
	}
	return nil
}

var userAddCmd = &cobra.Command{
	Use:   "add <login>",
	Short: "Create a user (firstname.lastname derives names; a plain login also works)",
	Args:  cobra.ExactArgs(1),
	Example: "  openldap-cli user add toto.titi                       # derives givenName/sn/displayName\n" +
		"  openldap-cli user add demo1                          # plain login: uid/cn/sn=demo1\n" +
		"  openldap-cli user add toto.titi --posix              # + posixAccount\n" +
		"  openldap-cli user add toto.titi --set title=Engineer --no-password",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		u, err := domain.ParseUser(args[0], cfg.MailDomain)
		if err != nil {
			return err
		}

		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		var posix *domain.Posix
		if userAddPosix {
			if serr := requirePosixSchema(cli); serr != nil {
				return serr
			}
			uidNum := userAddUIDNumber
			if uidNum == 0 {
				if uidNum, err = nextUIDNumber(cli); err != nil {
					return err
				}
			}
			posix = &domain.Posix{UIDNumber: uidNum, GIDNumber: userAddGIDNumber, Home: userAddHome, Shell: userAddShell}
		}

		// password: explicit, none, or generated (default).
		password, generated := userAddPassword, false
		if !userAddNoPassword && password == "" {
			// size the generated password to the effective policy (the user does
			// not exist yet, so this resolves the default pwdMinLength).
			if password, err = pwd.Strong(genLength(cli, "")); err != nil {
				return err
			}
			generated = true
		}

		// merge derived attrs with --set, validating against the schema.
		vals := u.AttributeMap(password, posix)
		var warnings []string
		schema, serr := cli.AttributeTypeNames()
		if serr != nil {
			warnings = append(warnings, "schema validation skipped: "+serr.Error())
		}
		overridden := map[string]bool{}
		for _, kv := range userAddSet {
			name, val, ok := strings.Cut(kv, "=")
			if !ok || name == "" {
				return fmt.Errorf("--set expects name=value, got %q", kv)
			}
			if schema != nil && !schema[strings.ToLower(name)] {
				warnings = append(warnings, fmt.Sprintf("attribute %q not in schema — skipped", name))
				continue
			}
			if !overridden[name] { // first --set for a name replaces any derived value
				vals[name] = nil
				overridden[name] = true
			}
			vals[name] = append(vals[name], val)
		}

		dn := u.DN(cfg.UserOU, cfg.BaseDN)
		if err := cli.AddEntry(dn, vals); err != nil {
			return fmt.Errorf("create %s: %w", u.UID, err)
		}
		log.Debug().Str("dn", dn).Msg("user created")

		res := userResult{DN: dn, UID: u.UID, CN: u.CN, DisplayName: u.DisplayName, Mail: u.Mail, Warnings: warnings}
		if posix != nil {
			res.UIDNumber = posix.UIDNumber
		}
		if generated {
			res.Password = password
		}
		return out.Emit(res)
	},
}

// nextUIDNumber returns max(existing posixAccount uidNumber, 9999) + 1.
func nextUIDNumber(cli *ldapx.Client) (int, error) {
	es, err := cli.Search(cli.UserBase(), "(objectClass=posixAccount)", []string{"uidNumber"})
	if err != nil {
		return 0, fmt.Errorf("scan uidNumber: %w", err)
	}
	maxUID := 9999
	for _, e := range es {
		if n, _ := strconv.Atoi(e.Get("uidNumber")); n > maxUID {
			maxUID = n
		}
	}
	return maxUID + 1, nil
}

type userResult struct {
	DN          string   `json:"dn" yaml:"dn"`
	UID         string   `json:"uid" yaml:"uid"`
	CN          string   `json:"cn" yaml:"cn"`
	DisplayName string   `json:"displayName,omitempty" yaml:"displayName,omitempty"`
	Mail        string   `json:"mail,omitempty" yaml:"mail,omitempty"`
	UIDNumber   int      `json:"uidNumber,omitempty" yaml:"uidNumber,omitempty"`
	Password    string   `json:"password,omitempty" yaml:"password,omitempty"`
	Warnings    []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

func (r userResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "created %s", r.DN)
	if r.Mail != "" {
		fmt.Fprintf(&b, "\n  mail: %s", r.Mail)
	}
	if r.UIDNumber > 0 {
		fmt.Fprintf(&b, "\n  uidNumber: %d", r.UIDNumber)
	}
	if r.Password != "" {
		fmt.Fprintf(&b, "\n  password: %s", r.Password)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\n  ! %s", w)
	}
	return b.String()
}

func init() {
	userAddCmd.Flags().StringVar(&userAddPassword, "password", "", "set initial userPassword (default: generate a strong one)")
	userAddCmd.Flags().BoolVar(&userAddNoPassword, "no-password", false, "create without a password (no auto-generation)")
	userAddCmd.Flags().StringArrayVar(&userAddSet, "set", nil, "extra attribute name=value (repeatable; unknown attrs are warned and skipped)")
	userAddCmd.Flags().BoolVar(&userAddPosix, "posix", false, "also make the user a posixAccount")
	userAddCmd.Flags().IntVar(&userAddUIDNumber, "uid-number", 0, "posix uidNumber (0 = auto: max+1)")
	userAddCmd.Flags().IntVar(&userAddGIDNumber, "gid-number", 10000, "posix gidNumber")
	userAddCmd.Flags().StringVar(&userAddHome, "home", "", "posix homeDirectory (default /home/<login>)")
	userAddCmd.Flags().StringVar(&userAddShell, "shell", "/bin/bash", "posix loginShell")
	userCmd.AddCommand(userAddCmd)
	rootCmd.AddCommand(userCmd)
}
