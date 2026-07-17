package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/acl"
	"github.com/MaximeWewer/openldap-cli/internal/humanize"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
	"github.com/MaximeWewer/openldap-cli/internal/overlay"
)

// overlayList renders `config overlay list`, marking the ones turned off.
type overlayList struct {
	Overlays []overlayItem `json:"overlays" yaml:"overlays"`
}

type overlayItem struct {
	Name     string `json:"name" yaml:"name"`
	DN       string `json:"dn" yaml:"dn"`
	Disabled bool   `json:"disabled" yaml:"disabled"`
}

func (l overlayList) Text() string {
	if len(l.Overlays) == 0 {
		return "no overlays configured"
	}
	var b strings.Builder
	for _, o := range l.Overlays {
		state := "active"
		if o.Disabled {
			state = "DISABLED"
		}
		fmt.Fprintf(&b, "%-12s %-8s %s\n", o.Name, state, o.DN)
	}
	fmt.Fprintf(&b, "(%d overlays)", len(l.Overlays))
	return b.String()
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Inspect/modify cn=config (limits, databases, overlays, ACLs)",
	Long:  "Reads and writes the dynamic configuration. Needs the config bind\n(config_bind_dn, e.g. cn=adminconfig,cn=config).",
}

// ---- limits -------------------------------------------------------------

var configLimitsCmd = &cobra.Command{Use: "limits", Short: "Show or set search limits"}

var limitsDB string

var configLimitsGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show olcSizeLimit / olcTimeLimit / olcLimits on a database",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		e, err := cc.ReadEntry(limitsDB, []string{"olcSizeLimit", "olcTimeLimit", "olcLimits"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

var (
	limitsSize string
	limitsTime string
	limitsFor  string
)

var configLimitsSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set global size/time limits, or a per-identity olcLimits with --for",
	Long: "Without --for: replaces the database's global olcSizeLimit/olcTimeLimit.\n" +
		"With --for <selector>: adds an olcLimits rule for that identity (e.g.\n" +
		"--for 'dn.exact=cn=admin,ou=users,dc=example,dc=org' --size unlimited).",
	Args: cobra.NoArgs,
	Example: "  openldap-cli --profile test config limits set --size 5000\n" +
		"  openldap-cli --profile test config limits set --for 'dn.exact=cn=admin,ou=users,dc=example,dc=org' --size unlimited --db 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		if limitsSize == "" && limitsTime == "" {
			return fmt.Errorf("pass --size and/or --time")
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		var mods []ldapx.Mod
		var detail string
		if limitsFor != "" {
			val := limitsFor
			if limitsSize != "" {
				val += " size=" + limitsSize
			}
			if limitsTime != "" {
				val += " time=" + limitsTime
			}
			mods = append(mods, ldapx.Mod{Op: ldapx.ModAdd, Name: "olcLimits", Values: []string{val}})
			detail = "olcLimits += " + val
		} else {
			if limitsSize != "" {
				mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "olcSizeLimit", Values: []string{limitsSize}})
			}
			if limitsTime != "" {
				mods = append(mods, ldapx.Mod{Op: ldapx.ModReplace, Name: "olcTimeLimit", Values: []string{limitsTime}})
			}
			detail = fmt.Sprintf("size=%s time=%s", limitsSize, limitsTime)
		}
		if err := cc.Modify(limitsDB, mods); err != nil {
			return fmt.Errorf("set limits on %s: %w", limitsDB, err)
		}
		log.Debug().Str("db", limitsDB).Msg("limits updated")
		return out.Emit(okResult{Action: "limits set", DN: limitsDB, Detail: detail})
	},
}

// ---- db / overlay / acl introspection -----------------------------------

var configDBCmd = &cobra.Command{Use: "db", Short: "Databases"}

var configDBListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured databases (olcDatabase + suffix)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		entries, err := cc.Search("cn=config", "(objectClass=olcDatabaseConfig)",
			[]string{"olcDatabase", "olcSuffix"})
		if err != nil {
			return err
		}
		return out.Emit(toEntryList(entries))
	},
}

var configDBResizeCmd = &cobra.Command{
	Use:   "resize <database-dn> <size>",
	Short: "Set olcDbMaxSize on an mdb database (accepts 4GiB, 512MiB, or raw bytes)",
	Long: "Sets olcDbMaxSize (the LMDB map size). <size> takes a human value\n" +
		"(4GiB, 512MiB, 2G) or a plain byte count. Grow only — LMDB cannot shrink\n" +
		"below the data in use.\n\n" +
		"WARNING: changing olcDbMaxSize remaps the LMDB env. On a live, busy server\n" +
		"this can briefly interrupt or even restart slapd (the remap races with\n" +
		"active transactions). The change is persisted to cn=config and applied\n" +
		"regardless — prefer a quiet window.",
	Args:    cobra.ExactArgs(2),
	Example: "  openldap-cli config db resize 'olcDatabase={1}mdb,cn=config' 4GiB",
	RunE: func(cmd *cobra.Command, args []string) error {
		size, err := humanize.ParseBytes(args[1])
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		dn := strings.TrimSpace(args[0])

		// olcDbMaxSize remaps the LMDB env; on a busy server this can briefly
		// interrupt or restart slapd. The change still persists either way.
		log.Warn().Str("dn", dn).Msg("resizing olcDbMaxSize remaps the LMDB env and may briefly interrupt or restart slapd under load; the new size is persisted")

		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: "olcDbMaxSize", Values: []string{strconv.FormatInt(size, 10)}}
		if err := cc.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("resize %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Int64("bytes", size).Msg("olcDbMaxSize updated")
		return out.Emit(okResult{Action: "olcDbMaxSize set to " + humanize.Bytes(size) + " on", DN: dn})
	},
}

var configOverlayCmd = &cobra.Command{Use: "overlay", Short: "Overlays"}

var configOverlayListCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured overlays and whether each one is active",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		entries, err := cc.Search("cn=config", "(objectClass=olcOverlayConfig)", []string{"olcOverlay", "olcDisabled"})
		if err != nil {
			return err
		}
		res := overlayList{}
		for _, e := range entries {
			res.Overlays = append(res.Overlays, overlayItem{
				Name:     overlay.Name(e.Get("olcOverlay")),
				DN:       e.DN,
				Disabled: strings.EqualFold(e.Get("olcDisabled"), "TRUE"),
			})
		}
		return out.Emit(res)
	},
}

// ---- overlay enable/disable ---------------------------------------------

var (
	overlayDB       string
	overlayNoModule bool
	overlayPurge    bool
)

// overlayDatabaseDN resolves --db, defaulting to the database holding base_dn.
func overlayDatabaseDN(cc *ldapx.Client) (string, error) {
	if db := strings.TrimSpace(overlayDB); db != "" {
		return db, nil
	}
	base := cc.Config().BaseDN
	if base == "" {
		return "", fmt.Errorf("no base_dn in the profile: pass --db <database-dn> (see `config db list`)")
	}
	return cc.DataDatabaseDN(base)
}

var configOverlayEnableCmd = &cobra.Command{
	Use:   "enable <name>",
	Short: "Enable an overlay on a database, loading its module if needed",
	Long: "Adds the overlay entry under the database (memberof, refint, ppolicy,\n" +
		"accesslog, unique, …). An overlay entry is only valid once its module is\n" +
		"loaded — otherwise slapd rejects it with the opaque `objectClass: value #1\n" +
		"invalid per syntax` — so the module is loaded first when missing, and the\n" +
		"overlay's config objectClass is read back from the server's schema rather\n" +
		"than guessed.\n\n" +
		"Re-running is a no-op, and an overlay previously turned off with `disable`\n" +
		"is switched back on with its settings intact.\n\n" +
		"Loading a module is one-way: slapd refuses to unload one until restart.",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config overlay enable memberof\n  openldap-cli config overlay enable unique --db 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.ToLower(strings.TrimSpace(args[0]))
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		db, err := overlayDatabaseDN(cc)
		if err != nil {
			return err
		}
		st, err := cc.EnableOverlay(db, name, !overlayNoModule)
		if err != nil {
			return err
		}
		if st.Module != "" {
			log.Info().Str("module", st.Module).Msg("module loaded (stays loaded until slapd restarts)")
		}
		log.Debug().Str("db", db).Str("overlay", name).Str("action", st.Action).Msg("overlay enable")
		return out.Emit(okResult{Action: "overlay " + name + " " + st.Action + ":", DN: st.DN})
	},
}

var configOverlayDisableCmd = &cobra.Command{
	Use:   "disable <name>",
	Short: "Disable an overlay (olcDisabled: TRUE), keeping its configuration",
	Long: "Stops the overlay at runtime by setting olcDisabled: TRUE, keeping its\n" +
		"entry and settings so `enable` restores them. Use --purge to delete the\n" +
		"entry and its settings instead.\n\n" +
		"The overlay's module stays loaded either way: slapd rejects deleting an\n" +
		"olcModuleLoad value. That is harmless — an unused module does nothing.",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config overlay disable ppolicy\n  openldap-cli config overlay disable unique --purge",
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.ToLower(strings.TrimSpace(args[0]))
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		db, err := overlayDatabaseDN(cc)
		if err != nil {
			return err
		}
		st, err := cc.DisableOverlay(db, name, overlayPurge)
		if err != nil {
			return err
		}
		if st.Action == "unchanged" && st.DN == "" {
			return fmt.Errorf("overlay %q is not configured on %s", name, db)
		}
		log.Debug().Str("db", db).Str("overlay", name).Str("action", st.Action).Msg("overlay disable")
		return out.Emit(okResult{Action: "overlay " + name + " " + st.Action + ":", DN: st.DN})
	},
}

var configACLCmd = &cobra.Command{Use: "acl", Short: "Access control"}

var configACLListCmd = &cobra.Command{
	Use:     "list <database-dn>",
	Short:   "List olcAccess rules on a database",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config acl list 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		e, err := cc.ReadEntry(strings.TrimSpace(args[0]), []string{"olcAccess"})
		if err != nil {
			return err
		}
		return out.Emit(newEntryResult(e))
	},
}

var aclMoveForce bool

// moveRefusal spells out what a move would change, so the operator can decide
// rather than discover it from a ticket weeks later.
func moveRefusal(from, to int, m acl.Impact) string {
	var b strings.Builder
	fmt.Fprintf(&b, "moving {%d} to {%d} would silently change access:\n", from, to)
	fmt.Fprintf(&b, "\n  the rule being moved:\n    %s\n", m.Rule)
	if len(m.Lost) > 0 {
		fmt.Fprintf(&b, "\n  it does not end in `by * break`, so on the entries it covers it now\n"+
			"  answers instead of this rule:\n    %s\n", m.Decided)
		b.WriteString("\n  these clauses stop applying there (their identities lose that access,\n" +
			"  and see noSuchObject rather than an error):\n")
		for _, c := range m.Lost {
			fmt.Fprintf(&b, "    %s\n", c)
		}
		b.WriteString("\n  to keep them, add `by * break` to the moved rule (`config set`) first.\n")
	}
	for _, f := range m.Dead {
		fmt.Fprintf(&b, "\n  this rule becomes unreachable, granting nothing:\n    {%d} %s\n    %s\n", f.Index, f.Rule, f.Message)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- acl delete ---------------------------------------------------------

var aclDeleteForce bool

// deleteRefusal spells out what removing a live rule would change.
func deleteRefusal(index int, m acl.Impact) string {
	var b strings.Builder
	fmt.Fprintf(&b, "deleting {%d} would silently change access:\n", index)
	fmt.Fprintf(&b, "\n  the rule being deleted:\n    %s\n", m.Rule)
	if len(m.Lost) > 0 {
		fmt.Fprintf(&b, "\n  it answers for those entries today; without it this rule does:\n    %s\n",
			cmp(m.Now, "(none — no rule below covers them, so access there falls back to denied)"))
		b.WriteString("\n  these clauses stop applying (their identities lose that access, and see\n" +
			"  noSuchObject rather than an error):\n")
		for _, c := range m.Lost {
			fmt.Fprintf(&b, "    %s\n", c)
		}
	}
	for _, f := range m.Dead {
		fmt.Fprintf(&b, "\n  this rule becomes unreachable, granting nothing:\n    {%d} %s\n    %s\n", f.Index, f.Rule, f.Message)
	}
	return strings.TrimRight(b.String(), "\n")
}

// cmp returns s, or alt when s is empty.
func cmp(s, alt string) string {
	if strings.TrimSpace(s) == "" {
		return alt
	}
	return s
}

var configACLDeleteCmd = &cobra.Command{
	Use:     "delete <database-dn> <index>",
	Aliases: []string{"del", "rm"},
	Short:   "Delete the olcAccess rule at {index}",
	Long: "Removes one rule, by the exact value the server holds — olcAccess is\n" +
		"ordered, so deleting renumbers every rule below it and a delete by index\n" +
		"alone would race with that. The other rules are left untouched (no\n" +
		"whole-attribute rewrite).\n\n" +
		"Removing a rule that never fires — one `config acl lint` reports as dead —\n" +
		"changes nothing and is the point of this command: `acl revoke` deliberately\n" +
		"keeps a `by * none`, so a dead rule has no other way out.\n\n" +
		"Deleting a LIVE rule hands its entries to whatever rule sits below, which\n" +
		"changes who has access; that is refused, with the clauses it would drop\n" +
		"named. --force does it anyway.",
	Args: cobra.ExactArgs(2),
	Example: "  openldap-cli config acl lint 'olcDatabase={1}mdb,cn=config'   # find the dead rule\n" +
		"  openldap-cli config acl delete 'olcDatabase={1}mdb,cn=config' 11",
	RunE: func(cmd *cobra.Command, args []string) error {
		db := strings.TrimSpace(args[0])
		index, err := strconv.Atoi(strings.Trim(args[1], "{}"))
		if err != nil {
			return fmt.Errorf("index %q: not a number", args[1])
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		e, err := cc.ReadEntry(db, []string{"olcAccess"})
		if err != nil {
			return err
		}
		value, impact, err := acl.InspectDelete(e.GetAll("olcAccess"), index)
		if err != nil {
			return err
		}
		if !impact.Empty() && !aclDeleteForce {
			return fmt.Errorf("%s\n\nre-run with --force to do it anyway", deleteRefusal(index, impact))
		}
		if !impact.Empty() {
			log.Warn().Int("rule", index).Msg("--force: deleting a rule that changes access\n" + deleteRefusal(index, impact))
		}
		// delete the exact stored value: surgical, and the server renumbers
		if err := cc.Modify(db, []ldapx.Mod{{Op: ldapx.ModDelete, Name: "olcAccess", Values: []string{value}}}); err != nil {
			return fmt.Errorf("delete olcAccess {%d} on %s: %w", index, db, err)
		}
		log.Debug().Str("db", db).Int("index", index).Msg("olcAccess rule deleted")
		return out.Emit(okResult{Action: fmt.Sprintf("deleted olcAccess {%d} on", index), DN: db, Detail: value})
	},
}

var configACLMoveCmd = &cobra.Command{
	Use:   "move <database-dn> <from> <to>",
	Short: "Reorder an olcAccess rule (move rule {from} to position {to})",
	Long: "olcAccess is evaluated in index order and STOPS at the first rule whose\n" +
		"`to` target matches, so a specific rule placed below a broad one never\n" +
		"fires. This moves rule {from} to position {to} and renumbers the rest in\n" +
		"one atomic replace.\n\n" +
		"Reordering decides WHICH rule answers for an entry, so the move is checked\n" +
		"first and refused when it would silently change access: raising a rule that\n" +
		"does not end in `by * break` above a broader one takes that rule's grantees\n" +
		"off the entries covered (they get no error — just noSuchObject), and moving\n" +
		"a rule under a broader one makes it unreachable. The refusal names exactly\n" +
		"which clauses stop applying; --force does it anyway.\n\n" +
		"To raise a rule without taking anyone's access, give it a `by * break` (or\n" +
		"the needed `by …` clauses) first — edit it with `config set`.",
	Args: cobra.ExactArgs(3),
	Example: "  # raise a specific rule above the broad ou=groups rule that shadows it\n" +
		"  openldap-cli config acl move 'olcDatabase={1}mdb,cn=config' 8 5",
	RunE: func(cmd *cobra.Command, args []string) error {
		from, err := strconv.Atoi(strings.Trim(args[1], "{}"))
		if err != nil {
			return fmt.Errorf("from index %q: not a number", args[1])
		}
		to, err := strconv.Atoi(strings.Trim(args[2], "{}"))
		if err != nil {
			return fmt.Errorf("to index %q: not a number", args[2])
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		dn := strings.TrimSpace(args[0])
		e, err := cc.ReadEntry(dn, []string{"olcAccess"})
		if err != nil {
			return err
		}
		reordered, impact, err := acl.InspectMove(e.GetAll("olcAccess"), from, to)
		if err != nil {
			return err
		}
		if !impact.Empty() && !aclMoveForce {
			return fmt.Errorf("%s\n\nre-run with --force to do it anyway", moveRefusal(from, to, impact))
		}
		if !impact.Empty() {
			log.Warn().Int("from", from).Int("to", to).Msg("--force: applying a move that changes access\n" + moveRefusal(from, to, impact))
		}
		if err := cc.Modify(dn, []ldapx.Mod{{Op: ldapx.ModReplace, Name: "olcAccess", Values: reordered}}); err != nil {
			return fmt.Errorf("reorder olcAccess on %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Int("from", from).Int("to", to).Msg("olcAccess reordered")
		return out.Emit(okResult{Action: fmt.Sprintf("moved olcAccess {%d} to {%d} on", from, to), DN: dn})
	},
}

// ---- lint (dead / empty olcAccess rules) --------------------------------

type aclFinding struct {
	Index   int    `json:"index" yaml:"index"`
	Level   string `json:"level" yaml:"level"`
	Message string `json:"message" yaml:"message"`
	Rule    string `json:"rule" yaml:"rule"`
}

type aclLintResult struct {
	DN       string       `json:"dn" yaml:"dn"`
	Checked  int          `json:"checked" yaml:"checked"`
	Findings []aclFinding `json:"findings" yaml:"findings"`
}

func (r aclLintResult) Text() string {
	if len(r.Findings) == 0 {
		return fmt.Sprintf("%d rule(s) checked on %s — no dead or empty rules", r.Checked, r.DN)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d rule(s) checked on %s — %d finding(s)\n", r.Checked, r.DN, len(r.Findings))
	for _, f := range r.Findings {
		rule := f.Rule
		if len(rule) > 90 {
			rule = rule[:90] + "…"
		}
		fmt.Fprintf(&b, "  [%s] {%d} %s\n        %s\n", f.Level, f.Index, f.Message, rule)
	}
	return strings.TrimRight(b.String(), "\n")
}

var configACLLintCmd = &cobra.Command{
	Use:   "lint <database-dn>",
	Short: "Report olcAccess rules that can never fire (shadowed) or grant nothing",
	Long: "slapd stops at the FIRST rule whose `to` matches, so a specific rule placed\n" +
		"below a broader one never fires: the grant looks present but has no effect\n" +
		"(and clients see noSuchObject when disclose is denied). Fix a dead rule by\n" +
		"raising it with `config acl move`, or give the shadowing rule a `by * break`.",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config acl lint 'olcDatabase={1}mdb,cn=config'",
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		dn := strings.TrimSpace(args[0])
		e, err := cc.ReadEntry(dn, []string{"olcAccess"})
		if err != nil {
			return err
		}
		rules := e.GetAll("olcAccess")
		res := aclLintResult{DN: dn, Checked: len(rules)}
		for _, f := range acl.Lint(rules) {
			res.Findings = append(res.Findings, aclFinding{Index: f.Index, Level: f.Level, Message: f.Message, Rule: f.Rule})
		}
		log.Debug().Str("db", dn).Int("findings", len(res.Findings)).Msg("olcAccess lint")
		return out.Emit(res)
	},
}

// ---- grant / revoke (olcAccess by-clause on a subtree) ------------------

var (
	aclGrantGroup  string
	aclGrantDN     string
	aclGrantAccess string
	aclGrantScope  string
	aclGrantFilter string
	aclGrantAt     int
	aclGrantTerm   string
	aclRevokeGroup string
	aclRevokeDN    string
)

// validAccess reports whether a is a recognized olcAccess level.
func validAccess(a string) bool {
	switch a {
	case "none", "disclose", "auth", "compare", "search", "read", "write", "manage":
		return true
	}
	return false
}

// aclWho resolves a --group/--dn pair to an olcAccess who-token. A --group value
// containing "=" is used as a DN as-is; otherwise it is resolved by name under
// the group OU (via the data bind).
func aclWho(group, dn string) (string, error) {
	if (group == "") == (dn == "") {
		return "", fmt.Errorf("pass exactly one of --group or --dn")
	}
	if dn != "" {
		return acl.DNWho(strings.TrimSpace(dn)), nil
	}
	g := strings.TrimSpace(group)
	if !strings.Contains(g, "=") { // a bare name -> resolve to its DN
		cli, err := connect()
		if err != nil {
			return "", err
		}
		defer cli.Close()
		e, ferr := cli.FindGroup(g, []string{"cn"})
		if ferr != nil {
			return "", ferr
		}
		g = e.DN
	}
	return acl.GroupWho(g), nil
}

// warnIfGrantUnreachable checks, after the write, that the rule carrying the new
// clause is one slapd can actually reach.
//
// Placement fixes the rule we create; it cannot fix a clause added to an
// EXISTING rule that a broader one already shadows, nor an --at the caller got
// wrong. Both grant nothing, silently — so re-read and say so rather than let
// `granted` stand for a rule that never fires.
func warnIfGrantUnreachable(cc *ldapx.Client, db string, o acl.InjectOpts) {
	e, err := cc.ReadEntry(db, []string{"olcAccess"})
	if err != nil {
		return // the grant succeeded; a failed re-read is not worth an error
	}
	values := e.GetAll("olcAccess")
	at := acl.RuleIndex(values, o)
	shadow := acl.ShadowIndex(values, o)
	if at < 0 || shadow < 0 || at <= shadow {
		return
	}
	log.Warn().Int("rule", at).Int("shadowed_by", shadow).
		Msg("the clause landed in a rule that an earlier one shadows, so it grants nothing — `config acl lint` explains it; `config acl move` raises it")
}

var configACLGrantCmd = &cobra.Command{
	Use:   "grant <database-dn> <subtree> --access <a> (--group <g> | --dn <d>)",
	Short: "Add a `by <who> <access>` clause to the rule protecting <subtree>",
	Long: "Grants access on <target> to a group (--group, all its members share the\n" +
		"right) or a single DN (--dn). The clause is inserted into the EXISTING rule\n" +
		"with the same selector, so multiple grantees coexist; a second rule with the\n" +
		"same `to` would be dead.\n\n" +
		"A NEW rule is placed ABOVE the rule that would otherwise shadow it, because\n" +
		"slapd stops at the first rule whose `to` matches: appended at the end, under\n" +
		"a broader rule that never breaks, it would grant nothing. --at overrides the\n" +
		"placement; either way the result is checked and a grant that cannot fire is\n" +
		"reported.\n\n" +
		"An app that must SEARCH a tree usually needs two grants: --scope base on the\n" +
		"container (to base/traverse the search) and a subtree grant to read entries,\n" +
		"optionally narrowed with --filter for least privilege — or just use\n" +
		"`svc grant`, which emits both.",
	Args: cobra.ExactArgs(2),
	Example: "  # let an app search ou=users and read ONLY members of a group\n" +
		"  openldap-cli config acl grant <db> 'ou=users,dc=example,dc=org' \\\n" +
		"      --dn 'cn=app,ou=service-accounts,dc=example,dc=org' --access search --scope base\n" +
		"  openldap-cli config acl grant <db> 'ou=users,dc=example,dc=org' \\\n" +
		"      --dn 'cn=app,ou=service-accounts,dc=example,dc=org' --access read \\\n" +
		"      --filter '(memberOf=cn=admins,ou=groups,dc=example,dc=org)'",
	RunE: func(cmd *cobra.Command, args []string) error {
		db, target := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
		if !validAccess(aclGrantAccess) {
			return fmt.Errorf("--access must be one of none|disclose|auth|compare|search|read|write|manage")
		}
		scope := strings.TrimSpace(aclGrantScope)
		switch scope {
		case "sub", "subtree":
			scope = "subtree"
		case "base":
		default:
			return fmt.Errorf("--scope must be sub or base")
		}
		if aclGrantTerm != "break" && aclGrantTerm != "none" {
			return fmt.Errorf("--terminator must be break or none")
		}
		if f := strings.TrimSpace(aclGrantFilter); f != "" && !strings.HasPrefix(f, "(") {
			return fmt.Errorf("--filter must be an LDAP filter, e.g. '(memberOf=cn=g,dc=x)'")
		}
		who, err := aclWho(aclGrantGroup, aclGrantDN)
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		opts := acl.InjectOpts{
			Target: target, Scope: scope, Filter: strings.TrimSpace(aclGrantFilter),
			Who: who, Access: aclGrantAccess, Terminator: aclGrantTerm, At: aclGrantAt,
		}
		before, err := cc.ReadEntry(db, []string{"olcAccess"})
		if err != nil {
			return err
		}
		// Appending a NEW rule at the end grants nothing when a broader rule above
		// already matches the target and never breaks: slapd stops at that one. So
		// place it above the rule that would shadow it (-1: nothing does, append at
		// the end). --at overrides, for a placement we cannot infer.
		shadow := acl.ShadowIndex(before.GetAll("olcAccess"), opts)
		if !cmd.Flags().Changed("at") {
			opts.At = shadow
		}

		rule, appended, err := cc.InjectAccess(db, opts)
		if err != nil {
			return fmt.Errorf("grant on %s: %w", db, err)
		}
		log.Debug().Str("db", db).Str("who", who).Bool("new_rule", appended).Int("at", opts.At).Msg("olcAccess grant")
		if rule == "" {
			return out.Emit(okResult{Action: "already granted (no change) to " + who + " on", DN: db})
		}
		if appended && opts.At >= 0 && !cmd.Flags().Changed("at") {
			log.Info().Int("at", opts.At).Msg("new rule placed above the rule that would have shadowed it")
			if aclGrantTerm == "none" {
				log.Warn().Int("at", opts.At).Msg("this rule ends in `by * none` and now sits above a broader one: every other identity that rule served loses access on these entries (rootDN excepted) — use --terminator break to stay additive")
			}
		}
		// The clause can also land in an EXISTING rule that is itself shadowed, or
		// at an --at the caller chose: placement alone does not prove reachability.
		warnIfGrantUnreachable(cc, db, opts)
		return out.Emit(okResult{Action: "granted " + aclGrantAccess + " to " + who + " on", DN: db, Detail: rule})
	},
}

var configACLRevokeCmd = &cobra.Command{
	Use:     "revoke <database-dn> (--group <g> | --dn <d>)",
	Short:   "Remove every `by <who> …` clause referencing a group or DN",
	Args:    cobra.ExactArgs(1),
	Example: "  openldap-cli config acl revoke 'olcDatabase={1}mdb,cn=config' --group readers",
	RunE: func(cmd *cobra.Command, args []string) error {
		db := strings.TrimSpace(args[0])
		who, err := aclWho(aclRevokeGroup, aclRevokeDN)
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()
		removed, dropped, err := cc.RemoveAccessGrantee(db, who)
		if err != nil {
			return fmt.Errorf("revoke on %s: %w", db, err)
		}
		log.Debug().Str("db", db).Str("who", who).Int("removed", removed).Int("dropped", dropped).Msg("olcAccess revoke")
		action := fmt.Sprintf("revoked %d clause(s) for %s on", removed, who)
		if dropped > 0 {
			action = fmt.Sprintf("revoked %d clause(s) for %s (%d now-empty rule(s) dropped) on", removed, who, dropped)
		}
		return out.Emit(okResult{Action: action, DN: db})
	},
}

// ---- set (generic cn=config attribute) ----------------------------------

var configSetCmd = &cobra.Command{
	Use:   "set <dn> <attr> [value...]",
	Short: "Set (or delete, if no value) an attribute on a cn=config entry",
	Long: "Generic cn=config writer (the config-tree counterpart of `user set`).\n" +
		"Replaces <attr> with the given value(s), or deletes it when none are given.",
	Args: cobra.MinimumNArgs(2),
	Example: "  # enable logging of successful operations in the accesslog overlay\n" +
		"  openldap-cli config set 'olcOverlay={4}accesslog,olcDatabase={1}mdb,cn=config' olcAccessLogSuccess TRUE\n" +
		"  openldap-cli config set 'olcDatabase={1}mdb,cn=config' olcDbMaxSize 2147483648",
	RunE: func(cmd *cobra.Command, args []string) error {
		dn, attr, values := args[0], args[1], args[2:]
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: attr, Values: values}
		action := "set " + attr + " on"
		if len(values) == 0 {
			mod.Op = ldapx.ModDelete
			action = "deleted " + attr + " on"
		}
		if err := cc.Modify(dn, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("modify %s: %w", dn, err)
		}
		log.Debug().Str("dn", dn).Str("attr", attr).Msg("config attribute modified")
		return out.Emit(okResult{Action: action, DN: dn})
	},
}

// toEntryList builds an entryList from raw entries.
func toEntryList(entries []*ldapx.Entry) entryList {
	var l entryList
	for _, e := range entries {
		l.Entries = append(l.Entries, newEntryResult(e))
	}
	return l
}

func init() {
	configLimitsGetCmd.Flags().StringVar(&limitsDB, "db", "olcDatabase={-1}frontend,cn=config", "database entry to read")
	configLimitsSetCmd.Flags().StringVar(&limitsDB, "db", "olcDatabase={-1}frontend,cn=config", "database entry to modify")
	configLimitsSetCmd.Flags().StringVar(&limitsSize, "size", "", "olcSizeLimit value (number or unlimited)")
	configLimitsSetCmd.Flags().StringVar(&limitsTime, "time", "", "olcTimeLimit value (seconds or unlimited)")
	configLimitsSetCmd.Flags().StringVar(&limitsFor, "for", "", "apply as olcLimits for this selector (e.g. dn.exact=...)")

	configLimitsCmd.AddCommand(configLimitsGetCmd, configLimitsSetCmd)
	configDBCmd.AddCommand(configDBListCmd, configDBResizeCmd)
	for _, c := range []*cobra.Command{configOverlayEnableCmd, configOverlayDisableCmd} {
		c.Flags().StringVar(&overlayDB, "db", "", "database entry to act on (default: the one holding base_dn)")
	}
	configOverlayEnableCmd.Flags().BoolVar(&overlayNoModule, "no-module", false, "fail instead of loading the overlay's module when its schema is missing")
	configOverlayDisableCmd.Flags().BoolVar(&overlayPurge, "purge", false, "delete the overlay entry and its settings instead of just deactivating it")
	configOverlayCmd.AddCommand(configOverlayListCmd, configOverlayEnableCmd, configOverlayDisableCmd)
	configACLMoveCmd.Flags().BoolVar(&aclMoveForce, "force", false, "apply the move even if it changes who has access")
	configACLDeleteCmd.Flags().BoolVar(&aclDeleteForce, "force", false, "delete even if the rule is live and its removal changes who has access")
	configACLGrantCmd.Flags().StringVar(&aclGrantGroup, "group", "", "grant to all members of this group (name or DN)")
	configACLGrantCmd.Flags().StringVar(&aclGrantDN, "dn", "", "grant to this exact DN")
	configACLGrantCmd.Flags().StringVar(&aclGrantAccess, "access", "read", "access level: none|disclose|auth|compare|search|read|write|manage")
	configACLGrantCmd.Flags().StringVar(&aclGrantScope, "scope", "sub", "rule scope: sub (the tree) or base (the container entry only, to traverse/search)")
	configACLGrantCmd.Flags().StringVar(&aclGrantFilter, "filter", "", "narrow the rule to entries matching this LDAP filter, e.g. '(memberOf=cn=g,dc=x)'")
	configACLGrantCmd.Flags().IntVar(&aclGrantAt, "at", -1, "index to insert a NEW rule at (default: auto — above the rule that would shadow it)")
	configACLGrantCmd.Flags().StringVar(&aclGrantTerm, "terminator", "break", "trailing `by *` of a NEW rule: break (additive) or none (blocks others)")
	configACLRevokeCmd.Flags().StringVar(&aclRevokeGroup, "group", "", "the group (name or DN) to revoke")
	configACLRevokeCmd.Flags().StringVar(&aclRevokeDN, "dn", "", "the exact DN to revoke")
	configACLCmd.AddCommand(configACLListCmd, configACLMoveCmd, configACLGrantCmd, configACLRevokeCmd,
		configACLDeleteCmd, configACLLintCmd)
	configCmd.AddCommand(configLimitsCmd, configDBCmd, configOverlayCmd, configACLCmd, configSetCmd)
	rootCmd.AddCommand(configCmd)
}
