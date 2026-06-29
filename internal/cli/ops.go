package cli

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldaptime"
	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

var opsCmd = &cobra.Command{
	Use:   "ops",
	Short: "Operations & diagnostics (most read via the config bind)",
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

// ---- db-stats -----------------------------------------------------------

var opsDBStatsCmd = &cobra.Command{
	Use:   "db-stats",
	Short: "MDB sizing per database (entries, page usage) to catch MDB_MAP_FULL",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		// config: suffix -> maxSize
		maxBySuffix := map[string]string{}
		cfg, err := cc.Search("cn=config", "(objectClass=olcMdbConfig)",
			[]string{"olcSuffix", "olcDbMaxSize"})
		if err != nil {
			return fmt.Errorf("read cn=config: %w", err)
		}
		for _, e := range cfg {
			maxBySuffix[e.Get("olcSuffix")] = e.Get("olcDbMaxSize")
		}

		mon, err := cc.Search("cn=Databases,cn=Monitor", "(olmMDBEntries=*)",
			[]string{"namingContexts", "olmMDBEntries", "olmMDBPagesMax", "olmMDBPagesUsed", "olmMDBPagesFree"})
		if err != nil {
			return fmt.Errorf("read cn=Monitor: %w", err)
		}
		var res dbStatsResult
		for _, e := range mon {
			suffix := e.Get("namingContexts")
			used := atoi(e.Get("olmMDBPagesUsed"))
			maxPages := atoi(e.Get("olmMDBPagesMax"))
			pct := 0.0
			if maxPages > 0 {
				pct = float64(used) / float64(maxPages) * 100
			}
			res.Databases = append(res.Databases, dbStat{
				Suffix:    suffix,
				Entries:   atoi(e.Get("olmMDBEntries")),
				MaxSize:   maxBySuffix[suffix],
				PagesUsed: used,
				PagesMax:  maxPages,
				PagesFree: atoi(e.Get("olmMDBPagesFree")),
				UsagePct:  pct,
			})
		}
		return out.Emit(res)
	},
}

type dbStat struct {
	Suffix    string  `json:"suffix" yaml:"suffix"`
	Entries   int     `json:"entries" yaml:"entries"`
	MaxSize   string  `json:"maxSize,omitempty" yaml:"maxSize,omitempty"`
	PagesUsed int     `json:"pagesUsed" yaml:"pagesUsed"`
	PagesMax  int     `json:"pagesMax" yaml:"pagesMax"`
	PagesFree int     `json:"pagesFree" yaml:"pagesFree"`
	UsagePct  float64 `json:"usagePct" yaml:"usagePct"`
}

type dbStatsResult struct {
	Databases []dbStat `json:"databases" yaml:"databases"`
}

func (r dbStatsResult) Text() string {
	var b strings.Builder
	for _, d := range r.Databases {
		fmt.Fprintf(&b, "%s\n", d.Suffix)
		fmt.Fprintf(&b, "  entries: %d  pages: %d/%d used (%.1f%%)  free: %d  maxSize: %s\n",
			d.Entries, d.PagesUsed, d.PagesMax, d.UsagePct, d.PagesFree, d.MaxSize)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- accesslog-purge ----------------------------------------------------

var (
	purgeKeepDays int
	purgeSweep    string
	purgeDryRun   bool
	purgeSet      string
)

var opsAccesslogPurgeCmd = &cobra.Command{
	Use:   "accesslog-purge",
	Short: "Tune the accesslog purge schedule (olcAccessLogPurge), or dry-run a count",
	Long: "Purging is done by OpenLDAP's scheduler. This sets olcAccessLogPurge; the\n" +
		"server then removes old entries on its next sweep. --dry-run only counts\n" +
		"entries older than --keep-days. --set writes an explicit spec (to restore).",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		ov, err := cc.Search("cn=config", "(olcOverlay=accesslog)", []string{"olcAccessLogPurge"})
		if err != nil || len(ov) == 0 {
			return fmt.Errorf("accesslog overlay not found: %w", err)
		}
		ovDN := ov[0].DN
		current := ov[0].Get("olcAccessLogPurge")

		if purgeDryRun {
			cutoff := ldaptime.Format(time.Now().Add(-time.Duration(purgeKeepDays) * 24 * time.Hour))
			old, err := cc.Search("cn=accesslog",
				fmt.Sprintf("(&(objectClass=auditObject)(reqStart<=%s))", cutoff), []string{"reqStart"})
			if err != nil {
				return fmt.Errorf("count accesslog: %w", err)
			}
			return out.Emit(okResult{Action: "dry-run", DN: ovDN,
				Detail: fmt.Sprintf("%d entries older than %dd; current purge: %s", len(old), purgeKeepDays, current)})
		}

		newSpec := purgeSet
		if newSpec == "" {
			newSpec = fmt.Sprintf("%02d+00:00 %s", purgeKeepDays, purgeSweep)
		}
		mods := []ldapx.Mod{{Op: ldapx.ModReplace, Name: "olcAccessLogPurge", Values: []string{newSpec}}}
		if err := cc.Modify(ovDN, mods); err != nil {
			return fmt.Errorf("set olcAccessLogPurge: %w", err)
		}
		return out.Emit(okResult{Action: "purge schedule set", DN: ovDN,
			Detail: fmt.Sprintf("%q -> %q (server purges on next sweep; restore with --set %q)", current, newSpec, current)})
	},
}

// ---- audit-binds --------------------------------------------------------

var (
	auditSince string
	auditUser  string
)

var opsAuditBindsCmd = &cobra.Command{
	Use:   "audit-binds",
	Short: "Summarize bind activity from the accesslog",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		since, err := ldaptime.ParseDuration(auditSince)
		if err != nil {
			return err
		}
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		cutoff := ldaptime.Format(time.Now().Add(-since))
		filter := fmt.Sprintf("(&(reqType=bind)(reqStart>=%s))", cutoff)
		if auditUser != "" {
			filter = fmt.Sprintf("(&(reqType=bind)(reqStart>=%s)(reqDN=cn=%s,%s))",
				cutoff, ldapx.EscapeFilter(strings.ToLower(auditUser)), cc.UserBase())
		}
		entries, err := cc.Search("cn=accesslog", filter,
			[]string{"reqDN", "reqResult", "reqStart", "reqMethod"})
		if err != nil {
			return fmt.Errorf("read accesslog: %w", err)
		}

		res := auditResult{Window: auditSince}
		byDN := map[string]int{}
		for _, e := range entries {
			res.Total++
			dn := e.Get("reqDN")
			byDN[dn]++
			if e.Get("reqResult") == "0" {
				res.Success++
			} else {
				res.Failed++
				if len(res.RecentFailures) < 10 {
					res.RecentFailures = append(res.RecentFailures, fmt.Sprintf("%s  %s  rc=%s",
						e.Get("reqStart"), dn, e.Get("reqResult")))
				}
			}
		}
		for dn, n := range byDN {
			res.TopBinders = append(res.TopBinders, binder{dn, n})
		}
		sort.Slice(res.TopBinders, func(i, j int) bool { return res.TopBinders[i].Count > res.TopBinders[j].Count })
		if len(res.TopBinders) > 10 {
			res.TopBinders = res.TopBinders[:10]
		}
		return out.Emit(res)
	},
}

type binder struct {
	DN    string `json:"dn" yaml:"dn"`
	Count int    `json:"count" yaml:"count"`
}

type auditResult struct {
	Window         string   `json:"window" yaml:"window"`
	Total          int      `json:"total" yaml:"total"`
	Success        int      `json:"success" yaml:"success"`
	Failed         int      `json:"failed" yaml:"failed"`
	TopBinders     []binder `json:"topBinders,omitempty" yaml:"topBinders,omitempty"`
	RecentFailures []string `json:"recentFailures,omitempty" yaml:"recentFailures,omitempty"`
}

func (r auditResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "binds in last %s: %d total, %d ok, %d failed\n", r.Window, r.Total, r.Success, r.Failed)
	if len(r.TopBinders) > 0 {
		fmt.Fprintf(&b, "top binders:\n")
		for _, t := range r.TopBinders {
			fmt.Fprintf(&b, "  %4d  %s\n", t.Count, t.DN)
		}
	}
	if len(r.RecentFailures) > 0 {
		fmt.Fprintf(&b, "recent failures:\n")
		for _, f := range r.RecentFailures {
			fmt.Fprintf(&b, "  %s\n", f)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- who-can-write ------------------------------------------------------

var opsWhoCanWriteCmd = &cobra.Command{
	Use:   "who-can-write <dn>",
	Short: "Show olcAccess rules referencing a DN (manual interpretation)",
	Long:  "Pure ACL retrieval + client-side filtering. Output is the raw matching\nrules — read them manually (manage > write > read).",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := strings.TrimSpace(args[0])
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		dbs, err := cc.Search("cn=config", "(olcAccess=*)", []string{"olcAccess"})
		if err != nil {
			return fmt.Errorf("read olcAccess: %w", err)
		}
		res := aclMatchResult{Target: target}
		for _, e := range dbs {
			for _, v := range e.GetAll("olcAccess") {
				if strings.Contains(v, target) {
					res.Rules = append(res.Rules, e.DN+" :: "+v)
				}
			}
		}
		return out.Emit(res)
	},
}

type aclMatchResult struct {
	Target string   `json:"target" yaml:"target"`
	Rules  []string `json:"rules" yaml:"rules"`
}

func (r aclMatchResult) Text() string {
	if len(r.Rules) == 0 {
		return "no olcAccess rule references " + r.Target
	}
	var b strings.Builder
	fmt.Fprintf(&b, "rules referencing %s:\n", r.Target)
	for _, rule := range r.Rules {
		fmt.Fprintf(&b, "  %s\n", rule)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- monitor ------------------------------------------------------------

var opsMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Server runtime stats from cn=Monitor (connections, operations, ...)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := connectConfig()
		if err != nil {
			return err
		}
		defer cc.Close()

		read := func(dn, attr string) string {
			e, err := cc.ReadEntry(dn, []string{attr})
			if err != nil {
				return ""
			}
			return e.Get(attr)
		}

		res := monitorResult{
			UptimeSeconds:     atoi(read("cn=Uptime,cn=Time,cn=Monitor", "monitoredInfo")),
			ConnectionsTotal:  read("cn=Total,cn=Connections,cn=Monitor", "monitorCounter"),
			ConnectionsActive: read("cn=Current,cn=Connections,cn=Monitor", "monitorCounter"),
			OpsInitiated:      read("cn=Operations,cn=Monitor", "monitorOpInitiated"),
			OpsCompleted:      read("cn=Operations,cn=Monitor", "monitorOpCompleted"),
			ThreadsActive:     read("cn=Active,cn=Threads,cn=Monitor", "monitoredInfo"),
			ThreadsMax:        read("cn=Max,cn=Threads,cn=Monitor", "monitoredInfo"),
		}
		if stats, err := cc.Search("cn=Statistics,cn=Monitor", "(objectClass=*)", []string{"cn", "monitorCounter"}); err == nil {
			for _, e := range stats {
				if c := e.Get("monitorCounter"); c != "" {
					res.Statistics = append(res.Statistics, fmt.Sprintf("%s=%s", e.Get("cn"), c))
				}
			}
		}
		return out.Emit(res)
	},
}

type monitorResult struct {
	UptimeSeconds     int      `json:"uptimeSeconds,omitempty" yaml:"uptimeSeconds,omitempty"`
	ConnectionsTotal  string   `json:"connectionsTotal,omitempty" yaml:"connectionsTotal,omitempty"`
	ConnectionsActive string   `json:"connectionsActive,omitempty" yaml:"connectionsActive,omitempty"`
	OpsInitiated      string   `json:"opsInitiated,omitempty" yaml:"opsInitiated,omitempty"`
	OpsCompleted      string   `json:"opsCompleted,omitempty" yaml:"opsCompleted,omitempty"`
	ThreadsActive     string   `json:"threadsActive,omitempty" yaml:"threadsActive,omitempty"`
	ThreadsMax        string   `json:"threadsMax,omitempty" yaml:"threadsMax,omitempty"`
	Statistics        []string `json:"statistics,omitempty" yaml:"statistics,omitempty"`
}

func (r monitorResult) Text() string {
	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			fmt.Fprintf(&b, "  %-18s %s\n", k+":", v)
		}
	}
	fmt.Fprintf(&b, "monitor\n")
	if r.UptimeSeconds > 0 {
		line("uptime", ldaptime.Human(time.Duration(r.UptimeSeconds)*time.Second))
	}
	line("connections", fmt.Sprintf("%s active / %s total", r.ConnectionsActive, r.ConnectionsTotal))
	line("operations", fmt.Sprintf("%s completed / %s initiated", r.OpsCompleted, r.OpsInitiated))
	line("threads", fmt.Sprintf("%s active / %s max", r.ThreadsActive, r.ThreadsMax))
	if len(r.Statistics) > 0 {
		line("statistics", strings.Join(r.Statistics, "  "))
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- replication --------------------------------------------------------

var opsReplicationCmd = &cobra.Command{
	Use:   "replication",
	Short: "Show local contextCSN values (multi-peer drift check is HA-only)",
	Long:  "Reads contextCSN at the base DN. A standalone server has no peers to\ncompare against; this just surfaces the local CSNs.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		e, err := cli.ReadEntry(cli.Config().BaseDN, []string{"contextCSN"})
		if err != nil {
			return err
		}
		return out.Emit(replicationResult{
			BaseDN:     cli.Config().BaseDN,
			ContextCSN: e.GetAll("contextCSN"),
		})
	},
}

type replicationResult struct {
	BaseDN     string   `json:"baseDN" yaml:"baseDN"`
	ContextCSN []string `json:"contextCSN" yaml:"contextCSN"`
	Note       string   `json:"note" yaml:"note"`
}

func (r replicationResult) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s contextCSN:\n", r.BaseDN)
	if len(r.ContextCSN) == 0 {
		fmt.Fprintf(&b, "  (none)\n")
	}
	for _, c := range r.ContextCSN {
		fmt.Fprintf(&b, "  %s\n", c)
	}
	fmt.Fprintf(&b, "note: standalone — no peers to compare; HA drift check needs >=2 servers")
	return b.String()
}

func init() {
	opsAccesslogPurgeCmd.Flags().IntVar(&purgeKeepDays, "keep-days", 7, "retention in days")
	opsAccesslogPurgeCmd.Flags().StringVar(&purgeSweep, "sweep", "00+00:05", "purge sweep interval (DD+HH:MM)")
	opsAccesslogPurgeCmd.Flags().BoolVar(&purgeDryRun, "dry-run", false, "only count entries older than --keep-days")
	opsAccesslogPurgeCmd.Flags().StringVar(&purgeSet, "set", "", "set an explicit olcAccessLogPurge spec (e.g. \"07+00:00 01+00:00\")")

	opsAuditBindsCmd.Flags().StringVar(&auditSince, "since", "24h", "time window (e.g. 24h, 7d)")
	opsAuditBindsCmd.Flags().StringVar(&auditUser, "user", "", "filter by user login")

	opsCmd.AddCommand(opsDBStatsCmd, opsAccesslogPurgeCmd, opsAuditBindsCmd, opsWhoCanWriteCmd, opsReplicationCmd, opsMonitorCmd)
	rootCmd.AddCommand(opsCmd)
}
