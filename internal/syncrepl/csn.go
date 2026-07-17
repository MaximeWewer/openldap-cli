// Package syncrepl decodes the replication state OpenLDAP exposes: the
// contextCSN values a server keeps at a naming context.
//
// A contextCSN is not one value but one PER contributing server, and each is a
// change-sequence-number:
//
//	20240101120000.000000Z#000000#001#000000
//	└─ generalizedTime ──┘ #count#  SID  #mod
//
// The SID identifies the server that made the change; the timestamp is how far
// that server's changes have propagated here. Comparing the same SID's timestamp
// across servers is how replication drift is seen — a replica whose SID-001 CSN
// lags the provider's is behind. A single connection cannot do that comparison
// (it needs the other servers), but it CAN decode what this server holds, which
// is the raw material for it.
package syncrepl

import (
	"fmt"
	"strings"
	"time"
)

// CSN is one decoded change-sequence-number.
type CSN struct {
	Raw  string
	Time time.Time // the change time, UTC
	SID  string    // the contributing server's ID, e.g. "001"
	OK   bool      // false when the value did not parse as a CSN
}

// Parse decodes one contextCSN value. A value it does not understand comes back
// with OK false and Raw set, so a caller can show it rather than drop it.
func Parse(v string) CSN {
	c := CSN{Raw: strings.TrimSpace(v)}
	parts := strings.Split(c.Raw, "#")
	if len(parts) != 4 {
		return c
	}
	// generalizedTime with a mandatory fractional part: 20240101120000.000000Z
	t, err := time.Parse("20060102150405.999999Z", parts[0])
	if err != nil {
		// tolerate a whole-second form some tools emit
		if t, err = time.Parse("20060102150405Z", parts[0]); err != nil {
			return c
		}
	}
	c.Time = t.UTC()
	c.SID = parts[2]
	c.OK = true
	return c
}

// ParseAll decodes every value, preserving order.
func ParseAll(values []string) []CSN {
	out := make([]CSN, 0, len(values))
	for _, v := range values {
		out = append(out, Parse(v))
	}
	return out
}

// SIDs returns the distinct server-IDs present among the parsed CSNs, in first-
// seen order. More than one means more than one server has contributed changes
// visible here — so the server is not standalone, whatever else is configured.
func SIDs(csns []CSN) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range csns {
		if !c.OK || seen[c.SID] {
			continue
		}
		seen[c.SID] = true
		out = append(out, c.SID)
	}
	return out
}

// Assess turns the facts a single connection can read — the contextCSN values,
// whether olcSyncrepl is configured, and whether this is a multi-provider
// (mirror) node — into a factual role and the warnings that follow from them.
//
// It deliberately claims only what one server can prove. Drift against a peer is
// not among those things: it needs the peer's own contextCSN, so the caller says
// how to compare rather than pretend a verdict.
func Assess(contextCSN []string, hasSyncrepl, mirror bool) (role string, warnings []string) {
	sids := SIDs(ParseAll(contextCSN))

	switch {
	case hasSyncrepl && mirror:
		role = "mirror"
	case hasSyncrepl:
		role = "replica"
	case len(sids) > 1:
		// no syncrepl here, yet several SIDs have written: a provider in a
		// multi-master ring, or one that has taken replicated writes
		role = "provider"
	default:
		role = "standalone"
	}

	// a replica that carries no contextCSN has never completed an initial sync
	if hasSyncrepl && len(contextCSN) == 0 {
		warnings = append(warnings, "configured as a replica but has NO contextCSN — it has never received data from its provider(s)")
	}
	// a standalone verdict the data itself contradicts: don't let the label bury it
	if role == "standalone" && len(sids) > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"no syncrepl configured, yet contextCSN carries %d server-IDs (%s) — this is not a solo server",
			len(sids), strings.Join(sids, ", ")))
	}
	return role, warnings
}
