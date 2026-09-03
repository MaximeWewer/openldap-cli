package cli

import (
	"os"
	"strings"
	"testing"
)

// withStdin points os.Stdin at a pipe holding s for the duration of the test.
func withStdin(t *testing.T, s string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig; _ = r.Close() })

	go func() {
		_, _ = w.WriteString(s)
		_ = w.Close()
	}()
}

func TestResolvePasswordFromStdin(t *testing.T) {
	// one trailing newline is the shell's, not the password's
	withStdin(t, "s3cret\n")
	got, err := resolvePassword("", true)
	if err != nil {
		t.Fatalf("resolvePassword: %v", err)
	}
	if got != "s3cret" {
		t.Errorf("password = %q, want %q", got, "s3cret")
	}
}

func TestResolvePasswordKeepsSignificantSpaces(t *testing.T) {
	// a password may legitimately end in a space; only the newline goes
	withStdin(t, "  pad  \n")
	got, err := resolvePassword("", true)
	if err != nil {
		t.Fatalf("resolvePassword: %v", err)
	}
	if got != "  pad  " {
		t.Errorf("password = %q, want %q", got, "  pad  ")
	}
}

func TestResolvePasswordRejectsBothSources(t *testing.T) {
	withStdin(t, "fromstdin\n")
	if _, err := resolvePassword("fromflag", true); err == nil {
		t.Fatal("resolvePassword accepted --password together with --password-stdin")
	}
}

func TestResolvePasswordRejectsEmptyAndMultiline(t *testing.T) {
	withStdin(t, "\n")
	if _, err := resolvePassword("", true); err == nil {
		t.Error("resolvePassword accepted an empty stdin")
	}
	withStdin(t, "one\ntwo\n")
	if _, err := resolvePassword("", true); err == nil {
		t.Error("resolvePassword accepted a multi-line stdin")
	}
}

func TestResolvePasswordFallsBackToTheFlag(t *testing.T) {
	got, err := resolvePassword("fromflag", false)
	if err != nil || got != "fromflag" {
		t.Errorf("resolvePassword = %q, %v", got, err)
	}
}

func TestResolvePasswordEmptyMeansGenerate(t *testing.T) {
	// neither source given: callers read "" as "generate one", never as
	// "set an empty password"
	got, err := resolvePassword("", false)
	if err != nil || got != "" {
		t.Errorf("resolvePassword = %q, %v; want the empty string", got, err)
	}
}

func TestPasswordStdinHelpMentionsPs(t *testing.T) {
	// the whole point of the flag is that --password is world-visible
	if !strings.Contains(passwordStdinHelp, "ps") {
		t.Errorf("flag help does not say why: %q", passwordStdinHelp)
	}
}
