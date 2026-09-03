package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// readPasswordStdin reads a password from standard input for the commands that
// take --password-stdin.
//
// A password passed as --password ends up in the shell history and, for as long
// as the command runs, in `ps` and /proc/<pid>/cmdline, where any local user can
// read it. Piping it in leaves it in neither.
//
// Exactly one trailing newline is stripped (so `echo pw | ...` works); anything
// else is taken literally, because a password may legitimately end in spaces.
func readPasswordStdin() (string, error) {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("read the password from stdin: %w", err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	s = strings.TrimSuffix(s, "\r")
	if s == "" {
		return "", errors.New("no password on stdin")
	}
	if strings.ContainsAny(s, "\n\r") {
		return "", errors.New("the password on stdin spans several lines")
	}
	return s, nil
}

// resolvePassword picks between the two ways a command accepts a password.
// An empty result means neither was given, which every caller reads as "generate
// one" rather than "set an empty password".
func resolvePassword(flagValue string, fromStdin bool) (string, error) {
	if fromStdin {
		if flagValue != "" {
			return "", errors.New("--password and --password-stdin are mutually exclusive")
		}
		return readPasswordStdin()
	}
	return flagValue, nil
}

const passwordStdinHelp = "read the password from stdin instead of --password, which is visible in ps"
