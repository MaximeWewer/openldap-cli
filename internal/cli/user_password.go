package cli

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/MaximeWewer/openldap-cli/internal/ldapx"
)

// ---- passwd -------------------------------------------------------------

var userPasswdValue string

var userPasswdCmd = &cobra.Command{
	Use:   "passwd <login>",
	Short: "Set a user's password (Password Modify ext-op; ppolicy hashes it)",
	Long:  "Sets the password via the LDAP Password Modify extended operation. Omit\n--password to generate a strong one, sized to the effective ppolicy\n(pwdMinLength), and print it.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}

		// When no password is given, generate one CLIENT-side sized to the
		// effective ppolicy, retrying stronger if rejected. (The server's own
		// Password Modify generator returns a short password that a non-trivial
		// pwdMinLength/quality policy would reject.)
		gen := ""
		if userPasswdValue == "" {
			p, gerr := setGeneratedPassword(cli, entry.DN)
			if gerr != nil {
				return gerr
			}
			gen = p
		} else if _, serr := cli.SetPassword(entry.DN, userPasswdValue); serr != nil {
			return fmt.Errorf("set password for %s: %w", entry.DN, serr)
		}
		log.Debug().Str("dn", entry.DN).Msg("password set")

		res := okResult{Action: "password set", DN: entry.DN}
		if gen != "" {
			res.Password = gen
		}
		return out.Emit(res)
	},
}

// ---- unlock -------------------------------------------------------------

var userUnlockCmd = &cobra.Command{
	Use:   "unlock <login>",
	Short: "Clear a user's ppolicy lockout and failure counter",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"pwdAccountLockedTime", "pwdFailureTime"})
		if err != nil {
			return err
		}
		locked := entry.Get("pwdAccountLockedTime") != ""
		failures := len(entry.GetAll("pwdFailureTime"))
		if !locked && failures == 0 {
			return out.Emit(okResult{Action: "already unlocked", DN: entry.DN})
		}

		// pwdAccountLockedTime is the actual lock and is always deletable.
		if locked {
			mods := []ldapx.Mod{{Op: ldapx.ModDelete, Name: "pwdAccountLockedTime"}}
			if err := cli.Modify(entry.DN, mods); err != nil {
				return fmt.Errorf("unlock %s: %w", entry.DN, err)
			}
		}

		// pwdFailureTime is no-user-modification; clearing it needs the Relax
		// Rules control and manage rights. Best-effort, non-fatal.
		detail := ""
		if failures > 0 {
			err := cli.ModifyRelax(entry.DN, []ldapx.Mod{{Op: ldapx.ModDelete, Name: "pwdFailureTime"}})
			switch {
			case err == nil, ldapx.IsNoSuchAttribute(err):
				detail = "lock + failure counter cleared"
			default:
				log.Warn().Err(err).Msg("could not clear pwdFailureTime (needs Relax control + manage rights)")
				detail = fmt.Sprintf("lock cleared; %d failure record(s) left (need manage rights to clear)", failures)
			}
		}
		log.Debug().Str("dn", entry.DN).Msg("user unlocked")
		return out.Emit(okResult{Action: "unlocked", DN: entry.DN, Detail: detail})
	},
}

// ---- force-reset --------------------------------------------------------

var userForceResetClear bool

var userForceResetCmd = &cobra.Command{
	Use:   "force-reset <login>",
	Short: "Require the user to change password at next login (pwdReset)",
	Long:  "Sets pwdReset=TRUE so the directory forces a password change on next bind.\nUse --clear to remove the flag.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		login := strings.ToLower(strings.TrimSpace(args[0]))
		cli, err := connect()
		if err != nil {
			return err
		}
		defer cli.Close()

		entry, err := cli.FindUser(login, []string{"uid"})
		if err != nil {
			return err
		}
		mod := ldapx.Mod{Op: ldapx.ModReplace, Name: "pwdReset", Values: []string{"TRUE"}}
		action := "force-reset set on"
		if userForceResetClear {
			mod = ldapx.Mod{Op: ldapx.ModDelete, Name: "pwdReset"}
			action = "force-reset cleared on"
		}
		if err := cli.Modify(entry.DN, []ldapx.Mod{mod}); err != nil {
			return fmt.Errorf("force-reset %s: %w", entry.DN, err)
		}
		log.Debug().Str("dn", entry.DN).Bool("clear", userForceResetClear).Msg("pwdReset changed")
		return out.Emit(okResult{Action: action, DN: entry.DN})
	},
}

func init() {
	userPasswdCmd.Flags().StringVar(&userPasswdValue, "password", "", "new password (omit to have the server generate one)")
	userForceResetCmd.Flags().BoolVar(&userForceResetClear, "clear", false, "remove the pwdReset flag instead of setting it")
	userCmd.AddCommand(userPasswdCmd, userUnlockCmd, userForceResetCmd)
}
