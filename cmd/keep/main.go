// keep — the client CLI for keep (keepcentral.com): deployment-side
// one-shot operations for non-Go services, deploy scripts, and
// scheduler-driven jobs. Rotation reaches a process only via its own
// supervisor's restart.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	keep "xoba.com/keep"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var identityDir string
	root := &cobra.Command{
		Use:           "keep",
		Short:         "keep client: status, secrets, leases, and backups for a deployment",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.PersistentFlags().StringVar(&identityDir, "identity",
		envOr("KEEP_IDENTITY", defaultIdentity("client")), "identity dir (cert.pem, key.pem)")

	cl := func() (*keep.Client, error) {
		return keep.New(identityDir)
	}

	// keygen
	var dir, name string
	keygen := &cobra.Command{
		Use:   "keygen",
		Short: "generate an Ed25519 key + self-signed client certificate",
		Long: `Generates key.pem and cert.pem in --dir. The private key never leaves
this machine; give the printed public key to an administrator to register.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dir == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return err
				}
				dir = filepath.Join(home, ".keep", name)
			}
			keyid, pubB64, err := keep.GenerateIdentity(dir, name)
			if err != nil {
				return err
			}
			printJSON(map[string]string{
				"dir":        dir,
				"keyid":      keyid,
				"public_key": pubB64,
			})
			return nil
		},
	}
	keygen.Flags().StringVar(&dir, "dir", "", "output directory (default ~/.keep/<name>)")
	keygen.Flags().StringVar(&name, "name", "client", "identity name (certificate CN)")

	// status
	var health, revision string
	status := &cobra.Command{
		Use: "status", Short: "report deployment status",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			st := keep.DefaultStatus(health)
			if revision != "" {
				st.RunningRevision = revision
			}
			if err := c.PutStatus(st); err != nil {
				return err
			}
			printJSON(st)
			return nil
		},
	}
	status.Flags().StringVar(&health, "health", "healthy", "health: healthy|unhealthy")
	status.Flags().StringVar(&revision, "revision", "", "running revision (default: embedded VCS revision)")

	// lease (printing is explicit, never the default)
	var toStdout bool
	lease := &cobra.Command{
		Use: "lease <secret>", Args: cobra.ExactArgs(1),
		Short: "lease a secret (one-shot; use --stdout to print the value)",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			l, err := c.LeaseSecret(args[0])
			if err != nil {
				return err
			}
			if toStdout {
				payload, err := l.PayloadBytes()
				if err != nil {
					return err
				}
				os.Stdout.Write(payload)
				return nil
			}
			printJSON(map[string]any{
				"name": l.Name, "version": l.Version,
				"issued_at": l.IssuedAt, "refresh_after": l.RefreshAfter,
				"soft_lease_until": l.SoftLeaseUntil,
				"note":             "value withheld; pass --stdout to print it",
			})
			return nil
		},
	}
	lease.Flags().BoolVar(&toStdout, "stdout", false, "print the secret value to stdout")

	// exec: env injection at process start; never argv
	var prefix string
	execCmd := &cobra.Command{
		Use:   "exec <secret> -- <command> [args...]",
		Short: "exec a command with the secret's JSON keys as environment variables",
		Long: `Leases the secret once and execs the command with each top-level JSON key
injected as an uppercased environment variable (e.g. api_key -> API_KEY).
The process must be restarted to pick up a rotated value; keep never
initiates that restart.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			l, err := c.LeaseSecret(args[0])
			if err != nil {
				return err
			}
			payload, err := l.PayloadBytes()
			if err != nil {
				return err
			}
			var kv map[string]string
			if err := json.Unmarshal(payload, &kv); err != nil {
				return fmt.Errorf("secret payload is not a flat JSON object of strings; use lease --stdout instead")
			}
			env := os.Environ()
			for k, v := range kv {
				env = append(env, prefix+strings.ToUpper(strings.ReplaceAll(k, "-", "_"))+"="+v)
			}
			bin, err := exec.LookPath(args[1])
			if err != nil {
				return err
			}
			return syscall.Exec(bin, args[1:], env)
		},
	}
	execCmd.Flags().StringVar(&prefix, "prefix", "", "environment variable name prefix")

	// secrets: names available to this deployment's service
	secrets := &cobra.Command{
		Use: "secrets", Short: "list the secret names available to this deployment",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			infos, err := c.ListSelfSecrets()
			if err != nil {
				return err
			}
			names := make([]string, len(infos))
			for i, in := range infos {
				names[i] = in.Name
			}
			printJSON(names)
			return nil
		},
	}

	// backup
	backup := &cobra.Command{
		Use: "backup <database-name> <sqlite-path>", Args: cobra.ExactArgs(2),
		Short: "snapshot (VACUUM INTO), validate, gzip, and upload a database backup",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			res, err := c.BackupDatabase(args[0], args[1])
			if err != nil {
				return err
			}
			printJSON(res)
			return nil
		},
	}

	// set-desired: the deploy-time write (design S10)
	setDesired := &cobra.Command{
		Use: "set-desired <revision>", Args: cobra.ExactArgs(1),
		Short: "record the desired revision of this deployment's own service",
		Long: `Publishes what *should* be running for this deployment's service —
typically the commit a deploy script just shipped:

  keep set-desired "$(git rev-parse HEAD)"

The service is determined by the identity; no other service can be named.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := cl()
			if err != nil {
				return err
			}
			if err := c.SetDesiredRevision(args[0]); err != nil {
				return err
			}
			printJSON(map[string]string{"desired_revision": args[0]})
			return nil
		},
	}

	root.AddCommand(keygen, status, secrets, lease, execCmd, backup, setDesired)
	return root
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func defaultIdentity(name string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".keep", name)
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(string(b))
}
