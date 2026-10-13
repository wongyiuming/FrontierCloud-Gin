// fc is a short-lived operator client, shipped separately from Web.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/wongyiuming/FrontierCloud-Gin/internal/operator"
	"github.com/wongyiuming/FrontierCloud-Gin/internal/release"
)

var Revision string

func main() { os.Exit(run(os.Args[1:])) }
func run(args []string) int {
	flags := flag.NewFlagSet("fc", flag.ContinueOnError)
	directory := flags.String("directory", ".", "deployment bundle directory")
	role := flags.String("role", "master", "doctor role: master or storage")
	database := flags.String("database", "sqlite", "master database: sqlite or mysql")
	structured := flags.Bool("json", false, "structured report")
	revision := flags.String("revision", "", "explicit published main revision; install alone may discover latest")
	ordered, err := globalArguments(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if flags.Parse(ordered) != nil {
		return 2
	}
	args = flags.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "fc [--directory DIR] [--json] doctor | install master|storage | status | logs | restart | diagnose | backup create|verify|set-create|set-verify | restore check|apply|activate|open|set-check|set-apply|set-prepare|set-activate|set-open | upgrade plan|apply|open | node retire check|apply NODE_ID | node migrate plan|plan-status|start|status|pause|resume|cancel|retry|release-drain\nRead-only: doctor/status/logs/diagnose, backup verify/set-verify, restore check/set-check, upgrade plan and node retire check. Writes require the corresponding operation's explicit confirmations. Install refuses existing data. No command deletes volumes.")
		return 2
	}
	if args[0] == "version" && len(args) == 1 {
		fmt.Println(Revision)
		return 0
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := commandContext(parent, args)
	defer cancel()
	if args[0] == "node" {
		return nodeCommand(ctx, args, *structured, os.Stdin, os.Stdout, os.Stderr)
	}
	if args[0] == "backup" || args[0] == "restore" {
		return recoveryCommand(ctx, *directory, args)
	}
	if args[0] == "upgrade" {
		return upgradeCommand(ctx, *directory, *revision, args, os.Stdout, os.Stderr)
	}
	emit := func(v any) {
		if !*structured {
			if r, ok := v.(operator.Report); ok {
				fmt.Print(r.Human())
				return
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(v)
	}
	if args[0] == "doctor" || args[0] == "install" {
		if args[0] == "install" {
			if len(args) != 2 {
				fmt.Fprintln(os.Stderr, "install requires master or storage")
				return 2
			}
			*role = args[1]
		} else if len(args) != 1 {
			return 2
		}
		d, err := operator.New(*directory, *role, *database)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		d.Runner = dockerRunner{d.Directory}
		registry := release.NewRegistryClient()
		defer registry.Close()
		d.ImageInspector = registry
		report := d.Doctor(ctx)
		if args[0] == "doctor" {
			emit(report)
			return report.ExitCode()
		}
		if report.ExitCode() == 2 {
			emit(report)
			return 2
		}
		for _, check := range report.Checks {
			if check.Item == "ports" && check.State == "warning" {
				fmt.Fprintln(os.Stderr, "configured ports are occupied; identify and resolve their owner before fresh installation")
				return 2
			}
		}
		if release.ValidSHA(Revision) {
			if *revision != "" && *revision != Revision {
				fmt.Fprintln(os.Stderr, "installation target differs from the operator bundle; download the selected release bundle")
				return 2
			}
			*revision = Revision
		}
		raw, err := d.Runner.Run(ctx, "docker", "info", "--format", "{{.Architecture}}")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		v, err := release.NewVerifier(release.DefaultPolicy(), "")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		receipt, err := d.Install(ctx, *revision, operator.Architecture(string(raw)), v, registry)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		emit(receipt)
		return 0
	}
	if len(args) != 1 {
		return 2
	}
	d, receipt, err := operator.Open(*directory)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	d.Runner = dockerRunner{d.Directory}
	switch args[0] {
	case "status", "diagnose":
		report := d.Status(ctx, receipt)
		report.Operation = args[0]
		emit(report)
		return report.ExitCode()
	case "logs":
		report, e := d.Logs(ctx, receipt)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		emit(report)
		return 0
	case "restart":
		if _, markerErr := os.Lstat(filepath.Join(d.Directory, ".fc-recovery-set.json")); markerErr == nil || !os.IsNotExist(markerErr) {
			fmt.Fprintln(os.Stderr, "deployment belongs to an incomplete coordinated recovery set; finish the set recovery before restart")
			return 2
		}
		if receipt.State != "ready" {
			fmt.Fprintln(os.Stderr, "deployment is not ready; finish its recorded recovery or upgrade before restart")
			return 2
		}
		done, e := d.AcquireOperation()
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return 2
		}
		defer done()
		if _, err = d.ValidateReceipt(ctx, receipt); err == nil {
			_, err = d.Compose(ctx, true, "up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "600")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		report := d.Status(ctx, receipt)
		emit(report)
		return report.ExitCode()
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		return 2
	}
}

// Bulk recovery includes complete archive hashing, logical dumps and restore
// passes. Its duration follows the state size; cancellation is operator-owned.
func commandContext(parent context.Context, args []string) (context.Context, context.CancelFunc) {
	if len(args) != 0 && (args[0] == "backup" || args[0] == "restore" || args[0] == "upgrade") {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, 15*time.Minute)
}

// Keep the small global FlagSet while accepting common command-first syntax.
func globalArguments(args []string) ([]string, error) {
	var options, positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		key := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if strings.HasPrefix(arg, "-") && (key == "directory" || key == "role" || key == "database" || key == "revision" || key == "json") {
			options = append(options, arg)
			if key != "json" && !strings.Contains(arg, "=") {
				if i+1 == len(args) {
					return nil, fmt.Errorf("%s requires a value", arg)
				}
				i++
				options = append(options, args[i])
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(options, positionals...), nil
}
