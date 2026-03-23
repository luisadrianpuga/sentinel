package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/luisadrianpuga/sentinel/internal/sentinel"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		log.Fatalf("sentinel: %v", err)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage("")
		return errors.New("invalid command")
	}

	cfg := sentinel.DefaultConfig()
	switch args[0] {
	case "run":
		return runCommand(ctx, cfg, args[1:])
	case "query":
		return queryCommand(ctx, cfg, args[1:])
	case "diff":
		return diffCommand(ctx, cfg, args[1:])
	case "help", "-h", "--help":
		printUsage("")
		return nil
	default:
		printUsage(fmt.Sprintf("unknown command %q", args[0]))
		return errors.New("invalid command")
	}
}

func runCommand(ctx context.Context, cfg sentinel.Config, args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&cfg.AgentCommand, "agent", os.Getenv("AGENT"), "command to start and trace")
	fs.IntVar(&cfg.PID, "pid", 0, "attach to an existing pid instead of starting a command")
	fs.StringVar(&cfg.AgentRun, "session", "", "optional session tag")
	fs.StringVar(&cfg.DatabaseURL, "database-url", os.Getenv("DATABASE_URL"), "database url; sqlite path or postgres DSN")
	fs.StringVar(&cfg.SQLitePath, "sqlite-path", filepath.Join("data", "sentinel.db"), "sqlite database path when DATABASE_URL is empty")
	fs.StringVar(&cfg.BPFObjectPath, "bpf-object", filepath.Join("bpf", "trace.bpf.o"), "compiled eBPF object path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := sentinel.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.Migrate(ctx); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner, err := sentinel.NewRunner(cfg, store)
	if err != nil {
		return err
	}

	return runner.Run(ctx)
}

func queryCommand(ctx context.Context, cfg sentinel.Config, args []string) error {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var filter sentinel.QueryFilter
	fs.StringVar(&filter.Syscall, "syscall", "", "filter by syscall name")
	fs.StringVar(&filter.ArgContains, "arg", "", "filter by substring match on arg")
	fs.StringVar(&filter.AgentRun, "session", "", "filter by session tag")
	fs.IntVar(&filter.Limit, "limit", 100, "maximum rows to return")
	fs.StringVar(&cfg.DatabaseURL, "database-url", os.Getenv("DATABASE_URL"), "database url; sqlite path or postgres DSN")
	fs.StringVar(&cfg.SQLitePath, "sqlite-path", filepath.Join("data", "sentinel.db"), "sqlite database path when DATABASE_URL is empty")
	if err := fs.Parse(args); err != nil {
		return err
	}

	store, err := sentinel.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	events, err := store.Query(ctx, filter)
	if err != nil {
		return err
	}
	for _, event := range events {
		fmt.Printf("[%s] pid=%d comm=%s syscall=%s arg=%s session=%s\n",
			event.Timestamp.Format(time.RFC3339),
			event.PID,
			event.Comm,
			event.Syscall,
			event.Arg,
			event.AgentRun,
		)
	}
	return nil
}

func diffCommand(ctx context.Context, cfg sentinel.Config, args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&cfg.DatabaseURL, "database-url", os.Getenv("DATABASE_URL"), "database url; sqlite path or postgres DSN")
	fs.StringVar(&cfg.SQLitePath, "sqlite-path", filepath.Join("data", "sentinel.db"), "sqlite database path when DATABASE_URL is empty")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("diff requires exactly two session identifiers")
	}

	store, err := sentinel.OpenStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer store.Close()

	diff, err := store.DiffSessions(ctx, fs.Arg(0), fs.Arg(1))
	if err != nil {
		return err
	}

	fmt.Printf("only in %s\n", fs.Arg(0))
	for _, line := range diff.OnlyInLeft {
		fmt.Printf("  %s\n", line)
	}
	fmt.Printf("only in %s\n", fs.Arg(1))
	for _, line := range diff.OnlyInRight {
		fmt.Printf("  %s\n", line)
	}
	return nil
}

func printUsage(msg string) {
	if msg != "" {
		fmt.Fprintln(os.Stderr, msg)
	}
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  sentinel run   [--agent \"python3 mantis.py\" | --pid 1234]")
	fmt.Fprintln(os.Stderr, "  sentinel query [--syscall openat] [--arg /etc] [--session session_1]")
	fmt.Fprintln(os.Stderr, "  sentinel diff  <session_a> <session_b>")
}
