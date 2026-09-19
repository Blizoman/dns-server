// Command dnsserver runs a simple authoritative DNS server that answers A
// record queries for a configured set of domains.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"dnsserver/internal/config"
	"dnsserver/internal/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "config.yaml", "path to the YAML or JSON configuration file")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	logger := newLogger(*logLevel)

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger.Info("configuration loaded", "path", *configPath, "records", len(cfg.Records), "listen", cfg.Listen)

	srv := server.New(cfg.Lookup(), logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return srv.ListenAndServe(ctx, cfg.Listen)
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	return slog.New(handler)
}
