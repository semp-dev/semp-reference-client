// Command semp-gui is the desktop GUI for the SEMP reference client.
// It provides the same capabilities as the CLI (semp-client) through a
// Fyne-based graphical interface.
package main

import (
	"flag"
	"log/slog"
	"os"

	"fyne.io/fyne/v2/app"

	"semp.dev/semp-reference-client/internal/config"
	"semp.dev/semp-reference-client/internal/gui"
	"semp.dev/semp-reference-client/internal/store"
)

func main() {
	configPath := flag.String("config", "semp.toml", "path to TOML config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "err", err)
		os.Exit(1)
	}

	db, err := store.InitDB(cfg.Database.Path)
	if err != nil {
		logger.Error("failed to init database", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	s := store.NewSQLiteStore(db)

	a := app.NewWithID("dev.semp.client")
	w := a.NewWindow("SEMP Client — " + cfg.Identity)

	g := gui.NewGUIApp(a, w, cfg, s, logger)
	g.Build()

	w.ShowAndRun()
}
