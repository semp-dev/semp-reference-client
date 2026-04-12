package gui

import (
	"context"
	"fmt"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

// RunInBackground executes work in a goroutine. On success it calls onDone.
// On error it shows an error dialog on the given window.
func RunInBackground(g *GUIApp, label string, work func(ctx context.Context) error, onDone func()) {
	g.ConnState.Set(label + "...")
	go func() {
		ctx := context.Background()
		if err := work(ctx); err != nil {
			g.ConnState.Set("Error")
			g.Logger.Error(label+" failed", "err", err)
			dialog.ShowError(fmt.Errorf("%s: %w", label, err), g.Window)
			return
		}
		g.ConnState.Set("Connected")
		if onDone != nil {
			onDone()
		}
	}()
}

// RunInBackgroundWithWindow is like RunInBackground but shows errors on a
// specific window (e.g. compose window).
func RunInBackgroundWithWindow(g *GUIApp, label string, w fyne.Window, work func(ctx context.Context) error, onDone func()) {
	g.ConnState.Set(label + "...")
	go func() {
		ctx := context.Background()
		if err := work(ctx); err != nil {
			g.ConnState.Set("Error")
			g.Logger.Error(label+" failed", "err", err)
			dialog.ShowError(fmt.Errorf("%s: %w", label, err), w)
			return
		}
		g.ConnState.Set("Connected")
		if onDone != nil {
			onDone()
		}
	}()
}
