package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// StatusBar is the bottom bar showing identity, connection state, and key info.
type StatusBar struct {
	app       *GUIApp
	container fyne.CanvasObject
}

// NewStatusBar creates the status bar.
func NewStatusBar(g *GUIApp) *StatusBar {
	identityLabel := widget.NewLabelWithData(g.IdentityText)
	identityLabel.TextStyle = fyne.TextStyle{Bold: true}

	connLabel := widget.NewLabelWithData(g.ConnState)

	idKeyLabel := widget.NewLabelWithData(g.IDKeyFP)
	encKeyLabel := widget.NewLabelWithData(g.EncKeyFP)

	bar := container.NewHBox(
		identityLabel,
		widget.NewSeparator(),
		widget.NewLabel("Status:"),
		connLabel,
		widget.NewSeparator(),
		widget.NewLabel("ID Key:"),
		idKeyLabel,
		widget.NewSeparator(),
		widget.NewLabel("Enc Key:"),
		encKeyLabel,
	)

	return &StatusBar{app: g, container: bar}
}

// Container returns the status bar's renderable container.
func (s *StatusBar) Container() fyne.CanvasObject {
	return s.container
}
