package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
)

// BuildLayout assembles the main window layout.
func BuildLayout(g *GUIApp) fyne.CanvasObject {
	sidebar := g.sidebar.Container()
	messageList := g.messageList.Container()
	messageDetail := g.messageDetail.Container()
	statusBar := g.statusBar.Container()

	// Center: message list (left) | message detail (right).
	centerSplit := container.NewHSplit(messageList, messageDetail)
	centerSplit.SetOffset(0.35)

	// Full layout: sidebar | center, with status bar at bottom.
	return container.NewBorder(
		nil,       // top
		statusBar, // bottom
		sidebar,   // left
		nil,       // right
		centerSplit,
	)
}

// BuildMenu creates the application menu bar.
func BuildMenu(g *GUIApp) *fyne.MainMenu {
	// File menu.
	importItem := fyne.NewMenuItem("Import .semp...", func() {
		ShowImportDialog(g)
	})
	exportItem := fyne.NewMenuItem("Export .semp...", func() {
		ShowExportDialog(g)
	})
	quitItem := fyne.NewMenuItem("Quit", func() {
		g.DisconnectClient()
		g.App.Quit()
	})
	fileMenu := fyne.NewMenu("File", importItem, exportItem, fyne.NewMenuItemSeparator(), quitItem)

	// Tools menu.
	initItem := fyne.NewMenuItem("Register", func() {
		ShowRegisterDialog(g)
	})
	keysItem := fyne.NewMenuItem("Lookup Keys...", func() {
		ShowKeyLookupDialog(g)
	})
	connectItem := fyne.NewMenuItem("Connect", func() {
		ShowConnectAction(g)
	})
	fetchItem := fyne.NewMenuItem("Fetch Messages", func() {
		ShowFetchAction(g)
	})
	toolsMenu := fyne.NewMenu("Tools", initItem, keysItem, fyne.NewMenuItemSeparator(), connectItem, fetchItem)

	// Help menu.
	statusItem := fyne.NewMenuItem("Status", func() {
		ShowStatusDialog(g)
	})
	aboutItem := fyne.NewMenuItem("About", func() {
		ShowAboutDialog(g)
	})
	helpMenu := fyne.NewMenu("Help", statusItem, aboutItem)

	return fyne.NewMainMenu(fileMenu, toolsMenu, helpMenu)
}
