package gui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Sidebar is the left panel with folder navigation and a compose button.
type Sidebar struct {
	widget.BaseWidget
	app       *GUIApp
	inboxBtn  *widget.Button
	sentBtn   *widget.Button
	container fyne.CanvasObject
}

// NewSidebar creates the folder navigation sidebar.
func NewSidebar(g *GUIApp) *Sidebar {
	s := &Sidebar{app: g}

	s.inboxBtn = widget.NewButtonWithIcon("Inbox", theme.MailComposeIcon(), func() {
		g.CurrentFolder = "received"
		s.updateHighlight()
		g.RefreshMessages()
		if g.messageDetail != nil {
			g.messageDetail.Clear()
		}
	})
	s.inboxBtn.Importance = widget.HighImportance

	s.sentBtn = widget.NewButtonWithIcon("Sent", theme.MailSendIcon(), func() {
		g.CurrentFolder = "sent"
		s.updateHighlight()
		g.RefreshMessages()
		if g.messageDetail != nil {
			g.messageDetail.Clear()
		}
	})

	composeBtn := widget.NewButtonWithIcon("New Message", theme.ContentAddIcon(), func() {
		ShowComposeWindow(g)
	})
	composeBtn.Importance = widget.SuccessImportance

	header := widget.NewLabelWithStyle("Folders", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})

	s.container = container.NewVBox(
		header,
		widget.NewSeparator(),
		s.inboxBtn,
		s.sentBtn,
		layout.NewSpacer(),
		widget.NewSeparator(),
		composeBtn,
	)
	return s
}

func (s *Sidebar) updateHighlight() {
	if s.app.CurrentFolder == "received" {
		s.inboxBtn.Importance = widget.HighImportance
		s.sentBtn.Importance = widget.MediumImportance
	} else {
		s.inboxBtn.Importance = widget.MediumImportance
		s.sentBtn.Importance = widget.HighImportance
	}
	s.inboxBtn.Refresh()
	s.sentBtn.Refresh()
}

// Container returns the sidebar's renderable container.
func (s *Sidebar) Container() fyne.CanvasObject {
	return s.container
}
