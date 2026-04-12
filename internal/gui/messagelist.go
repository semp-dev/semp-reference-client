package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// MessageListPanel displays the message list for the current folder.
type MessageListPanel struct {
	app       *GUIApp
	list      *widget.List
	container fyne.CanvasObject
}

// NewMessageListPanel creates the message list panel.
func NewMessageListPanel(g *GUIApp) *MessageListPanel {
	p := &MessageListPanel{app: g}

	p.list = widget.NewList(
		// Length
		func() int {
			return len(g.Messages())
		},
		// CreateItem
		func() fyne.CanvasObject {
			from := widget.NewLabel("From")
			from.TextStyle = fyne.TextStyle{Bold: true}
			from.Truncation = fyne.TextTruncateEllipsis
			subject := widget.NewLabel("Subject")
			subject.Truncation = fyne.TextTruncateEllipsis
			date := widget.NewLabel("Date")
			date.Alignment = fyne.TextAlignTrailing

			return container.NewBorder(
				nil, nil, nil, date,
				container.NewVBox(from, subject),
			)
		},
		// UpdateItem
		func(id widget.ListItemID, item fyne.CanvasObject) {
			msgs := g.Messages()
			if id >= len(msgs) {
				return
			}
			msg := msgs[id]

			border := item.(*fyne.Container)
			vbox := border.Objects[0].(*fyne.Container)
			fromLabel := vbox.Objects[0].(*widget.Label)
			subjectLabel := vbox.Objects[1].(*widget.Label)
			dateLabel := border.Objects[1].(*widget.Label)

			// Display name based on direction.
			if msg.Direction == "sent" {
				if len(msg.To) > 0 {
					fromLabel.SetText("To: " + strings.Join(msg.To, ", "))
				} else {
					fromLabel.SetText("To: (unknown)")
				}
			} else {
				fromLabel.SetText(msg.From)
			}

			subj := msg.Subject
			if subj == "" {
				subj = "(no subject)"
			}
			subjectLabel.SetText(subj)

			dateLabel.SetText(formatDate(msg.StoredAt))
		},
	)

	p.list.OnSelected = func(id widget.ListItemID) {
		msgs := g.Messages()
		if id >= len(msgs) {
			return
		}
		msg := msgs[id]

		full, err := g.Store.GetMessage(msg.MessageID)
		if err != nil {
			g.Logger.Error("failed to load message", "err", err)
			return
		}
		if full == nil {
			return
		}
		if g.messageDetail != nil {
			g.messageDetail.ShowMessage(full)
		}
	}

	p.container = p.list
	return p
}

// Refresh reloads the list widget.
func (p *MessageListPanel) Refresh() {
	p.list.Refresh()
	p.list.UnselectAll()
}

// Container returns the panel's renderable container.
func (p *MessageListPanel) Container() fyne.CanvasObject {
	return p.container
}

// formatDate formats a stored RFC3339 timestamp for display.
func formatDate(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	now := time.Now()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	if t.Year() == now.Year() {
		return fmt.Sprintf("%s %d", t.Month().String()[:3], t.Day())
	}
	return t.Format("2006-01-02")
}
