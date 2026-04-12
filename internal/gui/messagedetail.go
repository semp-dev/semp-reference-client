package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"semp.dev/semp-reference-client/internal/store"
)

// MessageDetailPanel displays a single message's full content.
type MessageDetailPanel struct {
	app *GUIApp
	msg *store.Message

	fromLabel    *widget.Label
	toLabel      *widget.Label
	ccLabel      *widget.Label
	ccRow        *fyne.Container
	subjectLabel *widget.Label
	dateLabel    *widget.Label
	bodyText     *widget.Label
	attachLabel  *widget.Label
	attachRow    *fyne.Container

	placeholder *widget.Label
	content     *fyne.Container
	scroll      *container.Scroll
	outer       *fyne.Container
}

// NewMessageDetailPanel creates the message detail view.
func NewMessageDetailPanel(g *GUIApp) *MessageDetailPanel {
	p := &MessageDetailPanel{app: g}

	p.fromLabel = widget.NewLabel("")
	p.toLabel = widget.NewLabel("")
	p.ccLabel = widget.NewLabel("")
	p.subjectLabel = widget.NewLabel("")
	p.subjectLabel.TextStyle = fyne.TextStyle{Bold: true}
	p.dateLabel = widget.NewLabel("")

	p.ccRow = container.NewHBox(
		widget.NewLabelWithStyle("CC:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		p.ccLabel,
	)
	p.ccRow.Hide()

	p.bodyText = widget.NewLabel("")
	p.bodyText.Wrapping = fyne.TextWrapWord

	p.attachLabel = widget.NewLabel("")
	p.attachRow = container.NewVBox(
		widget.NewSeparator(),
		widget.NewLabelWithStyle("Attachments:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		p.attachLabel,
	)
	p.attachRow.Hide()

	headers := container.NewVBox(
		container.NewHBox(
			widget.NewLabelWithStyle("From:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			p.fromLabel,
		),
		container.NewHBox(
			widget.NewLabelWithStyle("To:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			p.toLabel,
		),
		p.ccRow,
		container.NewHBox(
			widget.NewLabelWithStyle("Date:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			p.dateLabel,
		),
		p.subjectLabel,
		widget.NewSeparator(),
	)

	p.content = container.NewVBox(
		headers,
		p.bodyText,
		p.attachRow,
	)

	p.scroll = container.NewVScroll(p.content)

	p.placeholder = widget.NewLabel("Select a message to read")
	p.placeholder.Alignment = fyne.TextAlignCenter

	p.outer = container.NewStack(p.placeholder, p.scroll)
	p.scroll.Hide()

	return p
}

// ShowMessage displays the given message.
func (p *MessageDetailPanel) ShowMessage(msg *store.Message) {
	p.msg = msg
	p.fromLabel.SetText(msg.From)
	p.toLabel.SetText(strings.Join(msg.To, ", "))

	if len(msg.CC) > 0 {
		p.ccLabel.SetText(strings.Join(msg.CC, ", "))
		p.ccRow.Show()
	} else {
		p.ccRow.Hide()
	}

	p.dateLabel.SetText(msg.StoredAt)

	subj := msg.Subject
	if subj == "" {
		subj = "(no subject)"
	}
	p.subjectLabel.SetText(subj)

	body := msg.BodyText
	if body == "" {
		body = "(empty)"
	}
	p.bodyText.SetText(body)

	// Show attachment summary if raw envelope is available.
	if len(msg.RawEnvelope) > 0 {
		atts := parseAttachmentSummary(p.app, msg.RawEnvelope)
		if atts != "" {
			p.attachLabel.SetText(atts)
			p.attachRow.Show()
		} else {
			p.attachRow.Hide()
		}
	} else {
		p.attachRow.Hide()
	}

	p.placeholder.Hide()
	p.scroll.Show()
	p.scroll.ScrollToTop()
}

// Clear hides the detail and shows the placeholder.
func (p *MessageDetailPanel) Clear() {
	p.msg = nil
	p.scroll.Hide()
	p.placeholder.Show()
}

// SelectedMessage returns the currently displayed message, if any.
func (p *MessageDetailPanel) SelectedMessage() *store.Message {
	return p.msg
}

// Container returns the panel's renderable container.
func (p *MessageDetailPanel) Container() fyne.CanvasObject {
	return p.outer
}

// parseAttachmentSummary tries to decode the raw envelope and extract
// attachment info. Returns a formatted string or empty.
func parseAttachmentSummary(g *GUIApp, rawEnvelope []byte) string {
	// Try to decode and extract attachment info from the enclosure.
	// We use envelope.Decode + OpenEnclosureAny with local keys.
	env, err := decodeEnvelope(rawEnvelope)
	if err != nil {
		return ""
	}

	candidates, err := buildCandidates(g)
	if err != nil {
		return ""
	}

	enc, err := openEnclosure(env, g.Suite(), candidates)
	if err != nil {
		return ""
	}

	if len(enc.Attachments) == 0 {
		return ""
	}

	var lines []string
	for _, a := range enc.Attachments {
		lines = append(lines, fmt.Sprintf("  %s (%s, %d bytes)", a.Filename, a.MimeType, a.Size))
	}
	return strings.Join(lines, "\n")
}
