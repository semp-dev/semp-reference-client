package gui

import (
	"context"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"semp.dev/semp-reference-client/internal/client"
)

// ShowComposeWindow opens a new compose window.
func ShowComposeWindow(g *GUIApp) {
	w := g.App.NewWindow("Compose Message")

	toEntry := widget.NewEntry()
	toEntry.SetPlaceHolder("recipient@example.com, ...")

	ccEntry := widget.NewEntry()
	ccEntry.SetPlaceHolder("cc@example.com, ... (optional)")

	subjectEntry := widget.NewEntry()
	subjectEntry.SetPlaceHolder("Subject")

	bodyEntry := widget.NewMultiLineEntry()
	bodyEntry.SetPlaceHolder("Message body...")
	bodyEntry.SetMinRowsVisible(12)

	var attachedPaths []string
	attachLabel := widget.NewLabel("No attachments")

	attachBtn := widget.NewButton("Attach Files...", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			reader.Close()
			path := reader.URI().Path()
			attachedPaths = append(attachedPaths, path)
			attachLabel.SetText(fmt.Sprintf("%d file(s) attached", len(attachedPaths)))
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{})) // all files
		fd.Show()
	})

	clearAttachBtn := widget.NewButton("Clear", func() {
		attachedPaths = nil
		attachLabel.SetText("No attachments")
	})

	sendBtn := widget.NewButton("Send", nil)
	sendBtn.Importance = widget.HighImportance
	cancelBtn := widget.NewButton("Cancel", func() {
		w.Close()
	})

	sendBtn.OnTapped = func() {
		to := strings.TrimSpace(toEntry.Text)
		if to == "" {
			dialog.ShowError(fmt.Errorf("recipient (To) is required"), w)
			return
		}

		toList := splitAddresses(to)
		var ccList []string
		if cc := strings.TrimSpace(ccEntry.Text); cc != "" {
			ccList = splitAddresses(cc)
		}

		opts := client.SendOptions{
			To:          toList,
			CC:          ccList,
			Subject:     subjectEntry.Text,
			Body:        bodyEntry.Text,
			Attachments: attachedPaths,
		}

		sendBtn.Disable()
		cancelBtn.Disable()

		RunInBackgroundWithWindow(g, "Sending", w, func(ctx context.Context) error {
			c, err := g.GetClient(ctx)
			if err != nil {
				return err
			}
			resp, err := c.Send(ctx, opts)
			if err != nil {
				return err
			}

			// Build result summary.
			var lines []string
			for _, r := range resp.Results {
				line := fmt.Sprintf("%s: %s", r.Recipient, r.Status)
				if r.Reason != "" {
					line += " (" + r.Reason + ")"
				}
				lines = append(lines, line)
			}

			dialog.ShowInformation("Message Sent",
				fmt.Sprintf("Envelope ID: %s\n\n%s", resp.EnvelopeID, strings.Join(lines, "\n")),
				w)
			return nil
		}, func() {
			g.RefreshMessages()
			w.Close()
		})
	}

	form := container.NewVBox(
		widget.NewForm(
			widget.NewFormItem("To", toEntry),
			widget.NewFormItem("CC", ccEntry),
			widget.NewFormItem("Subject", subjectEntry),
		),
		bodyEntry,
		container.NewHBox(attachBtn, clearAttachBtn, attachLabel),
		widget.NewSeparator(),
		container.NewHBox(sendBtn, cancelBtn),
	)

	w.SetContent(container.NewVScroll(form))
	w.Resize(fyne.NewSize(600, 500))
	w.Show()
}

// splitAddresses splits a comma-separated address string into trimmed parts.
func splitAddresses(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
