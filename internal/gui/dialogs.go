package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/crypto"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"

	"semp.dev/semp-reference-client/internal/client"
)

// ShowRegisterDialog prompts for a password and registers the user with the server.
func ShowRegisterDialog(g *GUIApp) {
	pwEntry := widget.NewPasswordEntry()
	pwEntry.SetPlaceHolder("Account password")

	items := []*widget.FormItem{
		widget.NewFormItem("Password", pwEntry),
	}

	dialog.ShowForm("Register", "Register", "Cancel", items,
		func(ok bool) {
			if !ok {
				return
			}
			password := pwEntry.Text
			if password == "" {
				dialog.ShowError(fmt.Errorf("password is required"), g.Window)
				return
			}
			RunInBackground(g, "Registering", func(ctx context.Context) error {
				c := client.New(g.Cfg, g.Store, g.Logger)
				return c.Register(ctx, password)
			}, func() {
				g.loadKeyFingerprints()
				dialog.ShowInformation("Registered",
					fmt.Sprintf("Registered %s with server", g.Cfg.Identity),
					g.Window)
			})
		}, g.Window)
}

// ShowConnectAction establishes a connection to the server.
func ShowConnectAction(g *GUIApp) {
	RunInBackground(g, "Connecting", func(ctx context.Context) error {
		_, err := g.GetClient(ctx)
		return err
	}, func() {
		dialog.ShowInformation("Connected",
			fmt.Sprintf("Connected to %s", g.Cfg.Server), g.Window)
	})
}

// ShowFetchAction fetches and decrypts pending messages.
func ShowFetchAction(g *GUIApp) {
	RunInBackground(g, "Fetching", func(ctx context.Context) error {
		c, err := g.GetClient(ctx)
		if err != nil {
			return err
		}
		msgs, err := c.Fetch(ctx)
		if err != nil {
			return err
		}
		count := len(msgs)
		g.RefreshMessages()
		if count == 0 {
			dialog.ShowInformation("Fetch", "No new messages.", g.Window)
		} else {
			dialog.ShowInformation("Fetch",
				fmt.Sprintf("%d new message(s) received.", count), g.Window)
		}
		return nil
	}, nil)
}

// ShowKeyLookupDialog shows a dialog to request keys for an address.
func ShowKeyLookupDialog(g *GUIApp) {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("user@example.com")

	dialog.ShowForm("Lookup Keys", "Lookup", "Cancel",
		[]*widget.FormItem{
			widget.NewFormItem("Address", entry),
		},
		func(ok bool) {
			if !ok {
				return
			}
			addr := strings.TrimSpace(entry.Text)
			if addr == "" {
				return
			}
			RunInBackground(g, "Key lookup", func(ctx context.Context) error {
				c, err := g.GetClient(ctx)
				if err != nil {
					return err
				}
				fetcher := keys.NewFetcher(c.Conn())
				reqID := fmt.Sprintf("kr-%d", time.Now().UnixNano())
				req := keys.NewRequest(reqID, []string{addr})

				resp, err := fetcher.FetchKeys(ctx, req)
				if err != nil {
					return err
				}

				var lines []string
				for _, r := range resp.Results {
					lines = append(lines, fmt.Sprintf("Address: %s  Status: %s", r.Address, r.Status))
					if r.DomainKey != nil {
						lines = append(lines, fmt.Sprintf("  Domain key: %s (%s)", r.DomainKey.KeyID, r.DomainKey.Algorithm))
					}
					for _, uk := range r.UserKeys {
						lines = append(lines, fmt.Sprintf("  %s key: %s (%s, expires %s)",
							uk.Type, uk.KeyID, uk.Algorithm, uk.Expires.Format(time.RFC3339)))
					}
					if r.ErrorReason != "" {
						lines = append(lines, "  Error: "+r.ErrorReason)
					}
				}
				dialog.ShowInformation("Key Lookup Results",
					strings.Join(lines, "\n"), g.Window)
				return nil
			}, nil)
		}, g.Window)
}

// ShowImportDialog opens a file picker to import a .semp file.
func ShowImportDialog(g *GUIApp) {
	fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil || reader == nil {
			return
		}
		defer reader.Close()

		// Read entire file.
		var data []byte
		buf := make([]byte, 4096)
		for {
			n, readErr := reader.Read(buf)
			data = append(data, buf[:n]...)
			if readErr != nil {
				break
			}
		}

		env, err := envelope.DecodeFile(data)
		if err != nil {
			dialog.ShowError(fmt.Errorf("decode .semp: %w", err), g.Window)
			return
		}

		suite := g.Suite()
		candidates, err := buildCandidates(g)
		if err != nil {
			dialog.ShowError(err, g.Window)
			return
		}

		b, err := openBrief(env, suite, candidates)
		if err != nil {
			dialog.ShowError(fmt.Errorf("decrypt brief: %w", err), g.Window)
			return
		}

		enc, err := openEnclosure(env, suite, candidates)
		if err != nil {
			dialog.ShowError(fmt.Errorf("decrypt enclosure: %w", err), g.Window)
			return
		}

		// Store imported message.
		rawJSON, _ := json.Marshal(env)
		toStrs := make([]string, len(b.To))
		for i, a := range b.To {
			toStrs[i] = string(a)
		}
		_ = g.Store.StoreMessage(b.MessageID, "received", string(b.From),
			toStrs, nil, enc.Subject, enc.Body.Get("text/plain"), rawJSON)

		g.RefreshMessages()
		dialog.ShowInformation("Import Successful",
			fmt.Sprintf("Imported message %s from %s", b.MessageID, b.From), g.Window)

	}, g.Window)
	fd.SetFilter(storage.NewExtensionFileFilter([]string{".semp"}))
	fd.Show()
}

// ShowExportDialog exports the selected message as a .semp file.
func ShowExportDialog(g *GUIApp) {
	if g.messageDetail == nil || g.messageDetail.SelectedMessage() == nil {
		dialog.ShowInformation("Export", "Select a message first.", g.Window)
		return
	}
	msg := g.messageDetail.SelectedMessage()
	if len(msg.RawEnvelope) == 0 {
		dialog.ShowError(fmt.Errorf("no raw envelope stored for this message"), g.Window)
		return
	}

	env, err := envelope.Decode(msg.RawEnvelope)
	if err != nil {
		dialog.ShowError(fmt.Errorf("decode envelope: %w", err), g.Window)
		return
	}
	fileData, err := envelope.EncodeFile(env)
	if err != nil {
		dialog.ShowError(fmt.Errorf("encode .semp: %w", err), g.Window)
		return
	}

	fd := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()
		if _, err := writer.Write(fileData); err != nil {
			dialog.ShowError(fmt.Errorf("write file: %w", err), g.Window)
			return
		}
		dialog.ShowInformation("Export", "Message exported successfully.", g.Window)
	}, g.Window)
	fd.SetFileName(msg.MessageID + ".semp")
	fd.Show()
}

// ShowStatusDialog displays identity, key, and connection info.
func ShowStatusDialog(g *GUIApp) {
	connState, _ := g.ConnState.Get()
	idFP, _ := g.IDKeyFP.Get()
	encFP, _ := g.EncKeyFP.Get()

	inbox, _ := g.Store.ListMessages("received")
	sent, _ := g.Store.ListMessages("sent")

	info := fmt.Sprintf(
		"Identity:   %s\nDomain:     %s\nServer:     %s\nDatabase:   %s\nTLS:        insecure=%v\n\n"+
			"Identity key:   %s\nEncryption key: %s\n\n"+
			"Connection: %s\nInbox:      %d message(s)\nSent:       %d message(s)",
		g.Cfg.Identity, g.Cfg.Domain, g.Cfg.Server, g.Cfg.Database.Path, g.Cfg.TLS.Insecure,
		truncateFP(idFP), truncateFP(encFP),
		connState, len(inbox), len(sent),
	)
	dialog.ShowInformation("Status", info, g.Window)
}

// ShowAboutDialog shows application info.
func ShowAboutDialog(g *GUIApp) {
	dialog.ShowInformation("About",
		"SEMP Reference Client\n\n"+
			"A desktop client demonstrating the SEMP protocol.\n"+
			"Built with Fyne and semp-go.",
		g.Window)
}

// ---------------------------------------------------------------------------
// Helpers shared with messagedetail.go
// ---------------------------------------------------------------------------

// decodeEnvelope parses a raw envelope.
func decodeEnvelope(raw []byte) (*envelope.Envelope, error) {
	return envelope.Decode(raw)
}

// buildCandidates creates recipient private key candidates from the store.
func buildCandidates(g *GUIApp) ([]envelope.RecipientPrivateKey, error) {
	priv, fp, err := g.Store.LoadUserPrivateKey(g.Cfg.Identity, keys.TypeEncryption)
	if err != nil {
		return nil, fmt.Errorf("load encryption key: %w", err)
	}
	if fp == "" {
		return nil, fmt.Errorf("no encryption key for %s", g.Cfg.Identity)
	}
	return []envelope.RecipientPrivateKey{
		{Fingerprint: fp, PrivateKey: priv},
	}, nil
}

// openBrief decrypts the brief from an envelope.
func openBrief(env *envelope.Envelope, suite crypto.Suite, candidates []envelope.RecipientPrivateKey) (*brief.Brief, error) {
	return envelope.OpenBriefAny(env, suite, candidates)
}

// openEnclosure decrypts the enclosure from an envelope.
func openEnclosure(env *envelope.Envelope, suite crypto.Suite, candidates []envelope.RecipientPrivateKey) (*enclosure.Enclosure, error) {
	return envelope.OpenEnclosureAny(env, suite, candidates)
}

// truncateFP shortens a fingerprint for display.
func truncateFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "..."
	}
	return fp
}

