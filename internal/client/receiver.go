package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/envelope"
)

// DecryptedMessage holds the decrypted contents of an envelope.
type DecryptedMessage struct {
	MessageID   string
	From        brief.Address
	To          []brief.Address
	CC          []brief.Address
	Subject     string
	Body        string // text/plain body
	Attachments []AttachmentInfo
	RawEnvelope []byte
}

// AttachmentInfo summarises an attachment.
type AttachmentInfo struct {
	ID       string
	Filename string
	MimeType string
	Size     int64
}

// Fetch retrieves and decrypts all pending envelopes from the home server.
func (c *Client) Fetch(ctx context.Context) ([]DecryptedMessage, error) {
	if c.session == nil {
		return nil, fmt.Errorf("client: no active session")
	}

	// 1. Send fetch request.
	req := delivery.NewFetchRequest()
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("client: marshal fetch request: %w", err)
	}
	if err := c.conn.Send(ctx, reqBytes); err != nil {
		return nil, fmt.Errorf("client: send fetch request: %w", err)
	}

	// 2. Receive fetch response.
	respRaw, err := c.conn.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: recv fetch response: %w", err)
	}
	var resp delivery.FetchResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("client: parse fetch response: %w", err)
	}

	c.Log.Info("fetched envelopes", "count", len(resp.Envelopes), "drained", resp.Drained)

	if len(resp.Envelopes) == 0 {
		return nil, nil
	}

	// 3. Build candidate private keys.
	candidates, err := c.recipientPrivateKeys()
	if err != nil {
		return nil, err
	}
	envCandidates := make([]envelope.RecipientPrivateKey, len(candidates))
	for i, cand := range candidates {
		envCandidates[i] = envelope.RecipientPrivateKey{
			Fingerprint: cand.Fingerprint,
			PrivateKey:  cand.PrivateKey,
			PublicKey:   cand.PublicKey,
		}
	}

	// 4. Decrypt each envelope.
	var messages []DecryptedMessage
	for _, b64 := range resp.Envelopes {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			c.Log.Warn("skip envelope: bad base64", "err", err)
			continue
		}

		env, err := envelope.Decode(raw)
		if err != nil {
			c.Log.Warn("skip envelope: decode failed", "err", err)
			continue
		}

		// Decrypt brief.
		b, err := envelope.OpenBriefAny(env, c.Suite, envCandidates)
		if err != nil {
			c.Log.Warn("skip envelope: decrypt brief failed", "postmark_id", env.Postmark.ID, "err", err)
			continue
		}

		// Decrypt enclosure.
		enc, err := envelope.OpenEnclosureAny(env, c.Suite, envCandidates)
		if err != nil {
			c.Log.Warn("skip envelope: decrypt enclosure failed", "postmark_id", env.Postmark.ID, "err", err)
			continue
		}

		// Verify attachment hashes.
		for i := range enc.Attachments {
			att := &enc.Attachments[i]
			plain, verr := att.Plaintext()
			if verr != nil {
				c.Log.Warn("attachment hash verification failed",
					"attachment_id", att.ID,
					"filename", att.Filename,
					"err", verr)
			} else {
				_ = plain // content verified
			}
		}

		msg := DecryptedMessage{
			MessageID:   b.MessageID,
			From:        b.From,
			To:          b.To,
			CC:          b.CC,
			Subject:     enc.Subject,
			Body:        enc.Body.Get("text/plain"),
			RawEnvelope: raw,
		}
		for _, att := range enc.Attachments {
			msg.Attachments = append(msg.Attachments, AttachmentInfo{
				ID:       att.ID,
				Filename: att.Filename,
				MimeType: att.MimeType,
				Size:     att.Size,
			})
		}
		messages = append(messages, msg)

		// Store locally.
		toStrs := make([]string, len(b.To))
		for i, a := range b.To {
			toStrs[i] = string(a)
		}
		ccStrs := make([]string, len(b.CC))
		for i, a := range b.CC {
			ccStrs[i] = string(a)
		}
		_ = c.Store.StoreMessage(b.MessageID, "received", string(b.From),
			toStrs, ccStrs, enc.Subject, enc.Body.Get("text/plain"), raw)
	}

	return messages, nil
}
