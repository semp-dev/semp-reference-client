package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
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

		// Decrypt and verify in one pass per ENVELOPE.md §6.5.3 / §6.6.4.
		// The resolver looks up the sender's published identity key
		// in-session over SEMP_KEYS so verifyEnclosureWithResolver can
		// authenticate the sender_signature.
		res, err := envelope.OpenAndVerify(ctx, env, c.Suite, envCandidates, c.SenderKeyResolver())
		if err != nil {
			c.Log.Warn("skip envelope: open+verify failed", "postmark_id", env.Postmark.ID, "err", err)
			continue
		}
		b := res.Brief
		enc := res.Enclosure
		if !res.SenderSignatureVerified {
			c.Log.Warn("sender_signature unverified — content shown but origin is NOT authenticated",
				"postmark_id", env.Postmark.ID,
				"from", string(b.From),
				"err", res.SenderSignatureError)
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

// SenderKeyResolver returns an envelope.SenderKeyResolver bound to this
// client's active session. Callers pass it to envelope.OpenAndVerify so
// the receiver can authenticate sender_signatures per ENVELOPE.md §6.5.3.
func (c *Client) SenderKeyResolver() envelope.SenderKeyResolver {
	return envelope.SenderKeyResolverFunc(c.LookupSenderIdentityKey)
}

// LookupSenderIdentityKey resolves a sender's identity public key by
// (address, key_id) via an in-session SEMP_KEYS request. The home server
// resolves the key locally for same-domain senders and via the federated
// well-known fetcher for cross-domain senders.
func (c *Client) LookupSenderIdentityKey(ctx context.Context, senderAddr, keyID string) ([]byte, error) {
	fetcher := keys.NewFetcher(c.conn)
	reqID := fmt.Sprintf("vr-%d", time.Now().UnixNano())
	resp, err := fetcher.FetchKeys(ctx, keys.NewRequest(reqID, []string{senderAddr}))
	if err != nil {
		return nil, fmt.Errorf("verify-resolver: fetch keys: %w", err)
	}
	for _, r := range resp.Results {
		if r.Address != senderAddr || r.Status != keys.StatusFound {
			continue
		}
		for _, uk := range r.UserKeys {
			if uk.Type != keys.TypeIdentity {
				continue
			}
			if string(uk.KeyID) != keyID {
				continue
			}
			pub, derr := base64.StdEncoding.DecodeString(uk.PublicKey)
			if derr != nil {
				return nil, fmt.Errorf("verify-resolver: decode public key: %w", derr)
			}
			return pub, nil
		}
	}
	return nil, envelope.ErrSenderKeyUnknown
}
