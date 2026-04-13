package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"

	"semp.dev/semp-go/brief"
	"semp.dev/semp-go/delivery"
	"semp.dev/semp-go/enclosure"
	"semp.dev/semp-go/envelope"
	"semp.dev/semp-go/keys"
	"semp.dev/semp-go/seal"
)

// SendOptions describes a message to send.
type SendOptions struct {
	To          []string // recipient addresses
	CC          []string
	Subject     string
	Body        string   // text/plain body
	Attachments []string // file paths to attach
}

// Send composes, encrypts, and submits an envelope to the home server.
func (c *Client) Send(ctx context.Context, opts SendOptions) (*delivery.SubmissionResponse, error) {
	if c.session == nil {
		return nil, fmt.Errorf("client: no active session")
	}

	// 1. Fetch recipient keys.
	allAddrs := append([]string{}, opts.To...)
	allAddrs = append(allAddrs, opts.CC...)
	recipientKeys, domainEncKeys, domainSignFP, err := c.fetchRecipientKeys(ctx, allAddrs)
	if err != nil {
		return nil, fmt.Errorf("client: fetch recipient keys: %w", err)
	}

	// 2. Build brief.
	msgID := fmt.Sprintf("%s-%d", c.Cfg.Identity, time.Now().UnixNano())
	toAddrs := make([]brief.Address, len(opts.To))
	for i, a := range opts.To {
		toAddrs[i] = brief.Address(a)
	}
	ccAddrs := make([]brief.Address, len(opts.CC))
	for i, a := range opts.CC {
		ccAddrs[i] = brief.Address(a)
	}
	b := brief.Brief{
		MessageID: msgID,
		From:      brief.Address(c.Cfg.Identity),
		To:        toAddrs,
		CC:        ccAddrs,
		SentAt:    time.Now().UTC(),
	}

	// 3. Build enclosure.
	enc := enclosure.Enclosure{
		Subject:     opts.Subject,
		ContentType: "text/plain",
	}
	enc.Body = make(enclosure.Body)
	enc.Body.Set("text/plain", opts.Body)

	// Attachments.
	for i, path := range opts.Attachments {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("client: read attachment %s: %w", path, err)
		}
		filename := filepath.Base(path)
		mimeType := detectMIME(filename)
		attID := fmt.Sprintf("att-%d", i)
		att, err := enclosure.NewAttachment(attID, filename, mimeType, "sha256", data)
		if err != nil {
			return nil, fmt.Errorf("client: create attachment %s: %w", filename, err)
		}
		enc.Attachments = append(enc.Attachments, *att)
	}

	// 4. Build recipient key lists for seal wrapping.
	// Brief recipients: domain encryption keys (so servers can route)
	//                    + all recipient device/user encryption keys
	//                    + sender's own encryption key.
	// Enclosure recipients: only user/device encryption keys + sender's own.
	//                       Servers MUST NOT be able to read the enclosure.
	senderPub, senderFP, err := c.senderEncryptionPubKey()
	if err != nil {
		return nil, err
	}

	// Always include the home server's domain encryption key in brief recipients
	// so it can unwrap the brief for routing. This was cached during registration.
	briefRecipients := make([]seal.RecipientKey, 0, len(domainEncKeys)+len(recipientKeys)+2)
	homeDomEncRec, _ := c.Store.LookupDomainEncryptionKey(context.Background(), c.Cfg.Domain)
	var homeDomEncFP keys.Fingerprint
	if homeDomEncRec != nil {
		homeDomEncPub, err := base64.StdEncoding.DecodeString(homeDomEncRec.PublicKey)
		if err == nil {
			homeDomEncFP = homeDomEncRec.KeyID
			briefRecipients = append(briefRecipients, seal.RecipientKey{
				Fingerprint: homeDomEncFP, PublicKey: homeDomEncPub,
			})
		}
	}

	// Add any remote domain encryption keys from SEMP_KEYS responses.
	for _, dk := range domainEncKeys {
		// Skip if it's the same as home domain (already added).
		if dk.Fingerprint == homeDomEncFP {
			continue
		}
		briefRecipients = append(briefRecipients, dk)
	}
	briefRecipients = append(briefRecipients, seal.RecipientKey{
		Fingerprint: senderFP, PublicKey: senderPub,
	})

	enclosureRecipients := []seal.RecipientKey{
		{Fingerprint: senderFP, PublicKey: senderPub},
	}
	for _, rk := range recipientKeys {
		briefRecipients = append(briefRecipients, rk)
		enclosureRecipients = append(enclosureRecipients, rk)
	}

	// 5. Determine recipient domain for postmark.
	toDomain := c.Cfg.Domain
	if len(opts.To) > 0 {
		parts := strings.SplitN(opts.To[0], "@", 2)
		if len(parts) == 2 {
			toDomain = parts[1]
		}
	}

	// 6. Compose the envelope.
	env, err := envelope.Compose(&envelope.ComposeInput{
		Suite: c.Suite,
		Postmark: envelope.Postmark{
			ID:         msgID,
			SessionID:  c.session.ID,
			FromDomain: c.Cfg.Domain,
			ToDomain:   toDomain,
			Expires:    time.Now().UTC().Add(7 * 24 * time.Hour),
		},
		Brief:               b,
		Enclosure:           enc,
		SenderDomainKeyID:   domainSignFP,
		BriefRecipients:     briefRecipients,
		EnclosureRecipients: enclosureRecipients,
	})
	if err != nil {
		return nil, fmt.Errorf("client: compose envelope: %w", err)
	}

	// 7. Encode and send. The server will sign (add signature + session MAC).
	wire, err := envelope.Encode(env)
	if err != nil {
		return nil, fmt.Errorf("client: encode envelope: %w", err)
	}
	if err := c.conn.Send(ctx, wire); err != nil {
		return nil, fmt.Errorf("client: send envelope: %w", err)
	}
	c.Log.Info("envelope sent", "message_id", msgID, "to", opts.To)

	// 8. Receive submission response.
	respRaw, err := c.conn.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: recv submission response: %w", err)
	}
	var resp delivery.SubmissionResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("client: parse submission response: %w", err)
	}

	// 9. Store sent message locally.
	_ = c.Store.StoreMessage(msgID, "sent", c.Cfg.Identity, opts.To, opts.CC, opts.Subject, opts.Body, wire)

	return &resp, nil
}

// fetchRecipientKeys requests encryption keys for all addresses via the
// in-session SEMP_KEYS protocol and returns seal.RecipientKey entries plus
// the sender domain's signing key fingerprint.
func (c *Client) fetchRecipientKeys(ctx context.Context, addresses []string) ([]seal.RecipientKey, []seal.RecipientKey, keys.Fingerprint, error) {
	fetcher := keys.NewFetcher(c.conn)
	reqID := fmt.Sprintf("kr-%d", time.Now().UnixNano())
	req := keys.NewRequest(reqID, addresses)

	resp, err := fetcher.FetchKeys(ctx, req)
	if err != nil {
		return nil, nil, "", fmt.Errorf("fetch keys: %w", err)
	}

	var recipients []seal.RecipientKey
	var domainSignFP keys.Fingerprint
	seenDomains := make(map[string]bool)
	var domainEncKeys []seal.RecipientKey

	for _, r := range resp.Results {
		if r.Status != keys.StatusFound {
			c.Log.Warn("key lookup failed", "address", r.Address, "status", r.Status, "reason", r.ErrorReason)
			continue
		}

		// Capture domain signing key fingerprint (for seal.key_id).
		if r.DomainKey != nil && domainSignFP == "" {
			domainSignFP = r.DomainKey.KeyID
		}

		// Capture domain encryption key (one per domain, for brief wrapping).
		if r.DomainEncKey != nil && !seenDomains[r.Domain] {
			seenDomains[r.Domain] = true
			pub, err := decodePubKey(r.DomainEncKey)
			if err == nil {
				domainEncKeys = append(domainEncKeys, seal.RecipientKey{
					Fingerprint: r.DomainEncKey.KeyID,
					PublicKey:   pub,
				})
			}
		}

		// Find encryption key among user keys.
		for _, uk := range r.UserKeys {
			if uk.Type == keys.TypeEncryption {
				pub, err := decodePubKey(uk)
				if err != nil {
					c.Log.Warn("bad public key", "address", r.Address, "key_id", uk.KeyID, "err", err)
					continue
				}
				recipients = append(recipients, seal.RecipientKey{
					Fingerprint: uk.KeyID,
					PublicKey:   pub,
				})

				// Cache in contacts.
				_ = c.Store.PutContact(r.Address, r.Domain, string(uk.KeyID), uk.PublicKey)
			}
		}
	}

	return recipients, domainEncKeys, domainSignFP, nil
}

// detectMIME returns a MIME type for the given filename, defaulting to
// application/octet-stream.
func detectMIME(filename string) string {
	ext := filepath.Ext(filename)
	if ext == "" {
		return "application/octet-stream"
	}
	t := mime.TypeByExtension(ext)
	if t == "" {
		return "application/octet-stream"
	}
	return t
}
